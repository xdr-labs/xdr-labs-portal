#!/usr/bin/env python3
"""Stellar Cyber 7.0 custom TI: repeatable, fail-closed staging builder.

Public-source inputs are HTTPS-only and allowlisted. This CLI never publishes a
feed or changes a tenant. The bulk ARTEX IP inventory is HUNT-ONLY.
"""
from __future__ import annotations

import argparse
import csv
from datetime import date, datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

SOURCES = {
    "threatdefence": "https://raw.githubusercontent.com/ThreatDefence/agentic-attack-detections/main/iocs/indicators.csv",
    "talos": "https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/11/artex-and-beyond.txt",
}
MAX_BYTES = 8 * 1024 * 1024
MAX_STELLAR_TSV_BYTES = 99 * 1024 * 1024
MAX_TSV_ROWS = 20000  # below documented 25,000 IOC/day ingestion ceiling
TALOS_SNAPSHOT_DATE = date(2026, 11, 13)
TALOS_HUNT_TTL_DAYS = 30
TYPES = {"domain": "domain", "url": "url", "sha256": "sha256-hash", "md5": "md5-hash"}
LEGITIMATE = {
    "api.anthropic.com", "api.deepseek.com", "api.x.ai", "open.bigmodel.cn",
    "api.db-ip.com", "webhook.site", "dnslog.cn", "api.github.com",
    "update.pentagi.com", "support.pentagi.com", "strix.gateway.scarf.sh",
}
LEGITIMATE_URLS = {
    "https://api.github.com/repos/BaaRai/ARTEX/releases/latest",
    "https://update.pentagi.com/api/v1/proxy/updates/pentagi/check",
}
THREATDEFENCE_REQUIRED = {
    "type", "value", "confidence", "context", "source", "source_url",
    "reported", "review_by", "framework",
}

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        raise ValueError("HTTP redirect forbidden for vetted source: " + str(newurl)[:200])

def fetch_source(key: str, allow_network: bool) -> bytes:
    if not allow_network:
        raise ValueError("Network is disabled; use --td-csv and --talos-txt or --allow-network")
    url = SOURCES[key]
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname != "raw.githubusercontent.com":
        raise ValueError("Untrusted source origin")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    with opener.open(Request(url, headers={"User-Agent": "stellar-osint-builder/1.0",
                                            "Accept": "text/plain"}), timeout=15) as response:
        data = response.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise ValueError("Empty or oversized source: " + key)
    return data

def hash_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def valid_value(kind: str, value: str) -> bool:
    if not value or any(x in value for x in ("\t", "\n", "\r", "\0", " ")):
        return False
    if kind == "ipv4":
        try:
            return ipaddress.ip_address(value).version == 4
        except ValueError:
            return False
    if kind == "domain":
        labels = value.rstrip(".").split(".")
        return (len(value) <= 253 and len(labels) >= 2 and
                all(0 < len(x) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", x)
                    for x in labels))
    if kind == "url":
        p = urlsplit(value)
        return p.scheme in ("http", "https") and bool(p.hostname) and not p.username and not p.password
    if kind in ("sha256", "md5"):
        return re.fullmatch(r"[0-9A-Fa-f]{" + ("64" if kind == "sha256" else "32") + "}", value) is not None
    return False

def classify(rec: dict, today: date) -> tuple[str, str]:
    typ = rec["type"]
    value = rec["value"]
    conf = rec["confidence"].lower()
    if any("\t" in rec.get(k, "") or "\n" in rec.get(k, "") or "\r" in rec.get(k, "")
           for k in ("type", "value", "confidence", "source", "framework")):
        return "exclude_invalid", "Control character in source data"
    if rec["reported"]:
        try:
            if date.fromisoformat(rec["reported"]) > today:
                return "exclude_future", "Future-dated observation"
        except ValueError:
            return "exclude_invalid", "Invalid reported date"
    if rec["review_by"]:
        try:
            if date.fromisoformat(rec["review_by"]) < today:
                return "exclude_expired", "Expired indicator review date"
        except ValueError:
            return "exclude_invalid", "Invalid review-by date"
    if typ == "ipv6":
        return "hunt_only", "IPv6 not documented in Stellar custom TSV"
    if typ == "ipv4":
        if not valid_value(typ, value):
            return "exclude_invalid", "Invalid IPv4 or CIDR masquerading as IPv4"
        return "hunt_only", "Dynamic IP reuse and maliciousness not corroborated"
    if typ not in TYPES:
        return "context_only", "Not a supported Stellar custom TSV type"
    if not valid_value(typ, value):
        return "exclude_invalid", "Invalid or unsafe TSV value"
    if typ == "domain" and value.lower() in LEGITIMATE:
        return "context_only", "Legitimate AI API/update/telemetry or shared dual-use service"
    if typ == "url" and value in LEGITIMATE_URLS:
        return "context_only", "Legitimate software update endpoint"
    if typ == "sha256" and re.search(r"favicon|icon|logo|legitimate gamehook", rec["context"], re.I):
        return "context_only", "Benign binary or infrastructure fingerprint, not malware"
    if conf != "high":
        return "hunt_only", "Not high confidence after false-positive screening"
    return "curated_draft", "Reported high-confidence IOC, not independently live-validated"

def make_outputs(td_bytes: bytes, talos_bytes: bytes, output: Path, today: date, now: datetime):
    if not td_bytes or not talos_bytes or len(td_bytes) > MAX_BYTES or len(talos_bytes) > MAX_BYTES:
        raise ValueError("Empty or oversized source")
    text = td_bytes.decode("utf-8-sig")
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames or not THREATDEFENCE_REQUIRED.issubset(reader.fieldnames):
        raise ValueError("Source schema mismatch")
    rows = list(reader)
    if len(rows) < 100:
        raise ValueError("Suspiciously small ThreatDefence source; fail closed")
    seen = set()
    audit = []
    for r in rows:
        key = (r["type"].lower(), r["value"].lower())
        if key in seen:
            raise ValueError("Duplicate indicator " + str(key))
        seen.add(key)
        status, reason = classify(r, today)
        audit.append({**r, "triage": status, "reason": reason})
    curated = [r for r in audit if r["triage"] == "curated_draft"]
    if not curated or len(curated) > MAX_TSV_ROWS:
        raise ValueError("Empty or excessive curated feed; refuse to publish")
    reported = [date.fromisoformat(r["reported"]) for r in rows if r["reported"]]
    if not reported or (today - max(reported)).days > 45:
        raise ValueError("ThreatDefence feed is stale; fail closed")
    tsv_lines = []
    for r in sorted(curated, key=lambda x: (x["type"], x["value"])):
        tsv_type = TYPES[r["type"]]
        score = 85 if tsv_type.endswith("hash") else 80
        tsv_lines.append("\t".join((tsv_type, r["value"], "ThreatDefence", str(score))))
    tsv = ("\n".join(tsv_lines) + "\n").encode("utf-8")
    if len(tsv) >= MAX_STELLAR_TSV_BYTES:
        raise ValueError("TSV exceeds Stellar Cyber maximum")
    talos = set()
    unexpected = []
    for line in talos_bytes.decode("utf-8-sig").splitlines():
        value = line.strip()
        if not value or value.startswith("#") or value == "ARTEX IPs:":
            continue
        try:
            addr = ipaddress.ip_address(value)
            if addr.version == 4 and addr.is_global:
                talos.add(str(addr))
        except ValueError:
            unexpected.append(value[:120])
    if unexpected or len(talos) < 100:
        raise ValueError("Suspicious Talos source content: " + repr(unexpected[:3]))
    talos_active = (today - TALOS_SNAPSHOT_DATE).days <= TALOS_HUNT_TTL_DAYS
    ip_sources = ({addr: {"CiscoTalos"} for addr in talos} if talos_active else {})
    for r in audit:
        if r["type"] == "ipv4" and r["triage"] == "hunt_only":
            ip_sources.setdefault(r["value"], set()).add("ThreatDefence")
    hunt = ["value,sources,tier,automated_alert,reason"]
    for value in sorted(ip_sources, key=ipaddress.ip_address):
        hunt.append(",".join((value, "|".join(sorted(ip_sources[value])),
                              "HUNT_ONLY", "false", "unverified_live_activity")))
    output.mkdir(parents=True, exist_ok=True)
    tsv_path = output / "agentic-malicious-DRAFT.tsv"
    hunt_path = output / "agentic-ip-HUNT-ONLY.csv"
    audit_path = output / "agentic-source-audit.csv"
    tsv_path.write_bytes(tsv)
    hunt_path.write_text("\n".join(hunt) + "\n", encoding="utf-8")
    with audit_path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=reader.fieldnames + ["triage", "reason"])
        writer.writeheader()
        writer.writerows(audit)
    files = [tsv_path, hunt_path, audit_path]
    hashes = {p.name: hash_of(p.read_bytes()) for p in files}
    summary = {
        "schema": "stellar-osint-stage.v1",
        "status": "QA_ONLY_NOT_PUBLISHED",
        "sequence": int(now.timestamp()),
        "generated_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
        "source": {key: {"url": SOURCES[key], "sha256": hash_of(blob)}
                   for key, blob in (("threatdefence", td_bytes), ("talos", talos_bytes))},
        "files": hashes,
        "threatdefence_total": len(rows),
        "curated_count": len(curated),
        "hunt_ipv4_count": len(ip_sources),
        "talos_snapshot_date": TALOS_SNAPSHOT_DATE.isoformat(),
        "talos_hunt_status": "HUNT_ONLY_VALID" if talos_active else "HUNT_EXPIRED_EXCLUDED",
        "excluded_or_context_count": len(rows) - len(curated),
        "policy": "No auto-block; hunt IPs do not enter the Stellar custom TIP",
    }
    (output / "manifest.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    return summary

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--td-csv", type=Path)
    p.add_argument("--talos-txt", type=Path)
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--as-of", type=date.fromisoformat, default=datetime.now(timezone.utc).date())
    args = p.parse_args()
    if bool(args.td_csv) != bool(args.talos_txt):
        p.error("Use both local source files together")
    if args.td_csv:
        td, talos = args.td_csv.read_bytes(), args.talos_txt.read_bytes()
    else:
        td, talos = fetch_source("threatdefence", args.allow_network), fetch_source("talos", args.allow_network)
    now = datetime.now(timezone.utc)
    print(json.dumps(make_outputs(td, talos, args.output, args.as_of, now), indent=2))

if __name__ == "__main__":
    main()

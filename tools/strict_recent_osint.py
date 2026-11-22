#!/usr/bin/env python3
"""Strict, *staging-only* recent threat signals for Stellar Cyber TIP.

Only two distinct independent feeds are admitted:
- CERT Polska Warning List: currently active phishing domains first added <24h.
- OffSeq Mirage: multi-sensor observed hostile IPs last seen <24h, high confidence,
  concrete shell/ransom/sip-fraud/Mirai activity, no TOR/VPN/CGNAT/research scanners.

Neither generic ThreatDefence article-date IOCs nor bulk Talos historical IPs are
admitted. This build deliberately does not publish or perform any action in a DP.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cert_polska_osint import parse_recent, URL as CERT_URL
from jacob_honeypot_osint import select as select_jacob

OFFSEQ = "https://raw.githubusercontent.com/offseq/mirage-feed/data/"
FILES = {
    "manifest": OFFSEQ + "feed.json",
    "attackers": OFFSEQ + "latest/attackers-7d.csv",
    "scanners": OFFSEQ + "latest/known-scanners-ipv4.txt",
    "anonymizers": OFFSEQ + "latest/anonymizers-7d.txt",
    "cert": CERT_URL,
    "jacob_json": "https://raw.githubusercontent.com/jacobyoby/honeypot-blocklist/main/blocklist.json",
    "jacob_csv": "https://raw.githubusercontent.com/jacobyoby/honeypot-blocklist/main/blocklist.csv",
}
REQUIRED_FIELDS = {
    "ip", "first_seen", "last_seen", "tags", "sensors", "networks", "hits", "confidence",
}
STRONG_TAGS = {"shell-commands", "db-ransom", "mirai-like", "sip-fraud"}
IGNORED_TAGS = {"tor-exit", "vpn-exit", "cgnat"}
MAX_BYTES = {"manifest": 100000, "attackers": 4000000, "scanners": 1000000,
             "anonymizers": 200000, "cert": 32 * 1024 * 1024,
             "jacob_json": 500000, "jacob_csv": 250000}
MAX_IPS = 200
MAX_DOMAINS = 750
SOURCE_IP = "OffSeqMirage"
SOURCE_DOMAIN = "CERTPolska"
EXACT_GOOD_DOMAINS = {"google.com", "www.google.com", "microsoft.com",
                      "apple.com", "www.apple.com", "github.com", "www.github.com"}

class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirect denied for allowlisted TI source")

def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()

def download(key: str) -> bytes:
    url = FILES[key]
    origin = urlsplit(url)
    if origin.scheme != "https" or origin.hostname not in ("raw.githubusercontent.com", "hole.cert.pl"):
        raise ValueError("Unrecognized source")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), RejectRedirects())
    with opener.open(Request(url, headers={"User-Agent": "stellar-strict-osint-qa/1.0"}),
                     timeout=30) as response:
        raw = response.read(MAX_BYTES[key] + 1)
    if not raw or len(raw) > MAX_BYTES[key]:
        raise ValueError("Empty or oversized " + key + " input")
    return raw

def utc(ts: str) -> datetime:
    x = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if x.tzinfo is None:
        raise ValueError("OffSeq timestamps must include timezone")
    return x.astimezone(timezone.utc)

def extract_ip_lines(data: bytes) -> set[str]:
    result: set[str] = set()
    for line in data.decode("utf-8-sig").splitlines():
        ip = line.strip()
        if not ip:
            continue
        addr = ipaddress.ip_address(ip)
        if addr.version != 4 or not addr.is_global or ip in result:
            raise ValueError("Non-public or duplicate IPv4 in OffSeq exclusion list")
        result.add(ip)
    return result

def parse_offseq(inputs: dict[str, bytes], now: datetime) -> tuple[list[dict], dict]:
    if now.tzinfo is None:
        raise ValueError("UTC-aware clock required")
    meta = json.loads(inputs["manifest"].decode("utf-8"))
    if not isinstance(meta.get("license"), dict) or meta["license"].get("data") != "CC-BY-4.0":
        raise ValueError("Unexpected or missing OffSeq data license")
    generated = utc(meta["generated"])
    if not (now - timedelta(hours=48) <= generated <= now + timedelta(minutes=5)):
        raise ValueError("OffSeq source stale or future-dated")
    entries = {x["path"]: x for x in meta.get("files", []) if isinstance(x, dict) and "path" in x}
    requested = {"attackers": "latest/attackers-7d.csv",
                 "scanners": "latest/known-scanners-ipv4.txt",
                 "anonymizers": "latest/anonymizers-7d.txt"}
    for key, path in requested.items():
        source = entries.get(path)
        if not source or sha(inputs[key]) != source.get("sha256") or source.get("bytes") != len(inputs[key]):
            raise ValueError("OffSeq origin SHA256/length mismatch: " + key)
    exclude = extract_ip_lines(inputs["scanners"]) | extract_ip_lines(inputs["anonymizers"])
    data = csv.DictReader(io.StringIO(inputs["attackers"].decode("utf-8-sig")))
    if not data.fieldnames or not REQUIRED_FIELDS.issubset(data.fieldnames):
        raise ValueError("OffSeq CSV columns changed")
    seen = set()
    total = 0
    selected = []
    reasons: dict[str, int] = {}
    def reject(reason):
        reasons[reason] = reasons.get(reason, 0) + 1

    for row in data:
        total += 1
        ip = row["ip"].strip()
        address = ipaddress.ip_address(ip)
        if address.version != 4 or not address.is_global or ip in seen:
            raise ValueError("Invalid/duplicate OffSeq attacker IPv4")
        seen.add(ip)
        first, last = utc(row["first_seen"]), utc(row["last_seen"])
        if not (first <= last <= generated + timedelta(minutes=10)):
            raise ValueError("Inconsistent OffSeq observed time")
        tag_set = set(row["tags"].split(";"))
        if ip in exclude or tag_set & IGNORED_TAGS:
            reject("shared, anonymizer or research scanner")
            continue
        if not (now - timedelta(hours=24) <= last <= now):
            reject("no observation in the last 24 hours")
            continue
        if int(row["confidence"]) < 85:
            reject("confidence below strict 85")
            continue
        if int(row["sensors"]) < 3 or int(row["networks"]) < 2:
            reject("insufficient sensor/network independence")
            continue
        if not (tag_set & STRONG_TAGS):
            reject("only scanning, brute-force or generic web requests")
            continue
        selected.append({"value": ip, "score": min(int(row["confidence"]), 95),
                         "last_seen": last.isoformat(), "first_seen": first.isoformat(),
                         "tags": row["tags"], "confidence": int(row["confidence"]),
                         "sensors": int(row["sensors"]), "networks": int(row["networks"])})
    if total < 100 or total != entries[requested["attackers"]]["count"]:
        raise ValueError("OffSeq CSV unexpectedly short or count inconsistent")
    if not selected or len(selected) > MAX_IPS:
        raise ValueError("OffSeq strict IP volume out of policy")
    return sorted(selected, key=lambda x: x["value"]), {
        "raw_rows": total, "selected": len(selected), "rejections": reasons,
        "source_generated": generated.isoformat(), "source_license": "CC BY 4.0",
        "source_attribution": "OffSeq Mirage (https://github.com/offseq/mirage-feed)",
    }

def build(source: dict[str, bytes], out: Path, now: datetime) -> dict:
    if now.tzinfo is None:
        raise ValueError("UTC-aware clock required")
    for key in FILES:
        if key not in source or not source[key] or len(source[key]) > MAX_BYTES[key]:
            raise ValueError("Missing or oversized strict source " + key)
    ips, evidence = parse_offseq(source, now)
    jacob, jacob_evidence = select_jacob(source["jacob_csv"], source["jacob_json"], now)
    # Merge proven sensor sources only, preserving independent provenance.
    combined = {x["value"]: {**x, "source": SOURCE_IP} for x in ips}
    corroborated = 0
    for x in jacob:
        current = combined.get(x["value"])
        if current is not None:
            corroborated += 1
            combined[x["value"]] = {
                **current, "source": "Corroborated", "score": max(current["score"], x["score"]),
                "jacob": x,
            }
        else:
            combined[x["value"]] = x
    all_ips = sorted(combined.values(), key=lambda x: x["value"])
    if len(all_ips) > MAX_IPS:
        raise ValueError("Combined strict IP feed volume out of policy")
    domain_records, cert_evidence = parse_recent(source["cert"], now, with_added_at=True)
    domain_records = [r for r in domain_records if r["domain"].lower() not in EXACT_GOOD_DOMAINS]
    domains = [r["domain"] for r in domain_records]
    if not domains or len(domains) > MAX_DOMAINS:
        raise ValueError("CERT Polska recent domains outside strict volume ceiling")
    outputs = {
        "strict-recent-attackers-DRAFT.tsv": "".join(
            f"ip\t{x['value']}\t{x['source']}\t{x['score']}\n" for x in all_ips).encode(),
        "strict-recent-phishing-DRAFT.tsv": "".join(
            f"domain\t{d}\t{SOURCE_DOMAIN}\t75\n" for d in domains).encode(),
        "strict-ip-evidence.csv": ("ip,first_seen,last_seen,confidence,sensors,networks,tags\n" +
            "".join(f"{x['value']},{x['first_seen']},{x['last_seen']},{x['confidence']},{x['sensors']},{x['networks']},{x['tags']}\n" for x in ips)).encode(),
        "strict-domain-evidence.csv": ("domain,added_at,removed_at\n" +
            "".join(f"{r['domain']},{r['added_at']},\n" for r in domain_records)).encode(),
    }
    out.mkdir(parents=True, exist_ok=True)
    for name, payload in outputs.items():
        (out / name).write_bytes(payload)
    summary = {
        "schema": "stellar-strict-live-stage.v1",
        "status": "QA_ONLY_NOT_PUBLISHED",
        "sequence": int(now.timestamp()),
        "generated_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
        "source_sha256": {key: sha(val) for key, val in source.items()},
        "source_url": FILES,
        "files": {name: sha(payload) for name, payload in outputs.items()},
        "feed_counts": {"strict-recent-attackers-DRAFT.tsv": len(all_ips),
                        "strict-recent-phishing-DRAFT.tsv": len(domains)},
        "offseq": evidence,
        "jacob_honeypot": jacob_evidence,
        "corroborated_ip_count": corroborated,
        "cert_polska": cert_evidence,
        "data_rights": {
            "OffSeqMirage": "CC BY 4.0; attribution required",
            "JacobHoneypot": "CC0 1.0; original-sensor observations",
            "CERTPolska": "commercial permitted; no endorsement",
        },
        "rules": "No older article-date or bulk unattributed IPs; 24h last_seen / active domain; not production certified",
    }
    (out / "strict-manifest.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return summary

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--input-dir", type=Path, help="Offline fixture inputs: manifest,attackers,scanners,anonymizers,cert")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.allow_network == bool(args.input_dir):
        p.error("Use exactly one of --allow-network and --input-dir")
    blobs = {key: download(key) if args.allow_network else (args.input_dir / (key + ".bin")).read_bytes()
             for key in FILES}
    print(json.dumps(build(blobs, args.output, datetime.now(timezone.utc)), indent=2))

if __name__ == "__main__":
    main()

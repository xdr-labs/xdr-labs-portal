#!/usr/bin/env python3
"""CERT Polska v2 active phishing domains: recent-only TSV staging (not publication).

Source: https://hole.cert.pl/domains/v2/domains.csv
Rights: https://cert.pl/en/warning-list/ permits commercial use.
The official TSV columns are ordinal/register ID, domain, added_at, removed_at.
This adapter intentionally refuses unrecognized schema, stale data and >5000
recent records; no silent truncation, automatic blocking or customer publication.
"""
import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit
from urllib.request import Request, HTTPSHandler, HTTPRedirectHandler, build_opener
from zoneinfo import ZoneInfo

URL = "https://hole.cert.pl/domains/v2/domains.csv"
MAX_BYTES = 32 * 1024 * 1024
MAX_RECENT = 5000
SOURCE = "CERTPolska"

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("CERT source redirect not permitted")

def download() -> bytes:
    url = urlsplit(URL)
    assert url.scheme == "https" and url.hostname == "hole.cert.pl"
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    req = Request(URL, headers={"User-Agent": "stellar-cert-polska-qa/1.0", "Accept": "text/plain"})
    with opener.open(req, timeout=20) as response:
        raw = response.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("Empty or oversized CERT Polska source")
    return raw

def parse_time(s: str):
    value = s.strip()
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Unparseable CERT Polska timestamp") from exc
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=ZoneInfo("Europe/Warsaw"))
    return timestamp.astimezone(timezone.utc)

def parse_recent(raw: bytes, now: datetime):
    try:
        src = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CERT Polska data is not UTF-8") from exc
    if len(raw) > MAX_BYTES or not raw:
        raise ValueError("Empty/oversized CERT Polska input")
    if now.tzinfo is None:
        raise ValueError("UTC-aware clock required")
    cutoff = now - timedelta(hours=24)
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from agentic_osint_feed import valid_value

    seen = {}
    records = 0
    rejected = 0
    for row in csv.reader(io.StringIO(src), delimiter="\t"):
        if not row or not any(col.strip() for col in row):
            continue
        if len(row) != 4:
            raise ValueError("CERT Polska TSV schema changed (expected four fields)")
        ordinal, domain, added, removed = [c.strip() for c in row]
        if not ordinal.isdecimal():
            if records == 0 and re.search("domain|domen", domain, re.I):
                continue  # documented header row, not an IOC
            raise ValueError("CERT Polska unexpected ordinal/header")
        records += 1
        if not valid_value("domain", domain):
            rejected += 1
            continue
        created = parse_time(added)
        deleted = parse_time(removed)
        if not created or created > now + timedelta(minutes=5):
            raise ValueError("CERT Polska invalid or future insertion timestamp")
        if deleted is not None:
            continue
        if cutoff <= created <= now:
            seen[domain.lower()] = created
    if records < 100:
        raise ValueError("CERT Polska source unexpectedly small")
    if not seen:
        raise ValueError("No recent domains: possible stale feed, refuse to publish")
    if len(seen) > MAX_RECENT:
        raise ValueError("CERT recent domains exceed controlled 5000-item ceiling")
    return sorted(seen), {"source_rows": records, "recent_active": len(seen),
                          "excluded_invalid_domain": rejected, "window_hours": 24}

def stage(raw: bytes, output: Path, now: datetime):
    domains, summary = parse_recent(raw, now)
    output.mkdir(parents=True, exist_ok=True)
    file = output / "cert-polska-recent-DRAFT.tsv"
    payload = ("".join("domain\t%s\t%s\t75\n" % (d, SOURCE) for d in domains)).encode("utf-8")
    file.write_bytes(payload)
    info = {
        "schema": "stellar-cert-polska-stage.v1",
        "status": "QA_ONLY_NOT_PUBLISHED",
        "as_of": now.isoformat(), "expires_at": (now+timedelta(hours=24)).isoformat(),
        "source_url": URL, "source_sha256": hashlib.sha256(raw).hexdigest(),
        "feed_sha256": hashlib.sha256(payload).hexdigest(),
        "feed_rows": len(domains), "summary": summary,
        "notice": "Not an approved TIP feed. Validate OEM overlap, license and ingestion capacity.",
    }
    (output / "cert-polska-stage.json").write_text(json.dumps(info, sort_keys=True, indent=2)+"\n")
    return info

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source-file", type=Path, help="Offline fixture/test input")
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if bool(args.source_file) == bool(args.allow_network):
        p.error("Specify either --source-file or --allow-network")
    raw = args.source_file.read_bytes() if args.source_file else download()
    print(json.dumps(stage(raw, args.output, datetime.now(timezone.utc)), sort_keys=True))

if __name__ == "__main__":
    main()

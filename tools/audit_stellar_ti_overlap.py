#!/usr/bin/env python3
"""Read-only Stellar TIP OEM-overlap and IOC churn audit.

Never republishes, enables or removes any indicator. A native-feed export is
authoritative only when it is complete and recent; without one uniqueness is
UNKNOWN, not 100% novel.
"""
import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path

ALIASES = {"ipv4": "ip", "ipv4-addr": "ip", "ip": "ip",
           "domain": "domain", "fqdn": "domain",
           "url": "url", "sha256": "sha256-hash", "sha256-hash": "sha256-hash",
           "md5": "md5-hash", "md5-hash": "md5-hash", "sha1": "sha1-hash",
           "sha1-hash": "sha1-hash"}

def key_of(kind: str, value: str) -> tuple[str, str]:
    kind = ALIASES.get(kind.strip().lower())
    value = value.strip()
    if not kind or not value or any(x in value for x in ("\t","\n","\r","\0")):
        raise ValueError("Invalid or unsupported IOC type/value")
    if kind == "ip":
        parsed = ipaddress.ip_address(value)
        if parsed.version != 4 or not parsed.is_global:
            raise ValueError("Not an allowed public IPv4")
        value = str(parsed)
    elif kind == "domain":
        value = value.lower().rstrip(".")
        if not value or "." not in value or len(value) > 253:
            raise ValueError("Invalid domain")
    elif kind.endswith("-hash"):
        lengths = {"md5-hash":32, "sha1-hash":40, "sha256-hash":64}
        if len(value) != lengths[kind] or any(x not in "0123456789abcdefABCDEF" for x in value):
            raise ValueError("Invalid hash")
        value = value.lower()
    return kind,value

def read_tsv(path: Path):
    result = set()
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(),1):
        if not line.strip():
            continue
        cells = line.split("\t")
        if len(cells) != 4:
            raise ValueError("Stellar TSV must have exactly four columns, at row " + str(number))
        item = key_of(cells[0],cells[1])
        if item in result:
            raise ValueError("Duplicate IOC in Stellar TSV")
        result.add(item)
    if not result:
        raise ValueError("No candidate IOC data")
    return result

def read_oem_csv(path: Path):
    with path.open(newline="",encoding="utf-8-sig") as stream:
        reader=csv.DictReader(stream)
        if not reader.fieldnames or not {"type","value"} <= set(reader.fieldnames):
            raise ValueError("Native OEM export must have type,value columns")
        if not set(reader.fieldnames) <= {"type","value","source"}:
            raise ValueError("Unexpected fields; provide normalized type,value,source CSV")
        items = set()
        providers = {}
        for row in reader:
            key = key_of(row["type"],row["value"])
            if key in items:
                raise ValueError("Duplicate OEM indicator")
            items.add(key)
            p = (row.get("source") or "unspecified").strip()
            providers[p] = providers.get(p,0)+1
    if not items:
        raise ValueError("OEM inventory empty, cannot prove no overlap")
    return items,providers

def assess(candidate_files, previous_files, oem_file, oem_date, now):
    current = set().union(*(read_tsv(path) for path in candidate_files))
    if len(current) != sum(len(read_tsv(path)) for path in candidate_files):
        raise ValueError("IOC appears in multiple candidate feeds")
    previous = set().union(*(read_tsv(path) for path in previous_files)) if previous_files else set()
    report = {
        "schema":"stellar-ti-churn-audit.v1",
        "mode":"READ_ONLY_NOT_A_LIVE_TIP_TEST",
        "generated_at":now.isoformat(),
        "current_count":len(current),
        "previous_count":len(previous) if previous_files else None,
        "added_since_previous":len(current-previous) if previous_files else None,
        "removed_since_previous":len(previous-current) if previous_files else None,
        "removed_sample":sorted(str(t)+":"+v for t,v in (previous-current))[:20] if previous_files else [],
        "oem_overlap_state":"UNVERIFIED_NO_CUSTOMER_TENANT_EXPORT",
        "actual_dp_ttl_state":"NOT_TESTED",
    }
    if oem_file:
        if not oem_date or oem_date.tzinfo is None or not (
            now-timedelta(hours=24)<=oem_date<=now
        ):
            raise ValueError("Current OEM export must be timestamped within 24h")
        oem, providers = read_oem_csv(oem_file)
        common = current & oem
        report.update({
            "oem_overlap_state":"MEASURED_AGAINST_PROVIDED_EXPORT_NOT_PROOF_OF_COMPLETENESS",
            "oem_export_at":oem_date.isoformat(),
            "oem_export_sha256":hashlib.sha256(oem_file.read_bytes()).hexdigest(),
            "oem_count":len(oem),
            "oem_provider_counts":providers,
            "overlapping_indicators":len(common),
            "not_in_export":len(current-common),
            "overlap_percent":round(100*len(common)/len(current),2),
            "overlap_examples":sorted(str(t)+":"+v for t,v in common)[:20],
            "note":"The tenant export must cover all active built-in indicators to establish actual incremental coverage",
        })
    return report

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--current",type=Path,nargs="+",required=True)
    p.add_argument("--previous",type=Path,nargs="*")
    p.add_argument("--oem-csv",type=Path)
    p.add_argument("--oem-generated-at",type=datetime.fromisoformat)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    result=assess(args.current,args.previous,args.oem_csv,
                  args.oem_generated_at,datetime.now(timezone.utc))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":
    main()

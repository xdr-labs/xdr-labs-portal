#!/usr/bin/env python3
"""Independent Suricata 8 EVE verifier for all 44 new SIDs plus benign controls."""
import argparse
import json
from pathlib import Path
from generate_inert_pcap import CASES

NEW = set(range(9876001, 9876031)) | set(range(9876101, 9876115))

def verify(logs):
    observed, failures = {}, []
    for case, (_, _, expected) in CASES.items():
        file = logs / case / "eve.json"
        if not file.exists():
            failures.append(f"{case}: missing EVE output")
            continue
        seen = set()
        for line in file.read_text().splitlines():
            item = json.loads(line)
            if item.get("event_type") == "alert":
                sid = int(item["alert"]["signature_id"])
                if sid in NEW: seen.add(sid)
        observed[case] = sorted(seen)
        if expected - seen:
            failures.append(f"{case}: missing expected {sorted(expected - seen)}")
        if not expected and seen:
            failures.append(f"{case}: benign alert {sorted(seen)}")
    covered = set().union(*(set(v) for v in observed.values())) if observed else set()
    missing = NEW - covered
    if missing: failures.append(f"no positive fixture detected: {sorted(missing)}")
    outcome = {
        "engine": "Suricata 8.0.1 (Docker isolated)",
        "cases": len(CASES), "positive_sids": len(NEW - missing),
        "sids_expected": len(NEW), "failures": failures,
        "observed": observed,
        "limitations": "synthetic PCAP only, not Sensor/DP or real-world false positive tests",
    }
    print("SURICATA_8_REPLAY_REPORT", json.dumps(outcome, sort_keys=True))
    assert not failures, "Suricata 8 coverage / benign failure:\n" + "\n".join(failures)
    print(f"SURICATA_8_REPLAY_PASS {len(CASES)}/{len(CASES)} PCAPs; {len(NEW)}/{len(NEW)} SIDs")
    return outcome

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--logs", required=True, type=Path)
    args = p.parse_args()
    verify(args.logs)

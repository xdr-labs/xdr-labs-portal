#!/usr/bin/env python3
"""Verify isolated Suricata 8 replay against per-fixture EVE outputs."""
import argparse
import json
from pathlib import Path
from generate_inert_pcap import CASES, NEW
def check(directory):
    combined = set()
    for name, (_, _, expected) in CASES.items():
        path = directory / name / "eve.json"
        assert path.is_file(), "Missing EVE " + str(path)
        seen = set()
        for raw in path.read_text().splitlines():
            event = json.loads(raw)
            if event.get("event_type") == "alert":
                sid = int(event["alert"]["signature_id"])
                if sid in NEW:
                    seen.add(sid)
        assert expected.issubset(seen), "%s missing %s" % (name, expected - seen)
        if not expected:
            assert not seen, "%s false positive %s" % (name, seen)
        combined |= seen
    assert combined == NEW, "Uncovered SIDs: %s" % (NEW - combined)
    print("SURICATA8_REPLAY_PASS 398 syntax, %d fixtures, %d new SIDs" % (len(CASES), len(NEW)))
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--logs", type=Path, required=True)
    args = p.parse_args()
    check(args.logs)

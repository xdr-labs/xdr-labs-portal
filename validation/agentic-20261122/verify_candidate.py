#!/usr/bin/env python3
"""Offline integrity gate: 383 immutable original rules + 15 curated addendum.

QA only: no Sensor import, no production rule publication.
"""
from pathlib import Path
import csv
import hashlib
import re

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
CANDIDATE = ROOT / "downloads/local-web-attack-ai-v1.3-398-qa.rules"
SOURCE_MAP = Path(__file__).with_name("source-map-addendum.csv")
BASE_SHA = "0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
NEW_IDS = set(range(9876201, 9876216))

def verify():
    base = BASE.read_bytes()
    cand = CANDIDATE.read_bytes()
    assert hashlib.sha256(base).hexdigest() == BASE_SHA, "Original published 383-byte baseline altered"
    assert cand.startswith(base), "Existing 383 signatures not byte-preserved"
    rules = [line for line in cand.decode("utf-8").splitlines() if line.startswith("alert ")]
    original = [line for line in base.decode("utf-8").splitlines() if line.startswith("alert ")]
    assert len(original) == 383, "Existing rule count changed"
    assert len(rules) == 398 and len(rules) == len(set(rules)), "Candidate rule count malformed"
    sids = []
    for rule in rules:
        match = re.search(r"\bsid:(\d+);", rule)
        assert match and rule.endswith(")"), "Malformed signature"
        assert rule.startswith("alert "), "Non-alert action found"
        sids.append(int(match.group(1)))
    assert len(set(sids)) == 398, "Duplicate SID"
    assert set(sids[383:]) == NEW_IDS, "Unexpected or missing new SID"
    with SOURCE_MAP.open(newline="", encoding="utf-8") as fp:
        mapping = list(csv.DictReader(fp))
    assert len(mapping) == 15
    assert {int(row["new_sid"]) for row in mapping} == NEW_IDS
    assert all(row["upstream_sid"].isdigit() and row["source_path"].endswith(".rules")
               and row["policy"] == "candidate-alert" for row in mapping)
    print("STATIC_PASS base 383 preserved, QA candidate 398, addendum 15, unique alert SIDs")
    print("BASE_SHA256", BASE_SHA)
    print("CANDIDATE_SHA256", hashlib.sha256(cand).hexdigest())

if __name__ == "__main__":
    verify()

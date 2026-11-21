#!/usr/bin/env python3
"""Static policy and preservation gate for combined 383-rule Suricata candidate."""
from pathlib import Path
import csv, hashlib, re

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "downloads/local-web-attack-ai-v1.1-339.rules"
CAND = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
MAP = ROOT / "validation/agentic-20261121/source-map.csv"
BASELINE_SHA = "2478ffd6b3dbdfbb527695f07e00e1a106a554d8bb898a0f9584bb3845b07483"

def parse(data):
    lines = [line for line in data.decode().splitlines() if line.startswith("alert ")]
    ids = []
    for line in lines:
        match = re.search(r"\bsid:(\d+);", line)
        assert match and line.endswith(")"), f"malformed rule: {line[:120]}"
        assert line.startswith("alert "), "blocking rule action"
        proto = line.split()[1]
        if proto == "http": assert "http." in line, "HTTP without sticky buffer"
        if proto == "tls": assert "tls." in line, "TLS without sticky buffer"
        if proto == "dns": assert "dns.query" in line, "DNS without query buffer"
        ids.append(int(match.group(1)))
    return lines, ids

def verify():
    base, cand = BASE.read_bytes(), CAND.read_bytes()
    assert hashlib.sha256(base).hexdigest() == BASELINE_SHA, "published baseline modified"
    assert cand.startswith(base), "first 339 signatures must be byte-identical"
    base_lines, base_ids = parse(base)
    all_lines, all_ids = parse(cand)
    assert len(base_lines) == len(set(base_ids)) == 339
    assert len(all_lines) == len(set(all_ids)) == 383, "383 count or SID collision"
    delta_ids = all_ids[len(base_ids):]
    assert delta_ids == list(range(9876001, 9876031)) + list(range(9876101, 9876115)), "missing or reordered new SID"
    with MAP.open(newline="") as stream:
        mapping = list(csv.DictReader(stream))
    assert len(mapping) == 44
    assert [int(m["new_sid"]) for m in mapping] == delta_ids, "source-map inconsistent"
    assert all(m["group"] == "integrated" for m in mapping)
    print("STATIC_PASS 339 byte-preserved + 44 merged + 383 unique alert SIDs")
    print("BASE_SHA256", hashlib.sha256(base).hexdigest())
    print("CANDIDATE_SHA256", hashlib.sha256(cand).hexdigest())
    return all_ids

if __name__ == "__main__":
    verify()

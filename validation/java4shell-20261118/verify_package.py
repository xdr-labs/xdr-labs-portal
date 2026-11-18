#!/usr/bin/env python3
"""Fail-closed source-integrity gate for Java4Shell v1.1 339-rule release."""
from pathlib import Path
import argparse
import hashlib
import re

BASE_SHA = "5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96"
NEW_SHA = "e05bcf3dc56bb0331481dbec8c4cad92561b66133e1fd274421886472e33cd03"
COMBINED_SHA = "2478ffd6b3dbdfbb527695f07e00e1a106a554d8bb898a0f9584bb3845b07483"
SIDS = set(range(9006101, 9006107))
ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--base", type=Path, default=ROOT / "downloads/local-web-attack-ai-v1.0-333.rules")
parser.add_argument("--additional", type=Path, default=ROOT / "downloads/java4shell-cve-2026-114938-6.rules")
parser.add_argument("--combined", type=Path, default=ROOT / "downloads/local-web-attack-ai-v1.1-339.rules")
a = parser.parse_args()
base, new, combined = (p.read_bytes() for p in (a.base, a.additional, a.combined))
def sha(data): return hashlib.sha256(data).hexdigest()
assert sha(base) == BASE_SHA, "original 333 bytes changed"
assert sha(new) == NEW_SHA, "Java4Shell six-signature candidate changed"
assert sha(combined) == COMBINED_SHA, "339-rule release hash mismatch"
assert combined == base + (b"" if base.endswith(b"\n") else b"\n") + new, "original 333 not unchanged prefix"
def alert_lines(data): return [l for l in data.decode("utf-8").splitlines() if l.startswith("alert ")]
def sids(lines):
    values=[]
    for line in lines:
        m=re.search(r"\bsid:(\d+);", line)
        assert m, "missing sid"
        values.append(int(m.group(1)))
    return values
b,n,c=map(alert_lines,(base,new,combined))
assert len(b)==333 and len(n)==6 and len(c)==339, "rule counts mismatch"
assert len(set(sids(c)))==339, "duplicate SID"
assert set(sids(n))==SIDS, "Java4Shell SID mismatch"
print("PASS | base=333 | new=6 | total=339 | no duplicate SIDs | hash and byte-preservation OK")

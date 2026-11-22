#!/usr/bin/env python3
"""Fail-closed QA-only EVE verifier for Lua multipart control counting experiments."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SRC = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
SOURCE_SHA = "0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
SID = 9005055
EXPECTED = {
    "php-empty99": False,
    "php-empty100": True,
    "php-empty105": True,
    "php-empty100-wide-gap": True,
    "php-empty105-wide-gap": True,
    "php-nonempty105": False,
    "php-wrongtype105": False,
    "nextjs-positive": False,
    "nextjs-origin-form": False,
    "nextjs-no-upgrade": False,
    "nextjs-no-key": False,
    "nextjs-benign-proxy-http": False,
    "nextjs-benign-proxy-https": False,
}

def verify(folder: Path):
    assert hashlib.sha256(SRC.read_bytes()).hexdigest() == SOURCE_SHA
    found = {}
    errors = []
    for case, positive in EXPECTED.items():
        path = folder / case / "eve.json"
        if not path.is_file():
            errors.append(case + ": missing EVE output")
            continue
        count = 0
        for line in path.read_text().splitlines():
            ev = json.loads(line)
            if ev.get("event_type") == "alert" and int(ev["alert"]["signature_id"]) == SID:
                count += 1
        found[case] = count
        if bool(count) != positive:
            errors.append(f"{case}: expected alert={positive} got {count}")
    report = {
        "positive_expected": sum(EXPECTED.values()),
        "negative_expected": len(EXPECTED)-sum(EXPECTED.values()),
        "cases":len(EXPECTED),
        "observed":found,
        "failures":errors,
        "release_ready":False,
        "scope":"QA-only 100-empty-filename shape; does not detect all CVE-2026-109618 variants",
        "needs_auxiliary_lua_and_body_buffer_config":True,
    }
    print("PHP2SHELL_LUA_QA_REPORT",json.dumps(report,sort_keys=True))
    assert not errors, "\n".join(errors)
    print("PHP2SHELL_LUA_QA_PASS",len(EXPECTED))
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--logs",required=True,type=Path)
    args=p.parse_args()
    verify(args.logs)

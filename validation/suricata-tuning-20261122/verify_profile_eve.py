#!/usr/bin/env python3
"""Check 365 default and 377 combined rules against existing harmless PCAP corpora.

A successful opt-in profile test does not authorize public release or sensor reload.
"""
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "validation/agentic-20261121"))
from generate_inert_pcap import CASES

CORE = set(range(9876001,9876029))
OPTIONAL = {9876029,9876030} | (set(range(9876101,9876115))-{9876104,9876109,9876110,9876111})
AGENTIC = set(range(9876001,9876031)) | set(range(9876101,9876115))
OAST = {
    "legit-oast-interact": 9006065,
    "legit-oast-fun": 9006064,
    "legit-oast-burp": 9006067,
}
PENTAGI = {
    "legit-pentagi-update-dns":9876105,
    "legit-pentagi-update-tls":9876106,
}
NEAR_MISS = {"near-miss-update-dns", "near-miss-update-tls", "not-update-domain"}
BASEDIR = Path(__file__).resolve().parent

def alerts(file: Path) -> set[int]:
    assert file.exists(), "Missing EVE file: " + str(file)
    found=set()
    for line in file.read_text().splitlines():
        rec=json.loads(line)
        if rec.get("event_type")=="alert":
            found.add(int(rec["alert"]["signature_id"]))
    return found

def check(base: Path):
    failures=[]
    counts={}
    for profile,active in [("core",CORE),("combined",CORE|OPTIONAL)]:
        seen=set()
        for case, (_, __, expected) in CASES.items():
            emitted=alerts(base/profile/"agentic"/case/"eve.json")
            new=emitted&AGENTIC
            expected_active=expected & active
            if not expected_active<=new:
                failures.append(f"{profile}/{case}: missing {sorted(expected_active-new)}")
            if not new<=active:
                failures.append(f"{profile}/{case}: excluded new SID triggered {sorted(new-active)}")
            if not expected_active and case.startswith("benign-") and new:
                failures.append(f"{profile}/{case}: benign fixture triggered {sorted(new)}")
            seen.update(new)
        if seen!=active:
            failures.append(f"{profile}: expected exactly {len(active)} distinct new SIDs; got missing {sorted(active-seen)} extra {sorted(seen-active)}")
        risk_names=["legit-claude-webfetch","legit-qwen-code","legit-norma-client","legit-maintenance-api",
                    "legit-management-tool-api","legit-wsus-service","legit-pentagi-update-dns",
                    "legit-pentagi-update-tls","legit-port-28500","legit-oast-interact",
                    "legit-oast-fun","legit-oast-burp","legit-model-prompt","near-miss-update-dns",
                    "near-miss-update-tls","not-update-domain","not-oast-domain",
                    "wrong-command-api-port","normal-home","normal-tcp-port"]
        for name in risk_names:
            emitted=alerts(base/profile/"risk"/name/"eve.json")
            if emitted&({9876104,9876109,9876110,9876111}):
                failures.append(f"{profile}/{name}: retired OAST/port SID fired {sorted(emitted)}")
            if profile=="core" and emitted&OPTIONAL:
                failures.append(f"{profile}/{name}: optional SID fired {sorted(emitted&OPTIONAL)}")
            if name in OAST:
                old=OAST[name]
                if old not in emitted:
                    failures.append(f"{profile}/{name}: expected one retained original OAST SID {old}")
            if name in NEAR_MISS and (emitted&{9876105,9876106}):
                failures.append(f"{profile}/{name}: PentAGI exact-domain boundary failed")
            if name in PENTAGI:
                sid=PENTAGI[name]
                if profile=="combined" and sid not in emitted:
                    failures.append(f"{profile}/{name}: exact PentAGI hostname should match")
                if profile=="core" and sid in emitted:
                    failures.append(f"{profile}/{name}: optional PentAGI lookup appeared in core")
            if name=="legit-port-28500" and 9876104 in emitted:
                failures.append(f"{profile}/{name}: port-only detection still enabled")
            if name in {"legit-claude-webfetch","legit-qwen-code","legit-norma-client"} and profile=="core" and emitted&{9876101,9876107,9876108}:
                failures.append(f"{profile}/{name}: normal tool UA matched new active core")
        counts[profile]={"agentic_pcap_cases":len(CASES),"risk_pcap_cases":len(risk_names),"new_distinct_sids":len(seen)}
    result={"status":"PASS" if not failures else "FAIL","profiles":counts,"failures":failures,
            "limitation":"synthetic offline PCAPs only; production false-positive rate not measured"}
    print("QUALITY_PROFILE_BEHAVIOR",json.dumps(result,sort_keys=True))
    assert not failures, "\n".join(failures)
    print("QUALITY_PROFILE_PASS: core 365+ combined 377, 49 agentic + 20 risk PCAPs each")
    return result
if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--logs",required=True,type=Path)
    args=ap.parse_args()
    check(args.logs)

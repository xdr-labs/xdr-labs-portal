#!/usr/bin/env python3
"""Full 383-SID inventory cross-check against unmodified release and historical evidence.

This is a per-SID audit, NOT a claim that 383 individual positive network PCAP
samples have been replayed against the current 383-rule binary in this run.
"""
import argparse
import collections
import csv
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE333 = ROOT / "downloads/local-web-attack-ai-v1.0-333.rules"
BASE339 = ROOT / "downloads/local-web-attack-ai-v1.1-339.rules"
FULL383 = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
HIST = ROOT / "validation/suricata-v1.0-modular-333-per-sid.csv"
INVENTORY = HERE / "inventory-383.csv"
CATALOG = ROOT / "downloads/local-web-attack-ai-v1.2-383-catalog.csv"
SOURCES = ROOT / "validation/agentic-20261121/source-map.csv"
EXPECTED_FULL_SHA = "0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
EXPECTED_PREVIOUS_SHA = "2478ffd6b3dbdfbb527695f07e00e1a106a554d8bb898a0f9584bb3845b07483"
EXPECTED_333_SHA = "5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96"
KNOWN_UNREPRODUCED = {9005017, 9005055}
KNOWN_OVERLAPS = {(9006065, 9876109), (9006064, 9876110), (9006067, 9876111)}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def parse_rules(path):
    results = []
    for line in path.read_text().splitlines():
        if not line.startswith("alert "):
            continue
        match = re.search(r"\bsid:(\d+);", line)
        assert match and line.endswith(")"), "malformed rule line"
        sid = int(match.group(1))
        msg = re.search(r'\bmsg:"((?:\\.|[^"])*)";', line)
        assert msg, f"{sid}: missing message"
        protocol = line.split()[1]
        assert protocol in {"http", "dns", "tcp", "tls", "smb", "dcerpc"}, (sid, protocol)
        if protocol == "http":
            assert "http." in line, f"{sid}: missing HTTP sticky-buffer"
        elif protocol == "dns":
            assert "dns.query;" in line, f"{sid}: missing DNS buffer"
        results.append((sid, protocol, msg.group(1), line))
    ids = [x[0] for x in results]
    assert len(ids) == len(set(ids)), "SID duplication"
    return results

def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def verify():
    assert sha(BASE333) == EXPECTED_333_SHA
    assert sha(BASE339) == EXPECTED_PREVIOUS_SHA
    assert sha(FULL383) == EXPECTED_FULL_SHA
    assert FULL383.read_bytes().startswith(BASE339.read_bytes()), "previous 339 changed"
    old, base, allrules = map(parse_rules, [BASE333, BASE339, FULL383])
    assert [x[:3] for x in old] == [x[:3] for x in base[:333]]
    assert [x[:3] for x in base] == [x[:3] for x in allrules[:339]]
    assert len(old) == 333 and len(base) == 339 and len(allrules) == 383
    assert [x[0] for x in allrules[339:]] == (list(range(9876001, 9876031))
                                                 + list(range(9876101, 9876115)))
    historical = read_csv(HIST)
    catalog = read_csv(CATALOG)
    inventory = read_csv(INVENTORY)
    source = read_csv(SOURCES)
    assert len(historical) == 333 and len(catalog) == len(inventory) == 383 and len(source) == 44
    assert [int(x["sid"]) for x in inventory] == [x[0] for x in allrules]
    assert [int(x["sid"]) for x in catalog] == [x[0] for x in allrules]
    assert [int(x["sid"]) for x in historical] == [x[0] for x in old]
    assert [int(x["new_sid"]) for x in source] == [x[0] for x in allrules[339:]]
    assert {int(x["sid"]) for x in historical if x["status"] == "NOT_REPRODUCED"} == KNOWN_UNREPRODUCED
    historical_ids = {int(x["sid"]) for x in historical}

    evidence = collections.Counter()
    kinds = collections.Counter()
    risk = collections.Counter()
    for (sid, proto, msg, line), row in zip(allrules, inventory):
        assert row["signature_message"] == msg and row["protocol"] == proto, f"{sid}: inventory mismatch"
        ev = row["per_sid_evidence"]
        expected = ("historical_sensor_individual_alert" if sid in historical_ids and sid not in KNOWN_UNREPRODUCED
                    else "historical_not_reproduced" if sid in KNOWN_UNREPRODUCED
                    else "historical_modular_sensor_offline_java_fixture" if 9006101 <= sid <= 9006106
                    else "isolated_suricata_7_8_individual_synthetic_fixture")
        assert ev == expected, (sid, ev, expected)
        assert line.startswith("alert ") and "sid:" in line, (sid, "non-alert / missing ID")
        if row["risk_category"] != "NONE":
            risk[row["risk_category"]] += 1
        evidence[ev] += 1
        kinds[proto] += 1
    assert evidence == {
        "historical_sensor_individual_alert": 331,
        "historical_not_reproduced": 2,
        "historical_modular_sensor_offline_java_fixture": 6,
        "isolated_suricata_7_8_individual_synthetic_fixture": 44,
    }, evidence
    assert kinds == {"http": 358, "tcp": 7, "smb": 2, "dcerpc": 1, "dns": 10, "tls": 5}

    per_sid = {x[0]: x[3] for x in allrules}
    assert "content:\".interact.sh\"" in per_sid[9006065]
    assert "content:\".interact.sh\"" in per_sid[9876109]
    assert "content:\".oast.\"" in per_sid[9006064]
    assert "content:\".oast.fun\"" in per_sid[9876110]
    assert "content:\".burpcollaborator.net\"" in per_sid[9006067]
    assert "content:\".burpcollaborator.net\"" in per_sid[9876111]
    assert "28000:29999" in per_sid[9876104] and "content:" not in per_sid[9876104]
    assert "malware_family BLOODALCHEMY" in per_sid[9876029]
    assert "ARTEX campaign" in per_sid[9876029], "attribution warning needs explicit review"
    assert not any(x[3].startswith(("drop ", "reject ", "pass ")) for x in allrules)

    report = {
        "overall": "INVENTORY_PASS_RELEASE_ACCEPTANCE_NOT_INFERRED",
        "rule_sha256": sha(FULL383),
        "rule_count": 383,
        "unique_sid_count": 383,
        "protocols": dict(kinds),
        "prior_339_preserved": True,
        "per_sid_evidence": dict(evidence),
        "rule_with_risk_annotations": sum(risk.values()),
        "risk_types": dict(risk),
        "historical_unreproduced": sorted(KNOWN_UNREPRODUCED),
        "overlapping_oast_sid_pairs": sorted([list(p) for p in KNOWN_OVERLAPS]),
        "current_full_383_replayed_old_331_individually": False,
        "current_live_sensor_import_or_dp_case_test": False,
        "production_fp_fn_assessed": False,
        "release_ready": False,
    }
    print("FULL_INVENTORY_PASS: 383/383 audited; 339 unchanged; 331 historical, 2 unreproduced, 6 sensor-offline historical, 44 CI synthetic")
    print("AUDIT_SUMMARY", json.dumps(report, sort_keys=True))
    return report

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--report", type=Path, default=None)
    args = p.parse_args()
    summary = verify()
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Verify sanitized, remotely observed sensor QA evidence without conflating real-time DP tests."""
from pathlib import Path
import csv, hashlib, json, re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SRC = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
EVIDENCE = HERE / "sensor-383-summary-20261122.json"
SIDS = HERE / "sensor-383-per-sid-20261122.csv"
EXPECTED = "0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
LIVE = "5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96"

def main():
    d = json.loads(EVIDENCE.read_text())
    assert hashlib.sha256(SRC.read_bytes()).hexdigest() == EXPECTED
    assert d["candidate_sha256"] == EXPECTED
    assert d["operational_rules_sha256"] == LIVE
    assert d["suricata_version"] == "8.0.1"
    assert d["operational_rules_unchanged"] and d["operational_suricata_process_unchanged"]
    assert d["total_rule_sids"] == 383 and d["current_sensor_offline_positive_sids"] == 381
    assert d["current_sensor_offline_not_reproduced"] == [9005017, 9005055]
    assert d["original_v1_0"]["curated_pcaps"] == 77
    assert d["original_v1_0"]["differential_full_vs_original_pcap_runs"] == 154
    assert d["original_v1_0"]["per_pcap_regression_count"] == 0
    assert d["original_v1_0"]["observed"] == 331
    assert d["java4shell_v1_1"]["cases_passing"] == 10
    assert d["agentic_v1_2"]["cases_passing"] == 49
    assert d["normal_traffic_risks"]["cases_executed"] == 20
    assert d["legacy_unconfirmed_24"]["alerts_for_unconfirmed_2"] == 0
    assert not d["normal_traffic_risks"]["real_network_false_positive_rate_measured"]
    assert d["release_ready"] is False
    rules = [l for l in SRC.read_text().splitlines() if l.startswith("alert ")]
    with SIDS.open(newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(rules) == 383
    observed, missing, groups = set(), set(), {}
    for l, row in zip(rules, rows):
        sid = int(re.search(r"\bsid:(\d+);",l).group(1))
        assert int(row["sid"]) == sid
        assert row["protocol"] == l.split()[1]
        assert row["message"] == re.search(r'msg:"(.*?)";',l).group(1)
        group = row["group"]
        groups[group] = groups.get(group, 0) + 1
        if row["sensor_offline_alert_observed"] == "True":
            observed.add(sid)
        else:
            assert row["sensor_offline_alert_observed"] == "False"
            missing.add(sid)
    assert groups == {"original_v1_0":333,"java4shell_v1_1":6,"agentic_v1_2":44}, groups
    assert len(observed) == 381 and missing == {9005017,9005055}
    print("ACTUAL_SENSOR_EVIDENCE_PASS: 383/383 audited; 381 offline SID alerts; 2 unreproduced; 77-PCAP 154-run differential no per-PCAP regression")

if __name__ == "__main__":
    main()

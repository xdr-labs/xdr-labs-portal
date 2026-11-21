#!/usr/bin/env python3
"""Summarize a bounded 100-session non-exploit multipart PCAP replay.

Timing includes Suricata startup; does not establish EPS or production capacity.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--pcap", type=Path, required=True)
p.add_argument("--eve", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--version", required=True)
a = p.parse_args()
assert a.pcap.is_file() and a.eve.is_file()
data = a.pcap.read_bytes()
assert data.startswith(bytes.fromhex("d4c3b2a1")), "not a classic little-endian PCAP"
assert 0 < len(data) < 50_000_000, "unexpected fixture size"
alerts = collections.Counter()
for line in a.eve.read_text().splitlines():
    item = json.loads(line)
    if item.get("event_type") == "alert":
        alerts[int(item["alert"]["signature_id"])] += 1
report = {
    "engine": a.version,
    "test": "bounded harmless multipart PCAP, 100 sessions each containing 105 empty-filename form controls",
    "network_transmission": False,
    "pcap_bytes": len(data),
    "pcap_sha256": hashlib.sha256(data).hexdigest(),
    "all_alerts": sum(alerts.values()),
    "sid_alert_counts": dict(sorted(alerts.items())),
    "legacy_9005055_alerts": alerts[9005055],
    "source_rules_file": "downloads/local-web-attack-ai-v1.2-383-rc1.rules",
    "interpretation": "Offline engine completed. Process CPU/RSS includes startup, not an EPS benchmark or production FP/FN result.",
    "release_ready": False,
}
a.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print("SURICATA_STRESS_100_COMPLETED", json.dumps(report, sort_keys=True))

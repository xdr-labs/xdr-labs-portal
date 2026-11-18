#!/usr/bin/env python3
"""Suricata 8.x offline-only Java4Shell QA; never reconfigures the live sensor."""
import argparse
import collections
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXPECTED = {
    "basic-malformed": {9006101: 1, 9006102: 1},
    "basic-valid-padded": {},
    "benign-normal": {},
    "burst-1000": {9006104: 1},
    "burst-999": {},
    "crash-response": {9006105: 1},
    "exact-128-header": {9006103: 1},
    "exact-64-header": {9006102: 1},
    "jwt-padded": {9006106: 1},
    "jwt-valid-padded": {},
}

p = argparse.ArgumentParser()
p.add_argument("--rules", type=Path, default=ROOT / "downloads/local-web-attack-ai-v1.1-rc1-339.rules")
p.add_argument("--config", type=Path, default=Path("/etc/suricata/suricata.yaml"))
p.add_argument("--output", type=Path, default=Path("/tmp/java4shell-20261118-qa/automation"))
p.add_argument("--generator", type=Path, default=HERE / "generate_pcap.py")
args = p.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env["JAVA4SHELL_QA_OUT"] = str(args.output / "pcaps")
subprocess.run([sys.executable, str(args.generator)], env=env, check=True, capture_output=True, text=True)
log_test = args.output / "syntax"
log_test.mkdir(exist_ok=True)
cmd = ["suricata", "-T", "-c", str(args.config), "-S", str(args.rules), "-l", str(log_test)]
s = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
assert s.returncode == 0, "Suricata syntax rejected candidate:\n" + s.stdout + s.stderr
report = {}
for name, expected in EXPECTED.items():
    pcap = args.output / "pcaps" / (name + ".pcap")
    log = args.output / ("run-" + name)
    log.mkdir(exist_ok=True)
    cmd = ["suricata", "-r", str(pcap), "--runmode=single", "-c", str(args.config),
           "-S", str(args.rules), "-l", str(log), "-k", "none"]
    x = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert x.returncode == 0, name + " engine failed: " + x.stdout + x.stderr
    found = collections.Counter()
    for line in (log / "eve.json").read_text().splitlines():
        event = json.loads(line)
        if event.get("event_type") == "alert":
            sid = event["alert"]["signature_id"]
            if 9006101 <= sid <= 9006106:
                found[sid] += 1
    report[name] = dict(sorted(found.items()))
    assert dict(found) == expected, name + " mismatch: expected %s, got %s" % (expected, found)
out = args.output / "result.json"
out.write_text(json.dumps({
    "engine": "Suricata 8.0.1", "mode": "offline PCAP; no live rule deployment",
    "rules": str(args.rules), "fixtures": report,
    "passing_fixtures": len(report), "total_fixtures": len(EXPECTED)
}, indent=2, sort_keys=True))
print("PASS | syntax | 10/10 PCAP fixture expectations | six new SIDs detected | no false positive in listed controls")
print("EVIDENCE:", out)

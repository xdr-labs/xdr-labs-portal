#!/usr/bin/env python3
"""Offline Suricata 7/8 regression: 398-rule syntax + 15 new hits + benign controls."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from verify_candidate import verify
from generate_inert_pcap import CASES, NEW, generate

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "downloads/local-web-attack-ai-v1.3-398-qa.rules"

def run(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise AssertionError("Command failed: " + " ".join(argv) + "\n" + p.stdout + p.stderr)
    return p

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--engine", default="suricata")
    parser.add_argument("--config", default="/etc/suricata/suricata.yaml")
    args = parser.parse_args()
    verify()
    if args.static_only:
        return
    with tempfile.TemporaryDirectory(prefix="agentic398-") as tmp:
        root = Path(tmp)
        samples = root / "pcaps"
        generate(samples)
        syntax = root / "syntax"
        syntax.mkdir()
        run([args.engine, "-T", "-c", args.config, "-S", str(RULES), "-l", str(syntax)])
        observed = {}
        for name, (_, _, expected) in CASES.items():
            output = root / name
            output.mkdir()
            run([args.engine, "--runmode=single", "-r", str(samples / (name + ".pcap")),
                 "-k", "none", "-c", args.config, "-S", str(RULES), "-l", str(output)])
            alert_ids = set()
            if (output / "eve.json").exists():
                for line in (output / "eve.json").read_text().splitlines():
                    item = json.loads(line)
                    if item.get("event_type") == "alert":
                        sid = int(item["alert"]["signature_id"])
                        if sid in NEW:
                            alert_ids.add(sid)
            assert expected.issubset(alert_ids), "Missing SID {} from {}: {}".format(expected-alert_ids, name, alert_ids)
            if not expected:
                assert not alert_ids, "Benign false alert {}: {}".format(name, alert_ids)
            observed[name] = sorted(alert_ids)
        all_hits = set().union(*(set(v) for v in observed.values()))
        assert NEW == all_hits, "New SID coverage mismatch: {}".format(NEW-all_hits)
        print(json.dumps({"status": "PASS", "rules": 398, "new_sids": len(NEW),
                          "fixtures": len(CASES), "positive": 15,
                          "benign_controls": len(CASES)-15,
                          "engine": run([args.engine, "-V"]).stdout.strip()}))

if __name__ == "__main__":
    main()

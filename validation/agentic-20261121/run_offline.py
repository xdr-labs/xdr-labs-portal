#!/usr/bin/env python3
"""Static integrity + engine-based per-SID PCAP testing of unified 383-rule pack."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from verify_candidate import verify
from generate_inert_pcap import CASES, generate

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
VALID_SIDS = set(range(9876001, 9876031)) | set(range(9876101, 9876115))

def run(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
    assert p.returncode == 0, f"Command failed: {' '.join(cmd)}\n{p.stdout}\n{p.stderr}"
    return p

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--static-only", action="store_true")
    p.add_argument("--config", default="/etc/suricata/suricata.yaml")
    p.add_argument("--engine", default="suricata")
    p.add_argument("--output-json", default="")
    args = p.parse_args()
    verify()
    if args.static_only: return
    with tempfile.TemporaryDirectory(prefix="agentic383-") as tmp:
        tmp = Path(tmp)
        pcaps = tmp / "pcaps"
        count = generate(pcaps)
        syntax = tmp / "syntax"
        syntax.mkdir()
        run([args.engine, "-T", "-c", args.config, "-S", str(RULES), "-l", str(syntax)])
        observed = {}
        errors = []
        for name, (kind, data, expected) in CASES.items():
            folder = tmp / ("run-" + name)
            folder.mkdir()
            run([args.engine, "-r", str(pcaps / (name + ".pcap")),
                 "--runmode=single", "-c", args.config, "-S", str(RULES),
                 "-l", str(folder), "-k", "none"])
            seen = set()
            eve = folder / "eve.json"
            if eve.exists():
                for line in eve.read_text().splitlines():
                    e = json.loads(line)
                    if e.get("event_type") == "alert":
                        sid = int(e["alert"]["signature_id"])
                        if sid in VALID_SIDS: seen.add(sid)
            observed[name] = sorted(seen)
            missing = expected - seen
            if missing: errors.append(f"{name}: missing {sorted(missing)} (seen {sorted(seen)})")
            if not expected and seen: errors.append(f"{name}: benign false alert {sorted(seen)}")
        all_pos = set().union(*(exp for _, _, exp in CASES.values()))
        coverage = all_pos & set.union(set(), *(set(v) for v in observed.values()))
        report = {
            "candidate": str(RULES.relative_to(ROOT)),
            "engine": run([args.engine, "--version"]).stdout.strip(),
            "total_rules": 383,
            "new_rules": 44,
            "fixtures": count,
            "sid_coverage": sorted(coverage),
            "sid_coverage_count": len(coverage),
            "sid_coverage_expected": sorted(VALID_SIDS),
            "positive_cases": sum(bool(v[2]) for v in CASES.values()),
            "negative_cases": sum(not v[2] for v in CASES.values()),
            "observed": observed,
            "errors": errors,
        }
        if args.output_json:
            Path(args.output_json).write_text(json.dumps(report, indent=2) + "\n")
        print("PCAP_TEST_REPORT", json.dumps(report, sort_keys=True))
        assert all_pos == VALID_SIDS, "Fixture matrix fails to include all 44 SIDs"
        assert len(coverage) == 44 and not errors, ("PCAP_FAILED:\n" + "\n".join(errors))
        print(f"ENGINE_PASS 383-rule -T; {count}/{count} PCAP fixtures; 44/44 SID detection; benign controls passed")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Offline-only Suricata regression gate for two unverified v1.0 SIDs.

This tool does not send traffic, modify the release file or reload a sensor.
It creates two test-only signature edits in a temporary directory, then
replays inert PCAPs using a separately executed Suricata process.
"""
import argparse
import collections
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
REPO = THIS_DIR.parent.parent
RULES = REPO / "downloads/local-web-attack-ai-v1.0-333.rules"
EXPECTED_RULE_SHA = "5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96"
EXPECTED = {
    "nextjs-positive.pcap": (1, 0),
    "nextjs-origin-form.pcap": (0, 0),
    "nextjs-no-upgrade.pcap": (0, 0),
    "nextjs-no-key.pcap": (0, 0),
    "php-empty99.pcap": (0, 0),
    "php-empty100.pcap": (0, 1),
    "php-empty105.pcap": (0, 1),
    "php-nonempty105.pcap": (0, 0),
    "php-wrongtype105.pcap": (0, 0),
}
SIDS = (9005017, 9005055)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_and_build() -> tuple[str, dict]:
    original = RULES.read_bytes()
    if sha(original) != EXPECTED_RULE_SHA:
        raise ValueError("Published v1.0 rule asset hash differs from test baseline")
    manifest = json.loads((THIS_DIR / "manifest.json").read_text())
    if set(manifest) != set(EXPECTED):
        raise ValueError("Fixture names and manifest do not match the test contract")
    for name in EXPECTED:
        pcap = (THIS_DIR / name).read_bytes()
        if sha(pcap) != manifest[name]["sha256"]:
            raise ValueError("Fixture integrity failed: " + name)
        if len(pcap) != manifest[name]["bytes"]:
            raise ValueError("Fixture size mismatch: " + name)
    original_lines = original.decode("utf-8").splitlines()
    candidate = []
    modified = []
    for line in original_lines:
        new = line
        if line.startswith("alert ") and re.search(r"\bsid:9005017;", line):
            if line.count("http.uri;") != 1:
                raise ValueError("Unexpected 9005017 original syntax")
            new = line.replace("http.uri;", "http.uri.raw;", 1)
            modified.append(9005017)
        if line.startswith("alert ") and re.search(r"\bsid:9005055;", line):
            if line.count(".{0,4096}){100,}") != 1:
                raise ValueError("Unexpected 9005055 original syntax")
            new = line.replace(".{0,4096}){100,}", ".{0,128}){100,}", 1)
            modified.append(9005055)
        candidate.append(new)
    if sorted(modified) != list(SIDS):
        raise ValueError("Did not modify exactly the intended two SIDs")
    original_signatures = [x for x in original_lines if x.startswith("alert ")]
    next_signatures = [x for x in candidate if x.startswith("alert ")]
    if len(original_signatures) != 333 or len(next_signatures) != 333:
        raise ValueError("Signature count mismatch")
    if sum(a != b for a, b in zip(original_signatures, next_signatures)) != 2:
        raise ValueError("Unexpected detection rule changes")
    sid_set = {int(re.search(r"\bsid:(\d+);", x).group(1)) for x in next_signatures}
    if len(sid_set) != 333:
        raise ValueError("Duplicate or missing SIDs")
    candidate_text = "\n".join(candidate) + "\n"
    return candidate_text, {"baseline_sha256": sha(original),
                            "candidate_sha256": sha(candidate_text.encode()),
                            "signature_count": len(sid_set), "changed_sids": modified,
                            "fixture_count": len(EXPECTED)}


def engine_run(command: list[str], seconds: int) -> float:
    start = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=seconds)
    elapsed = round(time.monotonic() - start, 3)
    if result.returncode != 0:
        raise RuntimeError("Suricata command failed: " + result.stderr[-800:])
    return elapsed


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--run", action="store_true", help="Run offline PCAP tests with Suricata")
    cli.add_argument("--suricata", default="/usr/bin/suricata")
    cli.add_argument("--config", help="Path to Suricata config; required for --run")
    cli.add_argument("--report", help="Write report JSON")
    args = cli.parse_args()
    candidate, report = validate_and_build()
    report["mode"] = "static-integrity-only"
    if args.run:
        if not args.config:
            cli.error("--config required when --run is set")
        if not Path(args.suricata).is_file() or not Path(args.config).is_file():
            cli.error("Suricata binary or config does not exist")
        with tempfile.TemporaryDirectory(prefix="suricata-two-sids-") as tmp:
            tmpdir = Path(tmp)
            rulefile = tmpdir / "candidate.rules"
            rulefile.write_text(candidate)
            report["engine_validate_seconds"] = engine_run(
                [args.suricata, "-T", "-c", args.config,
                 "-S", str(rulefile), "--init-errors-fatal"], 8)
            actual = []
            for index, (name, expected) in enumerate(EXPECTED.items()):
                output = tmpdir / ("case-" + str(index))
                output.mkdir()
                elapsed = engine_run(
                    [args.suricata, "-r", str(THIS_DIR / name),
                     "-k", "none", "-c", args.config,
                     "-S", str(rulefile), "-l", str(output),
                     "--init-errors-fatal"], 8)
                alerts = collections.Counter()
                for line in (output / "eve.json").read_text().splitlines():
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts[event["alert"]["signature_id"]] += 1
                observed = tuple(alerts[sid] for sid in SIDS)
                if observed != expected:
                    raise AssertionError(
                        "Alert mismatch %s: %r expected %r" %
                        (name, observed, expected))
                actual.append({"fixture": name, "expected": list(expected),
                               "observed": list(observed), "seconds": elapsed})
            report.update({"mode": "offline-suricata", "cases": actual,
                           "result": "PASS"})
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

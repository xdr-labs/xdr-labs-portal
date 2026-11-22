#!/usr/bin/env python3
"""Read-only upstream drift audit for ThreatDefence agentic attack rules.

Compares immutable upstream baseline with latest main via the GitHub public
compare API. Does NOT auto-publish changed signatures to a Sensor or main.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

UPSTREAM_REPO = "ThreatDefence/agentic-attack-detections"
BASELINE = "be7bd0b1211eefa6ad5c0ba029f995f9c110dc1d"
COMPARE_URL = ("https://api.github.com/repos/" + UPSTREAM_REPO +
               "/compare/" + BASELINE + "...main")

def review(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
        raise ValueError("Unexpected GitHub compare response")
    if payload.get("too_large") or payload.get("total_commits", 0) > 200:
        raise ValueError("Upstream compare too large; manual baseline review required")
    changed = []
    for file in payload["files"]:
        name = file.get("filename", "")
        if (name.startswith("frameworks/") and "/suricata/" in name and
            name.endswith(".rules") and not name.endswith("-ip.rules")) or name == "behaviors/suricata/behaviors.rules":
            changed.append({"path": name, "status": file.get("status", "unknown"),
                            "additions": file.get("additions", 0),
                            "deletions": file.get("deletions", 0)})
    return {
        "as_of_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_sha": BASELINE,
        "current_head": payload.get("commits", [{}])[-1].get("sha", BASELINE) if payload.get("commits") else BASELINE,
        "ahead_by": payload.get("ahead_by", 0),
        "rule_files_changed": changed,
        "needs_rule_review": bool(changed),
        "mode": "READ_ONLY_UPSTREAM_DRIFT",
        "notes": "Review additions, SID drift, detection semantics and licenses; never auto-enable untested signatures",
    }

def download():
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "stellar-agentic-drift/1.0",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    req = Request(COMPARE_URL, headers=headers)
    with urlopen(req, timeout=20) as response:
        body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("Oversized drift response")
    return json.loads(body)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--fixture", type=Path, help="Offline GitHub compare JSON fixture")
    args = p.parse_args()
    result = review(json.loads(args.fixture.read_text()) if args.fixture else download())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("RULE_DRIFT_AUDIT", "REVIEW_REQUIRED" if result["needs_rule_review"] else "NO_RULE_CHANGES",
          "ahead", result["ahead_by"], "files", len(result["rule_files_changed"]))

if __name__ == "__main__":
    main()

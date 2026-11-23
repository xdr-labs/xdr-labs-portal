#!/usr/bin/env python3
"""Read-only audit of legacy XDR URLs and GitHub owner references in local repo checkouts.

This tool never edits source files, DNS, git remotes, or deployment configuration.
Run against a directory containing clones of xdr-labs repositories.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

MARKERS = {
    "legacy_domain": re.compile(r"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*xdr\.ooo\b", re.I),
    "legacy_github_owner": re.compile(r"\b(?:github\.com|raw\.githubusercontent\.com|ghcr\.io)/xdr-labs\b", re.I),
    "legacy_owner_name": re.compile(r"(?<![a-z0-9-])xdr-labs(?![a-z0-9-])", re.I),
}
SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__", ".mypy_cache"}
OPERATIONAL_SUFFIXES = {".sh", ".py", ".ts", ".tsx", ".js", ".cjs", ".mjs", ".json", ".yaml", ".yml", ".toml", ".conf", ".service"}
OPERATIONAL_PREFIXES = ("ops/", "scripts/", "tools/", "src/", "backend/", "runtime/", "dsp/", ".github/")
MAX_FILE_BYTES = 2_000_000

def kind(path: str) -> str:
    if path == "AGENTS.md" or path.startswith(".engineering/"):
        return "governance"
    if path.startswith(OPERATIONAL_PREFIXES) or Path(path).suffix.lower() in OPERATIONAL_SUFFIXES:
        return "operational"
    return "documentation"

def head_sha(repo: Path) -> str | None:
    proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else None

def scan_repo(repo: Path) -> dict:
    matches = []
    skipped_large = 0
    for file in sorted(repo.rglob("*")):
        if not file.is_file():
            continue
        rel = file.relative_to(repo)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        try:
            if file.stat().st_size > MAX_FILE_BYTES:
                skipped_large += 1
                continue
            raw = file.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        path = rel.as_posix()
        for line_number, line in enumerate(content.splitlines(), 1):
            markers = sorted(name for name, pattern in MARKERS.items() if pattern.search(line))
            if markers:
                matches.append({"path": path, "line": line_number, "category": kind(path), "markers": markers})
    counts = {category: sum(m["category"] == category for m in matches)
              for category in ("operational", "documentation", "governance")}
    return {
        "repository": repo.name,
        "head": head_sha(repo),
        "matching_lines": len(matches),
        "counts": counts,
        "files_affected": len({m["path"] for m in matches}),
        "skipped_large_files": skipped_large,
        "matches": matches,
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="directory with one git checkout per repository")
    parser.add_argument("--output", type=Path, help="optional JSON output file; never modifies the source checkouts")
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error("root is not an existing directory")
    repos = sorted(p for p in args.root.iterdir() if p.is_dir() and (p / ".git").exists())
    if not repos:
        parser.error("no git checkouts found under root")
    results = [scan_repo(repo) for repo in repos]
    data = {
        "source": "read-only local checkouts",
        "repository_count": len(results),
        "matching_lines": sum(r["matching_lines"] for r in results),
        "repositories": results,
    }
    body = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(body, encoding="utf-8")
    print(json.dumps({"repository_count": data["repository_count"],
                      "matching_lines": data["matching_lines"],
                      "operational_lines": sum(r["counts"]["operational"] for r in results),
                      "per_repository": {r["repository"]: r["matching_lines"] for r in results}},
                     ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

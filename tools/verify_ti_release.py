#!/usr/bin/env python3
"""Detached Ed25519 signature gate for a staged Stellar TSV snapshot.

The public key lives at the HTTPS origin, the private key MUST remain offline or
in a protected signing service. Stellar TIP validates TLS, not this signature;
a trusted origin must verify before serving the TSV.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

def run(cmd):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError("OpenSSL signature operation failed: " + result.stderr.strip())
    return result

def sign(manifest: Path, private_key: Path, signature: Path):
    if not manifest.is_file():
        raise ValueError("Missing manifest")
    # Key material is never echoed or copied to the repository.
    run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
         "-in", str(manifest), "-out", str(signature)])

def verify(manifest: Path, signature: Path, public_key: Path,
           feed_dir: Path, min_sequence: int, now: datetime, require_approved: bool):
    run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
         "-inkey", str(public_key), "-sigfile", str(signature),
         "-in", str(manifest)])
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if payload.get("schema") != "stellar-osint-stage.v1":
        raise ValueError("Unknown manifest schema")
    if require_approved and payload.get("status") != "APPROVED_FOR_DEPLOYMENT":
        raise ValueError("Staging snapshot not approved for deployment")
    if int(payload["sequence"]) <= min_sequence:
        raise ValueError("Replay or rollback: non-increasing sequence")
    generated = datetime.fromisoformat(payload["generated_at"])
    expires = datetime.fromisoformat(payload["expires_at"])
    if generated.tzinfo is None or expires.tzinfo is None:
        raise ValueError("Timestamps must be timezone-aware")
    if not (generated <= now < expires) or (expires-generated).total_seconds() > 86400:
        raise ValueError("Stale, future-dated or overlong snapshot")
    files = payload.get("files")
    if not isinstance(files, dict) or "agentic-malicious-DRAFT.tsv" not in files:
        raise ValueError("Missing signed TSV inventory")
    for name, expected in files.items():
        if name != Path(name).name or "/" in name or "\\" in name:
            raise ValueError("Unsafe manifest filename")
        content = (feed_dir / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("Modified or missing feed content: " + name)
    lines = (feed_dir / "agentic-malicious-DRAFT.tsv").read_text(encoding="utf-8").splitlines()
    if len(lines) != payload["curated_count"] or not lines:
        raise ValueError("Missing, truncated or inconsistent TI feed")
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] not in {
            "ip", "domain", "url", "md5-hash", "sha1-hash", "sha256-hash"
        } or fields[2] != "ThreatDefence" or not fields[3].isdigit() or not 0 <= int(fields[3]) <= 100:
            raise ValueError("Invalid Stellar 4-column TSV row")
    print("SIGNED_FEED_PASS", len(lines), "indicators; replay and SHA256 verified")

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action", required=True)
    ps = sub.add_parser("sign")
    ps.add_argument("--manifest", required=True, type=Path)
    ps.add_argument("--private-key", required=True, type=Path)
    ps.add_argument("--signature", required=True, type=Path)
    pv = sub.add_parser("verify")
    pv.add_argument("--manifest", required=True, type=Path)
    pv.add_argument("--signature", required=True, type=Path)
    pv.add_argument("--public-key", required=True, type=Path)
    pv.add_argument("--feed-dir", required=True, type=Path)
    pv.add_argument("--min-sequence", type=int, default=0)
    pv.add_argument("--require-approved", action="store_true")
    args = p.parse_args()
    if args.action == "sign":
        sign(args.manifest, args.private_key, args.signature)
    else:
        verify(args.manifest, args.signature, args.public_key,
               args.feed_dir, args.min_sequence, datetime.now(timezone.utc),
               args.require_approved)

if __name__ == "__main__":
    main()

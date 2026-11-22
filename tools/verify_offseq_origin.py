#!/usr/bin/env python3
"""Source verification preflight for STRICT OSINT QA (no publication).

OffSeq's public 7-day CSV and exclusion lists are verified with the publisher's
pinned Minisign public key over SHA256SUMS before generating Stellar TSVs.
CERT Polska and Jacob have HTTPS plus internal schema/recency checks, but no
claimed publisher-origin detached signature.

Install minisign before running. The script never signs or deploys any feed.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, HTTPSHandler, HTTPRedirectHandler, build_opener
import ssl

from strict_recent_osint import FILES, MAX_BYTES, download

PUBKEY = "RWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA"
BASE = "https://raw.githubusercontent.com/offseq/mirage-feed/data/"
SPECIAL = {"SHA256SUMS": 120000, "SHA256SUMS.minisig": 1024}
SOURCE_MAP = {
    "manifest": "feed.json",
    "attackers": "latest/attackers-7d.csv",
    "scanners": "latest/known-scanners-ipv4.txt",
    "anonymizers": "latest/anonymizers-7d.txt",
}
COMMENT = re.compile(
    r"^mirage-feed (\d{4}-\d{2}-\d{2}) generated "
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) build ([0-9a-f]{16})$"
)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise ValueError("Unsigned HTTP redirect denied")

def get_signed_file(name):
    if name not in SPECIAL:
        raise ValueError("Unexpected signed file")
    url = BASE + name
    origin = urlsplit(url)
    assert origin.scheme == "https" and origin.hostname == "raw.githubusercontent.com"
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    with opener.open(Request(url, headers={"User-Agent": "stellar-origin-signature-qa/1.0"}),
                     timeout=20) as response:
        content = response.read(SPECIAL[name] + 1)
    if not content or len(content) > SPECIAL[name]:
        raise ValueError("Empty/oversized signed origin asset")
    return content

def decode_sums(blob: bytes) -> dict[str, str]:
    out = {}
    for line in blob.decode("utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9._/-]+)", line)
        if not match or ".." in match.group(2) or match.group(2).startswith("/"):
            raise ValueError("Malformed or unsafe signed SHA256SUMS entry")
        path = match.group(2)
        if path in out:
            raise ValueError("Duplicate signed sum path")
        out[path] = match.group(1)
    if len(out) < 20:
        raise ValueError("Unexpectedly sparse signed checksums")
    return out

def check_signed_contents(sums_blob, comment, blobs, now):
    match = COMMENT.fullmatch(comment.strip())
    if not match:
        raise ValueError("Invalid signed OffSeq trusted comment")
    date, generated_text, build = match.groups()
    generated = datetime.fromisoformat(generated_text.replace("Z", "+00:00"))
    if not (now - timedelta(hours=36) <= generated <= now + timedelta(minutes=5)):
        raise ValueError("Signed source is stale or from the future")
    manifest = json.loads(blobs["manifest"].decode("utf-8"))
    if (manifest.get("generated") != generated_text or manifest.get("day") != date or
        manifest.get("build") != build):
        raise ValueError("Signed comment does not match feed manifest")
    checksums = decode_sums(sums_blob)
    for key, path in SOURCE_MAP.items():
        if path not in checksums:
            raise ValueError("Missing required path from signed upstream")
        actual = hashlib.sha256(blobs[key]).hexdigest()
        if actual != checksums[path]:
            raise ValueError("OffSeq trusted-signer checksum mismatch: " + path)
    return {"publisher": "OffSeq Mirage", "method": "Minisign Ed25519",
            "trusted_comment": comment.strip(),
            "pinned_public_key": PUBKEY, "generated_at": generated_text,
            "source_sums_sha256": hashlib.sha256(sums_blob).hexdigest(),
            "signed_paths": list(SOURCE_MAP.values())}

def verify_minisign(sums, signature):
    # Minisign validates BOTH message signature and trusted-comment signature.
    with tempfile.TemporaryDirectory(prefix="offseq-minisign-") as temp:
        root = Path(temp)
        (root / "SHA256SUMS").write_bytes(sums)
        (root / "SHA256SUMS.minisig").write_bytes(signature)
        try:
            process = subprocess.run(
                ["minisign", "-VQm", str(root/"SHA256SUMS"),
                 "-x", str(root/"SHA256SUMS.minisig"), "-P", PUBKEY],
                capture_output=True, text=True, timeout=15, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise ValueError("OffSeq publisher signature could not be verified") from error
        return process.stdout.strip()

def fetch_verified_sources(out: Path, now: datetime):
    # Download the complete original bytes once; the offline parser reuses them.
    sources = {name: download(name) for name in FILES}
    sums = get_signed_file("SHA256SUMS")
    sig = get_signed_file("SHA256SUMS.minisig")
    comment = verify_minisign(sums, sig)
    attestation = check_signed_contents(sums, comment, sources, now)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in sources.items():
        (out / (name + ".bin")).write_bytes(content)
    report = {
        "status": "VERIFIED_SOURCE_SNAPSHOT_NOT_PUBLISHED",
        "verified_at": now.isoformat(),
        "offseq": attestation,
        "source_digests": {name: hashlib.sha256(blob).hexdigest()
                          for name, blob in sources.items()},
        "unverified_provider_signatures": ["CERTPolska", "JacobHoneypot"],
    }
    # Preserve the exact upstream-signed evidence for independent release-time
    # verification; a JSON success assertion alone is not a publisher signature.
    (out / "offseq-SHA256SUMS").write_bytes(sums)
    (out / "offseq-SHA256SUMS.minisig").write_bytes(sig)
    (out / "source-verification.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = fetch_verified_sources(args.output, datetime.now(timezone.utc))
    print("SOURCE_MINISIGN_PASS", result["offseq"]["generated_at"],
          "signed files", len(result["offseq"]["signed_paths"]))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Bind an independently verifiable publisher-origin proof to a signed TI release.

OffSeq SHA256SUMS + its genuine Minisign signature are copied into the locally
Ed25519-signed release inventory. A report saying 'verified' is NOT trusted:
the gateway checks the publisher signature again, then compares the signed
upstream checksums to the source hashes in the release manifest.

CERT Polska and Jacobrakai do not publish comparable signatures in this
pipeline: their HTTPS-fetched bytes are bound by the protected *local*
release signer but must NOT be described as upstream cryptographically signed.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from verify_offseq_origin import PUBKEY, COMMENT, SOURCE_MAP, decode_sums, verify_minisign

MEMBERS = {
    "offseq-SHA256SUMS": "offseq-SHA256SUMS",
    "offseq-SHA256SUMS.minisig": "offseq-SHA256SUMS.minisig",
    "origin-verification.json": "source-verification.json",
}
RELEASE_MEMBERS = set(MEMBERS)
MINISIGN_METHOD = "OffSeq-publisher-Minisign-SHA256SUMS-v1"
EXPECTED_OTHER_SOURCES = {"CERTPolska", "JacobHoneypot"}
REQUIRED_INPUTS = {"manifest","attackers","scanners","anonymizers","cert","jacob_json","jacob_csv"}

def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()

def timestamp(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Origin receipt timestamp without timezone")
    return parsed.astimezone(timezone.utc)

def check_origin(sums: bytes, signature: bytes, receipt_bytes: bytes,
                 release: dict, now: datetime, publisher_key: str = PUBKEY):
    """Reverify publisher signature (never only a JSON 'verified' boolean)."""
    if now.tzinfo is None:
        raise ValueError("Clock must be timezone-aware")
    if any(not isinstance(x, (bytes, bytearray)) or not x for x in
           (sums, signature, receipt_bytes)):
        raise ValueError("Missing publisher-origin signed material")
    comment = verify_minisign(sums, signature, public_key=publisher_key)
    match = COMMENT.fullmatch(comment.strip())
    if not match:
        raise ValueError("Invalid upstream publisher signed comment")
    signed_time = timestamp(match.group(2))
    generated = timestamp(release["generated_at"])
    if not (now - timedelta(hours=36) <= signed_time <= generated <= now + timedelta(minutes=5)):
        raise ValueError("OffSeq publisher signature is stale, future-dated, or after generation")
    if signed_time != timestamp(release["offseq"]["source_generated"]):
        raise ValueError("Upstream signed observation time differs from release source")

    receipt = json.loads(receipt_bytes.decode("utf-8"))
    proof = release.get("origin_proof")
    if proof != {
        "method": MINISIGN_METHOD,
        "publisher": "OffSeq Mirage",
        "signature_files": sorted(RELEASE_MEMBERS),
    }:
        raise ValueError("Missing signed release origin-proof contract")
    if receipt.get("status") != "VERIFIED_SOURCE_SNAPSHOT_NOT_PUBLISHED":
        raise ValueError("Origin receipt does not claim an authenticated source snapshot")
    verified = timestamp(receipt["verified_at"])
    if not (signed_time <= verified <= generated <= now + timedelta(minutes=5)):
        raise ValueError("Origin verification occurred outside signed build chronology")
    meta = receipt.get("offseq")
    if (not isinstance(meta, dict) or meta.get("publisher") != "OffSeq Mirage" or
        meta.get("method") != "Minisign Ed25519" or
        meta.get("pinned_public_key") != publisher_key or
        meta.get("trusted_comment") != comment.strip() or
        meta.get("generated_at") != match.group(2) or
        meta.get("source_sums_sha256") != digest(sums) or
        set(meta.get("signed_paths", [])) != set(SOURCE_MAP.values())):
        raise ValueError("Origin receipt and publisher signature disagree")
    if set(receipt.get("unverified_provider_signatures", [])) != EXPECTED_OTHER_SOURCES:
        raise ValueError("Non-signed providers must not be represented as publisher-signed")
    original = receipt.get("source_digests")
    if (not isinstance(original, dict) or set(original) != REQUIRED_INPUTS or
        original != release.get("source_sha256")):
        raise ValueError("Origin receipt source hashes differ from signed release")
    signed = decode_sums(sums)
    for name, path in SOURCE_MAP.items():
        if signed.get(path) != original[name]:
            raise ValueError("OffSeq publisher-signed checksum differs from selected source: " + path)
    return {
        "publisher_signature": "MINISIGN_VALID",
        "publisher": "OffSeq Mirage",
        "generated_at": signed_time.isoformat(),
        "signed_source_files": len(SOURCE_MAP),
        "other_sources": "HTTPS_AND_LOCAL_SIGNER_ONLY",
    }

def attach_origin(source_dir: Path, stage: Path, now: datetime):
    """Bind verified raw publisher proof before downstream local signing.

    This function is an internal QA packaging step, not a release authorization.
    """
    manifest = stage / "strict-manifest.json"
    release = json.loads(manifest.read_text(encoding="utf-8"))
    if release.get("status") != "QA_ONLY_NOT_PUBLISHED":
        raise ValueError("Origin evidence cannot authorize a release")
    original = {
        target: (source_dir / source).read_bytes()
        for target, source in MEMBERS.items()
    }
    release["origin_proof"] = {
        "method": MINISIGN_METHOD,
        "publisher": "OffSeq Mirage",
        "signature_files": sorted(RELEASE_MEMBERS),
    }
    check_origin(original["offseq-SHA256SUMS"],
                 original["offseq-SHA256SUMS.minisig"],
                 original["origin-verification.json"], release, now)
    if set(release["files"]) & RELEASE_MEMBERS:
        raise ValueError("Unexpected existing origin-proof inventory")
    for name, blob in original.items():
        if (stage / name).exists() or (stage / name).is_symlink():
            raise ValueError("Origin proof file already exists")
        (stage / name).write_bytes(blob)
        release["files"][name] = digest(blob)
    manifest.write_text(json.dumps(release, sort_keys=True, indent=2) + "\n",
                        encoding="utf-8")
    return release

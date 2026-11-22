#!/usr/bin/env python3
"""Independent, read-only source→IOC reproducibility audit before TI signing.

A *valid* signed source receipt does not by itself prove that all emitted IOCs
came from those original source bytes. This verifier re-runs the deterministic
selection from the frozen, origin-validated source snapshot and compares each
unsigned customer-facing TSV and evidence CSV byte-for-byte.

The protected release signer must run this on trusted input files before
approving/signing a snapshot. The audit does NOT publish or authorize release.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile

from origin_evidence import check_origin, PUBKEY
from strict_recent_osint import FILES, build, sha
from verify_offseq_origin import check_signed_contents, verify_minisign

DERIVED = {
    "strict-recent-attackers-DRAFT.tsv",
    "strict-recent-phishing-DRAFT.tsv",
    "strict-ip-evidence.csv",
    "strict-domain-evidence.csv",
}
PROOF = {
    "offseq-SHA256SUMS", "offseq-SHA256SUMS.minisig",
    "origin-verification.json",
}

def parse_time(value):
    dt = datetime.fromisoformat(value.replace("Z","+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Release timestamp requires a timezone")
    return dt.astimezone(timezone.utc)

def audit_rebuild(source_dir: Path, stage: Path, now: datetime,
                  publisher_key: str = PUBKEY) -> dict:
    """Reproduce frozen source bytes; never re-fetch moving upstream URLs."""
    if now.tzinfo is None:
        raise ValueError("An aware verification clock is required")
    if source_dir.resolve() == stage.resolve():
        raise ValueError("Trusted input snapshot and customer stage must differ")
    if any((source_dir / (key+".bin")).is_symlink() for key in FILES):
        raise ValueError("Symlinked source snapshot forbidden")
    if any((stage / name).is_symlink() for name in DERIVED | PROOF | {"strict-manifest.json"}):
        raise ValueError("Symlinked staged TI artifact forbidden")
    inputs = {
        key: (source_dir / (key+".bin")).read_bytes() for key in FILES
    }
    stored = json.loads((stage/"strict-manifest.json").read_text(encoding="utf-8"))
    if stored.get("schema") != "stellar-strict-live-stage.v1":
        raise ValueError("Unsupported strict source inventory")
    if stored.get("status") not in ("QA_ONLY_NOT_PUBLISHED", "APPROVED_FOR_DEPLOYMENT"):
        raise ValueError("Invalid staged release status")
    if {key: sha(val) for key,val in inputs.items()} != stored.get("source_sha256"):
        raise ValueError("Frozen source does not match release source hashes")
    expected_files = DERIVED | PROOF
    if set(stored.get("files",{})) != expected_files:
        raise ValueError("Incomplete signed-release proof inventory")
    source_sums = (stage/"offseq-SHA256SUMS").read_bytes()
    source_signature = (stage/"offseq-SHA256SUMS.minisig").read_bytes()
    receipt = (stage/"origin-verification.json").read_bytes()
    check_origin(source_sums, source_signature, receipt, stored, now,
                 publisher_key=publisher_key)
    # Independent second check against the *actual original OffSeq bytes*:
    comment = verify_minisign(source_sums, source_signature, public_key=publisher_key)
    check_signed_contents(source_sums, comment, inputs, now)
    for name in PROOF:
        content=(stage/name).read_bytes()
        if sha(content) != stored["files"][name]:
            raise ValueError("Origin-proof file modified in unsigned release")
    generated = parse_time(stored["generated_at"])
    if not now - generated <= timedelta(hours=24) or generated > now:
        raise ValueError("Unsigned feed not freshly generated")
    with tempfile.TemporaryDirectory(prefix="strict-rebuild-") as tmp:
        rebuilt = build(inputs, Path(tmp), generated)
        if rebuilt["source_sha256"] != stored["source_sha256"]:
            raise ValueError("Rebuild source hash mismatch")
        if rebuilt["feed_counts"] != stored["feed_counts"]:
            raise ValueError("Rebuilt feed count differs")
        for name in DERIVED:
            expected = (Path(tmp)/name).read_bytes()
            current = (stage/name).read_bytes()
            if expected != current or sha(expected) != stored["files"][name]:
                raise ValueError("Staged IOC content not reproducible from original sources: " + name)
    return {
        "schema": "stellar-strict-replay-audit.v1",
        "status": "REPRODUCIBLE_NOT_RELEASED",
        "verified_at": now.isoformat(),
        "release_sequence": stored["sequence"],
        "original_source_sha256": stored["source_sha256"],
        "replayed_derived_sha256": {name: stored["files"][name] for name in sorted(DERIVED)},
        "per_source_types": stored["feed_counts"],
        "publisher_proof": "REVERIFIED_MINISIGN",
        "authorization": "NONE",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--inputs",type=Path,required=True)
    p.add_argument("--stage",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    result=audit_rebuild(args.inputs,args.stage,datetime.now(timezone.utc))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("SOURCE_TO_TIP_REBUILD_PASS",result["release_sequence"],
          len(result["replayed_derived_sha256"]), "files; no publication")

if __name__=="__main__":
    main()

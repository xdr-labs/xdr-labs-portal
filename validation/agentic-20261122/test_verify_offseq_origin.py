"""Offline OffSeq source signer/manifest consistency and tamper-gate tests."""
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from verify_offseq_origin import (check_signed_contents, decode_sums, SOURCE_MAP,
                                  verify_minisign)

NOW = datetime(2026, 11, 22, 6, tzinfo=timezone.utc)
BUILD = "aabbccddeeff0011"
COMMENT = "mirage-feed 2026-11-21 generated 2026-11-22T03:58:04Z build " + BUILD

def fixtures():
    data = {
        "attackers": b"ip,last_seen\n8.8.8.8,2026-11-22T03:00:00Z\n",
        "scanners": b"8.8.4.4\n",
        "anonymizers": b"1.1.1.1\n",
        "manifest": json.dumps({"day": "2026-11-21",
                                "build": BUILD,
                                "generated": "2026-11-22T03:58:04Z"}).encode(),
    }
    hashes = [(hashlib.sha256(data[k]).hexdigest() + "  " + v)
              for k,v in SOURCE_MAP.items()]
    hashes += [(hashlib.sha256(str(i).encode()).hexdigest() + "  " +
                "other/placeholder%d.txt" % i) for i in range(20)]
    return data, ("\n".join(hashes)+"\n").encode()

class UpstreamMinisignChecks(unittest.TestCase):
    def test_checksum_and_timestamp_contract(self):
        blobs, sums = fixtures()
        result = check_signed_contents(sums, COMMENT, blobs, NOW)
        self.assertEqual(len(result["signed_paths"]), 4)
        self.assertEqual(result["generated_at"], "2026-11-22T03:58:04Z")

    def test_digest_mismatch_cannot_pass(self):
        blobs, sums = fixtures()
        blobs["attackers"] += b"altered"
        with self.assertRaisesRegex(ValueError,"checksum mismatch"):
            check_signed_contents(sums, COMMENT, blobs, NOW)

    def test_time_replay_and_forged_comment(self):
        blobs, sums = fixtures()
        with self.assertRaisesRegex(ValueError,"stale"):
            check_signed_contents(sums, COMMENT, blobs, NOW + timedelta(days=3))
        with self.assertRaisesRegex(ValueError,"comment"):
            check_signed_contents(sums, COMMENT.replace("2026-11-21","2026-11-20"), blobs, NOW)
        with self.assertRaisesRegex(ValueError,"does not match"):
            check_signed_contents(sums, COMMENT.replace(BUILD,"0000000000000000"), blobs, NOW)

    def test_unsafe_or_duplicate_signed_path(self):
        blobs, sums = fixtures()
        with self.assertRaisesRegex(ValueError,"unsafe"):
            decode_sums(sums + (b"0"*64) + b"  ../escape\n")
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            decode_sums(sums + sums.splitlines()[0] + b"\n")

    def test_invalid_detached_signature_rejected(self):
        with self.assertRaisesRegex(ValueError,"could not be verified"):
            verify_minisign(b"bad signed content", b"forged signature\n")

if __name__ == "__main__":
    unittest.main(verbosity=2)

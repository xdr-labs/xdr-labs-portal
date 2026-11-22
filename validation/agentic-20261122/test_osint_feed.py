#!/usr/bin/env python3
"""Offline unit and integrity tests for the Stellar agentic TI builder."""
import csv
from datetime import date, datetime, timezone
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from agentic_osint_feed import make_outputs, classify, valid_value, fetch_source
from verify_ti_release import sign, verify

NOW = datetime(2026, 11, 22, 5, 0, tzinfo=timezone.utc)
HEADERS = ["type", "value", "confidence", "context", "actor", "source",
           "source_url", "reported", "review_by", "framework"]

def sources():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=HEADERS)
    writer.writeheader()
    for i in range(101):
        writer.writerow(dict(type="domain", value="malicious%d.example.test" % i, confidence="high",
              context="Synthetic malware C2, test-only", actor="fixture", source="Fixture",
              source_url="https://example.test/report", reported="2026-11-21",
              review_by="", framework="artex"))
    writer.writerow(dict(type="domain", value="api.anthropic.com", confidence="high",
          context="Legitimate LLM API", actor="fixture", source="Fixture",
          source_url="https://example.test/report", reported="2026-11-21",
          review_by="", framework="artex"))
    writer.writerow(dict(type="ipv4", value="92.255.57.0/24", confidence="medium",
          context="CIDR mislabeled as single IPv4", actor="fixture", source="Fixture",
          source_url="https://example.test/report", reported="2026-11-21",
          review_by="", framework="artex"))
    # 100 public-format IP fixtures, never used as attack traffic or served as TI.
    talos = "ARTEX IPs:\n" + "\n".join("1.2.3.%d" % i for i in range(1, 101)) + "\n"
    return output.getvalue().encode(), talos.encode()

class PolicyTests(unittest.TestCase):
    def test_source_validation(self):
        self.assertFalse(valid_value("ipv4", "92.255.57.0/24"))
        self.assertFalse(valid_value("url", "https://ok.test/a\tinjected"))
        self.assertFalse(valid_value("sha256", "012345"))
        self.assertTrue(valid_value("domain", "valid.example.test"))
        with self.assertRaises(ValueError):
            fetch_source("threatdefence", allow_network=False)

    def test_curated_vs_hunt(self):
        td, talos = sources()
        with tempfile.TemporaryDirectory() as d:
            result = make_outputs(td, talos, Path(d), date(2026, 11, 22), NOW)
            self.assertEqual(result["curated_count"], 101)
            self.assertEqual(result["hunt_ipv4_count"], 100)
            tsv = (Path(d) / "agentic-malicious-DRAFT.tsv").read_text()
            self.assertNotIn("api.anthropic.com", tsv)
            self.assertNotIn("92.255.57.0/24", tsv)
            self.assertTrue(all(len(x.split("\t")) == 4 for x in tsv.splitlines()))
            self.assertIn("HUNT_ONLY,false", (Path(d) / "agentic-ip-HUNT-ONLY.csv").read_text())

    def test_stale_source_fails_closed(self):
        td, talos = sources()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "stale"):
                make_outputs(td, talos, Path(d), date(2027, 2, 1),
                             datetime(2027, 2, 1, tzinfo=timezone.utc))

    def test_stale_talos_hunt_removed_even_if_source_fetched(self):
        td, talos = sources()
        td = td.replace(b"2026-11-21", b"2026-12-22")
        with tempfile.TemporaryDirectory() as d:
            result = make_outputs(td, talos, Path(d), date(2026, 12, 23),
                                  datetime(2026, 12, 23, tzinfo=timezone.utc))
            self.assertEqual(result["talos_hunt_status"], "HUNT_EXPIRED_EXCLUDED")
            self.assertEqual(result["hunt_ipv4_count"], 0)

    def test_empty_or_duplicate_feed_rejected(self):
        td, talos = sources()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                make_outputs(b"", talos, Path(d), date(2026, 11, 22), NOW)
            lines = td.splitlines()
            duplicated = b"\n".join(lines + [lines[1]]) + b"\n"
            with self.assertRaises(ValueError):
                make_outputs(duplicated, talos, Path(d), date(2026, 11, 22), NOW)

    def test_ed25519_signature_tamper_replay(self):
        td, talos = sources()
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)
            result = make_outputs(td, talos, dest, date(2026, 11, 22), NOW)
            private = dest / "signing.pem"
            public = dest / "verify.pem"
            signature = dest / "manifest.sig"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                            "-out", str(private)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout",
                            "-out", str(public)], check=True, capture_output=True)
            manifest = dest / "manifest.json"
            sign(manifest, private, signature)
            verify(manifest, signature, public, dest, 0, NOW, False)
            with self.assertRaises(ValueError):
                verify(manifest, signature, public, dest, result["sequence"], NOW, False)
            file = dest / "agentic-malicious-DRAFT.tsv"
            original = file.read_bytes()
            file.write_bytes(original + b"malicious-injection\n")
            with self.assertRaises(ValueError):
                verify(manifest, signature, public, dest, 0, NOW, False)
            file.write_bytes(original)
            with self.assertRaises(ValueError):
                verify(manifest, signature, public, dest, 0,
                       datetime(2026, 11, 24, tzinfo=timezone.utc), False)
            with self.assertRaises(ValueError):
                verify(manifest, signature, public, dest, 0, NOW, True)

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Cheap security acceptance tests; no Suricata or network access required."""
import importlib.util
import unittest
from pathlib import Path

FILE = Path(__file__).with_name("run_offline.py")
SPEC = importlib.util.spec_from_file_location("suricata_qa_runner", FILE)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def witnesses(nextjs_http=(1, 0), nextjs_https=(1, 0), php=(0, 0)):
    return [
        {"fixture": "nextjs-benign-proxy-http.pcap", "observed": list(nextjs_http)},
        {"fixture": "nextjs-benign-proxy-https.pcap", "observed": list(nextjs_https)},
        {"fixture": "php-multiline105.pcap", "observed": list(php)},
    ]


class ReleaseSecurityTests(unittest.TestCase):
    def test_current_risks_explicitly_block_release(self):
        output = runner.assess_security_acceptance(witnesses())
        self.assertEqual(output["status"], "BLOCKED")
        self.assertEqual(output["security_failure_count"], 3)
        self.assertFalse(output["release_ready"])

    def test_hypothetical_safe_results_still_require_review(self):
        output = runner.assess_security_acceptance(
            witnesses(nextjs_http=(0, 0), nextjs_https=(0, 0), php=(0, 1)))
        self.assertEqual(output["status"], "REQUIRES_MANUAL_REVIEW")
        self.assertEqual(output["security_failure_count"], 0)
        self.assertFalse(output["release_ready"])

    def test_missing_risk_fixture_fails_closed(self):
        with self.assertRaises(ValueError):
            runner.assess_security_acceptance(witnesses()[:2])

    def test_duplicate_fixture_fails_closed(self):
        with self.assertRaises(ValueError):
            runner.assess_security_acceptance(witnesses() * 2)

    def test_static_manifest_not_a_release_pass(self):
        candidate, report = runner.validate_and_build()
        self.assertEqual(report["fixture_count"], 24)
        self.assertEqual(report["changed_sids"], [9005017, 9005055])
        self.assertEqual(report["signature_count"], 333)
        self.assertIn("sid:9005055;", candidate)


if __name__ == "__main__":
    unittest.main()

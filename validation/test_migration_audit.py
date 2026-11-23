"""Regression tests for the read-only XDR → ISOC legacy reference audit."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_xdr_isoc_refs import kind, scan_repo  # noqa: E402


class MigrationAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "example"
        (self.repo / ".git").mkdir(parents=True)

    def test_detects_old_domain_and_owner_but_not_new_host(self) -> None:
        (self.repo / "README.md").write_text(
            "https://isoc.ooo\nhttps://app.parser.xdr.ooo/\n"
            "https://github.com/xdr-labs/parser-studio\n", encoding="utf-8"
        )
        result = scan_repo(self.repo)
        self.assertEqual(result["matching_lines"], 2)
        self.assertEqual(result["counts"]["documentation"], 2)
        self.assertTrue(any("legacy_domain" in m["markers"] for m in result["matches"]))
        self.assertTrue(any("legacy_github_owner" in m["markers"] for m in result["matches"]))

    def test_classifies_installer_references_and_ignores_binary(self) -> None:
        (self.repo / "install.sh").write_text(
            "curl -fsSL https://raw.githubusercontent.com/xdr-labs/foo/main/install.sh\n",
            encoding="utf-8",
        )
        (self.repo / "asset.bin").write_bytes(b"\x00https://xdr.ooo\x00")
        result = scan_repo(self.repo)
        self.assertEqual(result["matching_lines"], 1)
        self.assertEqual(result["counts"]["operational"], 1)
        self.assertEqual(result["files_affected"], 1)

    def test_governance_not_misclassified_as_runtime(self) -> None:
        self.assertEqual(kind("AGENTS.md"), "governance")
        self.assertEqual(kind(".engineering/project.yaml"), "governance")
        self.assertEqual(kind("ops/preview-domain/deploy_web.sh.tpl"), "operational")
        self.assertEqual(kind("docs.json"), "operational")

    def test_cli_writes_only_report_outside_source(self) -> None:
        (self.repo / "README.md").write_text("https://xdr.ooo\n", encoding="utf-8")
        report = Path(self.tmp.name) / "report.json"
        before = (self.repo / "README.md").read_bytes()
        p = subprocess.run(
            [sys.executable, str(ROOT / "tools/audit_xdr_isoc_refs.py"),
             "--root", self.tmp.name, "--output", str(report)],
            capture_output=True, text=True, check=False
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(report.read_text())["repository_count"], 1)
        self.assertEqual(json.loads(report.read_text())["matching_lines"], 1)
        self.assertEqual((self.repo / "README.md").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

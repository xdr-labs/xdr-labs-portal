"""CERT Polska legal and bounded recent-domain feed QA: entirely synthetic data."""
import sys
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/"tools"))
from cert_polska_osint import parse_recent, stage

NOW = datetime(2026, 11, 22, 7, tzinfo=timezone.utc)

def fixture(n=101, stale=False, deleted=False):
    date = "2026-10-20T06:00:00Z" if stale else "2026-11-22T06:00:00Z"
    removed = "2026-11-22T06:30:00Z" if deleted else ""
    return ("Lp\tDomena\tDodano\tUsunieto\n" +
            "".join("%d\tphishing-%d.example.test\t%s\t%s\n" % (i, i, date, removed)
                    for i in range(1,n+1))).encode()

class CertPolskaQA(unittest.TestCase):
    def test_valid_recent_and_no_header_in_stellar_tsv(self):
        data = fixture()
        with TemporaryDirectory() as tmp:
            r = stage(data, Path(tmp), NOW)
            self.assertEqual(r["feed_rows"], 101)
            content = (Path(tmp)/"cert-polska-recent-DRAFT.tsv").read_text()
            self.assertEqual(len(content.splitlines()), 101)
            self.assertTrue(content.startswith("domain\t"))
            self.assertIn("\tCERTPolska\t75", content)

    def test_deleted_and_stale_domains_excluded(self):
        for source in (fixture(stale=True), fixture(deleted=True)):
            with self.assertRaisesRegex(ValueError,"No recent domains"):
                parse_recent(source,NOW)

    def test_schema_drift_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"schema changed"):
            parse_recent(b"1\tbad.example.test\n"*101,NOW)
        with self.assertRaisesRegex(ValueError,"ordinal"):
            parse_recent(b"???\tbad.example.test\t2026-11-22T06:00:00Z\t\n"*101,NOW)

    def test_volume_cap_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"5000-item ceiling"):
            parse_recent(fixture(5001),NOW)

if __name__=="__main__":
    unittest.main()

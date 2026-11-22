"""Read-only OEM delta comparison tests with synthetic tenant exports."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"))
from audit_stellar_ti_overlap import assess, key_of

NOW=datetime(2026,11,22,6,tzinfo=timezone.utc)

class OverlapTests(unittest.TestCase):
    def make(self,root,name,content):
        path=root/name
        path.write_text(content,encoding="utf-8")
        return path

    def test_no_oem_export_does_not_claim_uniqueness(self):
        with TemporaryDirectory() as base:
            root=Path(base)
            ip=self.make(root,"ip.tsv","ip\t1.2.3.4\tOffSeqMirage\t95\n")
            domain=self.make(root,"domain.tsv","domain\tmalware.example.test\tCERTPolska\t75\n")
            previous=self.make(root,"prior.tsv","ip\t1.2.3.4\tOffSeqMirage\t95\nip\t4.3.2.1\tOffSeqMirage\t90\n")
            report=assess([ip,domain],[previous],None,None,NOW)
            self.assertEqual(report["current_count"],2)
            self.assertEqual(report["added_since_previous"],1)
            self.assertEqual(report["removed_since_previous"],1)
            self.assertEqual(report["oem_overlap_state"],"UNVERIFIED_NO_CUSTOMER_TENANT_EXPORT")
            self.assertEqual(report["actual_dp_ttl_state"],"NOT_TESTED")

    def test_recent_oem_export_counts_real_overlap(self):
        with TemporaryDirectory() as base:
            root=Path(base)
            ip=self.make(root,"ip.tsv","ip\t1.2.3.4\tOffSeqMirage\t90\n")
            domain=self.make(root,"domain.tsv","domain\tmalware.example.test\tCERTPolska\t75\n")
            oem=self.make(root,"oem.csv","type,value,source\nIPv4,1.2.3.4,Proofpoint\nDomain,different.example.test,ETPro\n")
            r=assess([ip,domain],[],oem,NOW-timedelta(minutes=10),NOW)
            self.assertEqual(r["oem_overlap_state"],"MEASURED_AGAINST_PROVIDED_EXPORT_NOT_PROOF_OF_COMPLETENESS")
            self.assertEqual(r["overlapping_indicators"],1)
            self.assertEqual(r["not_in_export"],1)
            self.assertEqual(r["overlap_percent"],50)

    def test_stale_oem_and_bad_rows_fail_closed(self):
        with TemporaryDirectory() as base:
            root=Path(base)
            ip=self.make(root,"ip.tsv","ip\t1.2.3.4\tOffSeqMirage\t90\n")
            oem=self.make(root,"oem.csv","type,value\nipv4,1.2.3.4\n")
            with self.assertRaisesRegex(ValueError,"within 24h"):
                assess([ip],[],oem,NOW-timedelta(days=2),NOW)
            with self.assertRaisesRegex(ValueError,"within 24h"):
                assess([ip],[],oem,None,NOW)
            bad=self.make(root,"bad.tsv","ip\t8.8.8.8\tOffSeqMirage\n")
            with self.assertRaisesRegex(ValueError,"four columns"):
                assess([bad],[],None,None,NOW)
            with self.assertRaisesRegex(ValueError,"multiple candidate"):
                assess([ip,ip],[],None,None,NOW)

    def test_normalization(self):
        self.assertEqual(key_of("Domain","Phish.Example.Test."),("domain","phish.example.test"))
        self.assertEqual(key_of("ipv4","1.2.3.4"),("ip","1.2.3.4"))
        with self.assertRaises(ValueError):
            key_of("ip","10.0.0.1")
        with self.assertRaises(ValueError):
            key_of("sha256","abc")

if __name__=="__main__":
    unittest.main(verbosity=2)

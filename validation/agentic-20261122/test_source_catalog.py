"""Commercially safe, freshness-first OSINT source registry invariants."""
import json
from pathlib import Path
import unittest
from urllib.parse import urlsplit

CATALOG = Path(__file__).with_name("osint-source-catalog.json")
QA = {"cert-polska","offseq-mirage","jacobrakai"}
BLOCK = {"BUILTIN","LICENSE_REQUIRED","NONCOMMERCIAL","UPSTREAM_RIGHTS",
         "STALE","CUSTOMER_ONLY"}
class RegistryTests(unittest.TestCase):
    def test_registry_schema_unique_sources_and_https(self):
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.assertEqual(catalog["schema"],"stellar-osint-source-catalog.v1")
        self.assertGreaterEqual(len(catalog["entries"]),40)
        names=set()
        for item in catalog["entries"]:
            self.assertEqual(len(item),6)
            name,area,status,url,rights,evidence=item
            self.assertNotIn(name,names)
            names.add(name)
            self.assertTrue(all((name,area,status,url,rights,evidence)))
            self.assertEqual(urlsplit(url).scheme,"https")
        self.assertEqual({r[0] for r in catalog["entries"] if r[2]=="QA"},QA)

    def test_disallowed_and_built_in_sources_never_enabled(self):
        rows=json.loads(CATALOG.read_text())["entries"]
        for id_,area,status,url,rights,evidence in rows:
            if status in BLOCK:
                self.assertNotIn(id_,QA)
                self.assertNotEqual(status,"QA")
        required={"malwarebazaar","threatfox","proofpoint-etpro",
                  "alienvault-otx","urlhaus","openphish","phish-tank",
                  "c2intelfeeds","threatcluster","phishunt"}
        self.assertTrue(required.issubset({r[0] for r in rows}))

if __name__=="__main__":
    unittest.main()

"""Strict short-window live-source TI policy tests (no network or malicious traffic)."""
import csv
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from strict_recent_osint import build, parse_offseq, sha
from verify_ti_release import sign, verify

NOW = datetime(2026,11,22,6,0,tzinfo=timezone.utc)
HEAD = ["ip","asn","as_org","country","first_seen","last_seen","services",
        "tags","cves","kev","attack","sensors","networks","hits","confidence"]

def fixture():
    fp = io.StringIO()
    w = csv.DictWriter(fp, fieldnames=HEAD)
    w.writeheader()
    for n in range(1,121):
        w.writerow({
            "ip": f"1.2.3.{n}", "asn": "1234", "as_org": "Test Lab",
            "country": "US", "first_seen": "2026-11-19T04:00:00Z",
            "last_seen": "2026-11-22T04:00:00Z",
            "services": "http", "tags": "web-scan", "cves": "", "kev": "false",
            "attack": "T1595", "sensors": "3", "networks": "2",
            "hits": "10", "confidence": "90"})
    lines = fp.getvalue().splitlines()
    # Select concrete exploitation with multiple independent sensors and high score.
    lines[4] = lines[4].replace("web-scan", "shell-commands;web-exploit")
    lines[5] = lines[5].replace("web-scan", "db-ransom")
    lines[6] = lines[6].replace("web-scan", "sip-fraud")
    attackers = ("\n".join(lines) + "\n").encode()
    scanners = b"1.2.3.6\n"
    anonymizers = b"1.2.3.5\n"
    entry = lambda name, val: {
        "path": name, "bytes": len(val), "sha256": sha(val),
        "count": 120 if name.endswith(".csv") else len(val.splitlines())
    }
    meta = {
        "generated": "2026-11-22T05:00:00Z",
        "license": {"code": "MIT", "data": "CC-BY-4.0"},
        "files": [
            entry("latest/attackers-7d.csv", attackers),
            entry("latest/known-scanners-ipv4.txt", scanners),
            entry("latest/anonymizers-7d.txt", anonymizers),
        ],
    }
    cert = (
        "Lp\tDomena\tDodano\tUsunieto\n" +
        "".join(f"{i}\tphish-{i}.example.test\t2026-11-22T03:00:00Z\t\n"
                for i in range(1,102))
    ).encode()
    jac = io.StringIO()
    jwriter = csv.writer(jac)
    jwriter.writerow(["ip","tier","bans","attempts","first_seen","last_seen","first_banned","asn"])
    entries = []
    for n in range(1,45):
        ip = f"2.3.4.{n}"
        tier = "credential" if n == 3 else "scanner"
        bans = 5 if n == 3 else 0
        attempts = 400 if n == 3 else 1400
        d = dict(ip=ip,tier=tier,bans=bans,attempts=attempts,
                 first_seen="2026-11-21T02:00:00Z",last_seen="2026-11-22T04:00:00Z",
                 first_banned="",asn="AS100")
        entries.append(d)
        jwriter.writerow(list(d.values()))
    shared = dict(ip="1.2.3.4",tier="credential",bans=10,attempts=200,
                  first_seen="2026-11-20T02:00:00Z",last_seen="2026-11-22T04:00:00Z",
                  first_banned="",asn="AS100")
    entries.append(shared)
    jwriter.writerow(list(shared.values()))
    jmeta={"meta":{"license":"CC0-1.0","update_frequency":"hourly",
                   "updated":"2026-11-22T05:00:00Z","count":len(entries)},
           "ips":entries}
    return {"manifest":json.dumps(meta).encode(), "attackers":attackers,
            "scanners":scanners, "anonymizers":anonymizers, "cert":cert,
            "jacob_json":json.dumps(jmeta).encode(),"jacob_csv":jac.getvalue().encode()}

class StrictLivePolicy(unittest.TestCase):
    def test_two_evidence_driven_feeds(self):
        src=fixture()
        with tempfile.TemporaryDirectory() as path:
            r=build(src,Path(path),NOW)
            self.assertEqual(r["schema"],"stellar-strict-live-stage.v1")
            self.assertEqual(r["feed_counts"]["strict-recent-phishing-DRAFT.tsv"],101)
            # Shared OffSeq+Jacob IP is correlated, and one independent Jacob IP survives.
            self.assertEqual(r["feed_counts"]["strict-recent-attackers-DRAFT.tsv"],2)
            self.assertEqual(r["corroborated_ip_count"],1)
            ip=(Path(path)/"strict-recent-attackers-DRAFT.tsv").read_text()
            self.assertEqual(set(ip.splitlines()),{"ip\t1.2.3.4\tCorroborated\t90",
                                                  "ip\t2.3.4.3\tJacobHoneypot\t83"})
            domains=(Path(path)/"strict-recent-phishing-DRAFT.tsv").read_text()
            self.assertEqual(len(domains.splitlines()),101)
            self.assertTrue(all(x.count("\t")==3 for x in domains.splitlines()))
            self.assertNotIn("ThreatDefence",ip+domains)
            self.assertNotIn("CiscoTalos",ip+domains)

    def test_offseq_source_signature_and_freshness(self):
        src=fixture()
        with self.assertRaisesRegex(ValueError,"SHA256"):
            modified=dict(src)
            modified["attackers"]=src["attackers"]+b"unexpected-data\n"
            parse_offseq(modified,NOW)
        with self.assertRaisesRegex(ValueError,"license"):
            modified=dict(src)
            meta=json.loads(src["manifest"])
            meta["license"]["data"]="proprietary"
            modified["manifest"]=json.dumps(meta).encode()
            parse_offseq(modified,NOW)
        with self.assertRaisesRegex(ValueError,"stale"):
            parse_offseq(src,NOW+timedelta(days=4))

    def test_recent_observations_and_tag_gate(self):
        src=fixture()
        older=dict(src)
        old=src["attackers"].replace(
            b"2026-11-22T04:00:00Z",b"2026-11-20T04:00:00Z")
        older["attackers"]=old
        meta=json.loads(src["manifest"])
        meta["files"][0]["sha256"]=sha(old)
        meta["files"][0]["bytes"]=len(old)
        older["manifest"]=json.dumps(meta).encode()
        with self.assertRaisesRegex(ValueError,"volume"):
            parse_offseq(older,NOW)

    def test_signed_strict_feeds_and_tamper_replay(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            result = build(fixture(), root, NOW)
            priv, pub, sig = root/"private.pem", root/"public.pem", root/"strict.sig"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                            "-out", str(priv)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout",
                            "-out", str(pub)], check=True, capture_output=True)
            manifest = root/"strict-manifest.json"
            sign(manifest, priv, sig)
            verify(manifest, sig, pub, root, 0, NOW, False)
            with self.assertRaisesRegex(ValueError, "Replay"):
                verify(manifest, sig, pub, root, result["sequence"], NOW, False)
            with self.assertRaisesRegex(ValueError, "not approved"):
                verify(manifest, sig, pub, root, 0, NOW, True)
            ipfile = root/"strict-recent-attackers-DRAFT.tsv"
            ipfile.write_bytes(ipfile.read_bytes()+b"ip\t1.2.3.9\tOffSeqMirage\t95\n")
            with self.assertRaisesRegex(ValueError, "Modified"):
                verify(manifest, sig, pub, root, 0, NOW, False)

    def test_removed_cert_domains_do_not_enter_stellar(self):
        src=fixture()
        src["cert"]=src["cert"].replace(b"2026-11-22T03:00:00Z\t\n",
                                        b"2026-11-22T03:00:00Z\t2026-11-22T04:00:00Z\n")
        with tempfile.TemporaryDirectory() as path:
            with self.assertRaisesRegex(ValueError,"No recent domains"):
                build(src,Path(path),NOW)

if __name__ == "__main__":
    unittest.main(verbosity=2)

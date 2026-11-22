"""Offline atomic signed TIP gateway tests: no network, no real tenant, no server."""
import hashlib
import json
from datetime import timedelta
from pathlib import Path
import subprocess
import tempfile
import unittest
import threading
from urllib.request import urlopen
from urllib.error import HTTPError

from test_strict_recent_osint import fixture, NOW
from strict_recent_osint import build
from verify_ti_release import sign
from strict_ti_gateway import promote, current_file, serve_local

class SignedGatewayTests(unittest.TestCase):
    def keys(self, root):
        priv, pub = root/"private.pem", root/"public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ed25519","-out",str(priv)],
                       capture_output=True,check=True)
        subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)],
                       capture_output=True,check=True)
        return priv, pub

    def stage(self, root, key, now=NOW):
        root.mkdir()
        result=build(fixture(),root,now)
        path=root/"strict-manifest.json"
        data=json.loads(path.read_text())
        data["status"]="APPROVED_FOR_DEPLOYMENT"  # simulated authorization, local test only
        path.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")
        sign(path,key,root/"strict-manifest.sig")
        return result

    def test_atomic_promotion_requires_approval_and_blocks_replay(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)
            priv,pub=self.keys(root)
            stage=root/"stage1"
            self.stage(stage,priv)
            origin=root/"origin"
            dry=promote(stage,origin,pub,NOW,False)
            self.assertEqual(dry["result"],"DRY_RUN_VALID")
            self.assertFalse(origin.exists())
            applied=promote(stage,origin,pub,NOW,True)
            self.assertEqual(applied["result"],"TEMPORARY_RELEASE_PROMOTED")
            self.assertTrue((origin/"current").is_symlink())
            self.assertTrue(current_file(origin,pub,"/feeds/recent-attackers.tsv",NOW).is_file())
            self.assertIn(b"Corroborated",current_file(origin,pub,
                "/feeds/recent-attackers.tsv",NOW).read_bytes())
            self.assertEqual(applied["sequence"],json.loads((origin/"state.json").read_text())["last_sequence"])
            with self.assertRaisesRegex(ValueError,"Replay"):
                promote(stage,origin,pub,NOW,True)
            with self.assertRaises(ValueError):
                current_file(origin,pub,"/etc/passwd",NOW)
            with self.assertRaises(ValueError):
                current_file(origin,pub,"/feeds/recent-attackers.tsv",NOW+timedelta(days=2))

    def test_loopback_http_serves_only_fresh_signed_snapshot(self):
        """Localhost HTTP simulation only: TLS and authentication belong to test Nginx."""
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            priv, pub = self.keys(root)
            stage = root/"stage"
            self.stage(stage, priv)
            origin = root/"origin"
            promoted = promote(stage, origin, pub, NOW, True)
            server = serve_local(origin, pub, 0, clock=lambda: NOW, run_forever=False)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"http://127.0.0.1:{server.server_address[1]}/feeds/recent-phishing.tsv"
            try:
                with urlopen(url, timeout=4) as response:
                    body = response.read()
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"phish-1.example.test", body)
                    self.assertEqual(response.headers.get("Cache-Control"), "no-store, max-age=0")
                state = origin/"state.json"
                metadata = json.loads(state.read_text())
                metadata["last_sequence"] = int(promoted["sequence"]) + 1
                state.write_text(json.dumps(metadata))
                with self.assertRaises(HTTPError) as error:
                    urlopen(url, timeout=4)
                self.assertEqual(error.exception.code, 503)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_invalid_signature_tamper_and_unapproved_are_rejected(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)
            priv,pub=self.keys(root)
            stage=root/"stage"
            self.stage(stage,priv)
            target=stage/"strict-recent-phishing-DRAFT.tsv"
            target.write_bytes(target.read_bytes()+b"domain\tmalicious.example.test\tCERTPolska\t100\n")
            with self.assertRaises(ValueError):
                promote(stage,root/"origin",pub,NOW,False)
            self.assertFalse((root/"origin").exists())
            # Restore signed bytes and then attempt to promote an unapproved snapshot
            target=stage/"strict-recent-phishing-DRAFT.tsv"
            stage2=root/"stage2"
            self.stage(stage2,priv)
            manifest=stage2/"strict-manifest.json"
            doc=json.loads(manifest.read_text())
            doc["status"]="QA_ONLY_NOT_PUBLISHED"
            manifest.write_text(json.dumps(doc,sort_keys=True,indent=2)+"\n")
            sign(manifest,priv,stage2/"strict-manifest.sig")
            with self.assertRaisesRegex(ValueError,"not approved"):
                promote(stage2,root/"origin",pub,NOW,False)

    def test_signed_but_stale_ioc_evidence_is_not_enough(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)
            priv,pub=self.keys(root)
            stage=root/"stage"
            self.stage(stage,priv)
            evidence=stage/"strict-domain-evidence.csv"
            data=evidence.read_text().replace("2026-11-22T03:00:00", "2026-11-12T03:00:00")
            evidence.write_text(data)
            manifest=stage/"strict-manifest.json"
            m=json.loads(manifest.read_text())
            m["files"]["strict-domain-evidence.csv"]=hashlib.sha256(evidence.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(m,indent=2,sort_keys=True)+"\n")
            sign(manifest,priv,stage/"strict-manifest.sig")
            with self.assertRaisesRegex(ValueError,"outside 24h"):
                promote(stage,root/"origin",pub,NOW,False)

    def test_source_evidence_remains_one_to_one_with_ioc(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)
            priv,pub=self.keys(root)
            stage=root/"stage"
            self.stage(stage,priv)
            evidence=stage/"strict-ip-evidence.csv"
            # Signed metadata does NOT by itself prove record-level sensor evidence.
            txt=evidence.read_text()
            txt=txt.replace(",90,90,3,2,",",90,90,0,0,")
            evidence.write_text(txt)
            manifest=stage/"strict-manifest.json"
            m=json.loads(manifest.read_text())
            m["files"]["strict-ip-evidence.csv"]=hashlib.sha256(evidence.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(m,sort_keys=True,indent=2)+"\n")
            sign(manifest,priv,stage/"strict-manifest.sig")
            with self.assertRaisesRegex(ValueError,"Insufficient independent"):
                promote(stage,root/"origin",pub,NOW,False)

if __name__=="__main__":
    unittest.main(verbosity=2)

"""Offline atomic signed TIP gateway tests: no network, no real tenant, no server."""
import hashlib
import json
from datetime import timedelta
from pathlib import Path
import subprocess
import tempfile
import unittest
import threading
from unittest.mock import patch
from urllib.request import urlopen
from urllib.error import HTTPError

from test_strict_recent_osint import fixture, NOW
from strict_recent_osint import build
from origin_evidence import attach_origin
from verify_offseq_origin import SOURCE_MAP
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
        """Build a real Minisign-backed *synthetic* upstream + local release."""
        root.mkdir()
        sources=fixture()
        result=build(sources,root,now)
        upstream = root.parent / (root.name + "-upstream")
        upstream.mkdir()
        for source_name, original_blob in sources.items():
            (upstream/(source_name+".bin")).write_bytes(original_blob)
        publisher_pub=upstream/"publisher.pub"
        publisher_priv=upstream/"publisher.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(publisher_pub),
                        "-s", str(publisher_priv)], capture_output=True, check=True)
        test_key=publisher_pub.read_text().splitlines()[-1].strip()
        # A test private key can never substitute for the hardcoded production
        # publisher key: override is scoped to this unit-test process only.
        fixture_patch=patch("strict_ti_gateway.UPSTREAM_PUBKEY", test_key)
        fixture_patch.start()
        self.addCleanup(fixture_patch.stop)
        signed_lines=[
            hashlib.sha256(sources[k]).hexdigest()+"  "+p
            for k,p in SOURCE_MAP.items()
        ]
        signed_lines.extend(
            hashlib.sha256(str(n).encode()).hexdigest()+
            "  placeholder/inert-%02d.txt" % n for n in range(20))
        sums=("\n".join(signed_lines)+"\n").encode()
        sums_path=upstream/"SHA256SUMS"
        sums_path.write_bytes(sums)
        signature_path=upstream/"SHA256SUMS.minisig"
        comment=("mirage-feed 2026-11-21 generated "
                 "2026-11-22T05:00:00Z build aabbccddeeff0011")
        subprocess.run([
            "minisign", "-S", "-m", str(sums_path), "-s", str(publisher_priv),
            "-x", str(signature_path), "-t", comment
        ], capture_output=True, check=True)
        receipt={
            "status":"VERIFIED_SOURCE_SNAPSHOT_NOT_PUBLISHED",
            "verified_at":now.isoformat(),
            "offseq":{
                "publisher":"OffSeq Mirage", "method":"Minisign Ed25519",
                "trusted_comment":comment,
                "pinned_public_key":test_key,
                "generated_at":"2026-11-22T05:00:00Z",
                "source_sums_sha256":hashlib.sha256(sums).hexdigest(),
                "signed_paths":list(SOURCE_MAP.values())
            },
            "source_digests":{k:hashlib.sha256(v).hexdigest()
                              for k,v in sources.items()},
            "unverified_provider_signatures":["CERTPolska","JacobHoneypot"],
        }
        (upstream/"source-verification.json").write_text(
            json.dumps(receipt,sort_keys=True,indent=2)+"\n")
        (upstream/"offseq-SHA256SUMS").write_bytes(sums)
        (upstream/"offseq-SHA256SUMS.minisig").write_bytes(
            signature_path.read_bytes())
        attach_origin(upstream,root,now,publisher_key=test_key)
        path=root/"strict-manifest.json"
        data=json.loads(path.read_text())
        data["status"]="APPROVED_FOR_DEPLOYMENT"  # isolated-test authorization only
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

    def test_signed_release_is_bound_to_real_upstream_minisign_and_receipt(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)
            priv,pub=self.keys(root)
            stage=root/"stage"
            self.stage(stage,priv)
            origin=root/"origin"
            self.assertEqual(promote(stage,origin,pub,NOW,False)["result"],
                             "DRY_RUN_VALID")
            # A re-signed malicious replacement of the *publisher* signature
            # must still be rejected, even though local manifest checks pass.
            sig=stage/"offseq-SHA256SUMS.minisig"
            sig.write_bytes(sig.read_bytes()+b"garbled")
            manifest=stage/"strict-manifest.json"
            m=json.loads(manifest.read_text())
            m["files"][sig.name]=hashlib.sha256(sig.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(m,sort_keys=True,indent=2)+"\n")
            sign(manifest,priv,stage/"strict-manifest.sig")
            with self.assertRaisesRegex(ValueError,"publisher signature"):
                promote(stage,origin,pub,NOW,False)
            self.assertFalse(origin.exists())

    def test_forged_receipt_rejected_even_when_locally_resigned(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)
            priv,pub=self.keys(root)
            stage=root/"stage"
            self.stage(stage,priv)
            receipt=stage/"origin-verification.json"
            data=json.loads(receipt.read_text())
            data["offseq"]["trusted_comment"]="forged-upstream-verification"
            receipt.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")
            manifest=stage/"strict-manifest.json"
            m=json.loads(manifest.read_text())
            m["files"][receipt.name]=hashlib.sha256(receipt.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(m,sort_keys=True,indent=2)+"\n")
            sign(manifest,priv,stage/"strict-manifest.sig")
            with self.assertRaisesRegex(ValueError,"receipt and publisher signature"):
                promote(stage,root/"origin",pub,NOW,False)

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

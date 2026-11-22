"""E2E for one public mixed-type Stellar Custom TI URL.

All network traffic is localhost-only with synthetic IOCs and ephemeral signing keys.
"""
from contextlib import contextmanager
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen, Request

from test_strict_recent_osint import NOW
from test_strict_ti_gateway import SignedGatewayTests
from strict_ti_gateway import promote, current_unified_tsv
from ti_public_service import FEED_PATH, serve


@contextmanager
def running_service(clock=NOW):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        fixture_owner = SignedGatewayTests("test_atomic_promotion_requires_approval_and_blocks_replay")
        private, public = fixture_owner.keys(root)
        server = None
        worker = None
        try:
            stage = root/"stage"
            fixture_owner.stage(stage, private)
            origin = root/"origin"
            promote(stage, origin, public, NOW, True)
            server = serve(origin, public, port=0, clock=lambda:clock, run_forever=False)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            address = "http://127.0.0.1:"+str(server.server_address[1])
            yield address, root, public
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if worker is not None:
                worker.join(timeout=3)
            fixture_owner.doCleanups()


def get(base, path, method="GET"):
    try:
        with urlopen(Request(base+path,method=method),timeout=5) as result:
            return result.status,result.read(),dict(result.headers)
    except HTTPError as error:
        return error.code,error.read(),dict(error.headers)


class PublicUnifiedFeedTests(unittest.TestCase):
    def test_single_url_contains_all_signed_ioc_types_no_auth(self):
        with running_service() as (base,root,pub):
            status,content,headers = get(base,FEED_PATH)
            self.assertEqual(status,200)
            self.assertEqual(headers["Content-Type"],"text/tab-separated-values; charset=utf-8")
            self.assertEqual(content,current_unified_tsv(root/"origin",pub,NOW))
            self.assertEqual(headers["Cache-Control"],"no-store, max-age=0")
            lines = [line.split("\t") for line in content.decode().splitlines()]
            self.assertEqual(len(lines),103)
            self.assertEqual({line[0] for line in lines},{"ip","domain"})
            self.assertEqual(sum(line[0]=="ip" for line in lines),2)
            self.assertEqual(sum(line[0]=="domain" for line in lines),101)
            self.assertTrue(all(len(line)==4 and line[3].isdigit() for line in lines))

    def test_old_category_and_customer_routes_are_absent(self):
        with running_service() as (base,root,pub):
            for route in (
                "/v1/tenants/corp-alpha/feeds/stellar-ti.tsv",
                "/v1/tenants/corp-alpha/feeds/attackers.tsv",
                "/v1/tenants/corp-alpha/feeds/phishing.tsv",
                "/feeds/recent-attackers.tsv",
                "/feeds/recent-phishing.tsv",
                "/admin", "/",
            ):
                self.assertEqual(get(base,route)[0],404)
            for method in ("POST","PUT","DELETE","HEAD"):
                self.assertEqual(get(base,FEED_PATH,method=method)[0],405)

    def test_stale_or_rollback_release_fails_closed(self):
        with running_service() as (base,root,pub):
            self.assertEqual(get(base,FEED_PATH)[0],200)
            state=root/"origin"/"state.json"
            data=json.loads(state.read_text())
            data["last_sequence"]+=1
            state.write_text(json.dumps(data))
            self.assertEqual(get(base,FEED_PATH)[0],503)
            self.assertEqual(get(base,"/internal/healthz")[0],503)

        with running_service(NOW+timedelta(days=2)) as (base,root,pub):
            self.assertEqual(get(base,FEED_PATH)[0],503)

    def test_checksum_tamper_rejected_and_no_source_leak(self):
        with running_service() as (base,root,pub):
            self.assertEqual(get(base,"/internal/healthz")[0],200)
            self.assertEqual(get(base,"/internal/metrics")[0],404)
            release=root/"origin"/"current"
            file=(root/"origin"/release.readlink()/"strict-recent-phishing-DRAFT.tsv")
            file.chmod(0o600)
            file.write_bytes(file.read_bytes()+b"domain\tforged.example.test\tCERTPolska\t99\n")
            self.assertEqual(get(base,FEED_PATH)[0],503)
            self.assertEqual(get(base,"/internal/healthz")[0],503)

    def test_invalid_release_at_start_is_not_started_externally(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with self.assertRaisesRegex(ValueError,"absolute"):
                serve(Path("relative"),root/"public.pem",port=0,run_forever=False)
            with self.assertRaisesRegex(ValueError,"Invalid loopback"):
                serve(root,root/"public.pem",port=80,run_forever=False)


if __name__=="__main__":
    unittest.main(verbosity=2)

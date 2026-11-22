"""Isolated HTTP E2E: exactly one tenant-bound Stellar feed for every IOC type.

Loopback-only, synthetic IOCs and ephemeral publisher/release signing keys.
No production credentials, actual Stellar tenants, or internet requests.
"""
from contextlib import contextmanager
import base64
from datetime import timedelta
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from test_strict_recent_osint import NOW
from test_strict_ti_gateway import SignedGatewayTests
from strict_ti_gateway import promote, current_unified_tsv
from ti_customer_service import (make_password_hash, registry, serve, basic_auth,
                                 verify_secret)

PASSWORD_A = "synthetic-long-only-for-testing-AAAAA"
PASSWORD_B = "synthetic-long-only-for-testing-BBBBB"


def tenant_config(a_enabled=True, a_feeds=None, a_secret=PASSWORD_A):
    return {
        "schema": "stellar-ti-tenants.v1",
        "tenants": [
            {
                "id": "corp-alpha", "username": "corp-alpha-bot",
                "password_hash": make_password_hash(a_secret, b"\x01" * 16),
                "enabled": a_enabled,
                "feeds": ["unified"] if a_feeds is None else a_feeds,
            },
            {
                "id": "corp-beta", "username": "corp-beta-bot",
                "password_hash": make_password_hash(PASSWORD_B, b"\x02" * 16),
                "enabled": True, "feeds": ["unified"],
            },
        ],
    }


def set_config(path, content):
    target=path.with_suffix(".new")
    target.write_text(json.dumps(content,sort_keys=True)+"\n",encoding="utf-8")
    os.chmod(target,0o600)
    os.replace(target,path)


def basic(user, password):
    token=base64.b64encode((user+":"+password).encode()).decode()
    return {"Authorization": "Basic "+token}


@contextmanager
def running_service(at=NOW):
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        test_owner=SignedGatewayTests("test_atomic_promotion_requires_approval_and_blocks_replay")
        priv,pub=test_owner.keys(root)
        server=None
        thread=None
        try:
            stage=root/"stage"
            test_owner.stage(stage,priv)
            origin=root/"origin"
            promote(stage,origin,pub,NOW,True)
            credentials=root/"customers.json"
            set_config(credentials,tenant_config())
            server=serve(origin,pub,credentials,port=0,clock=lambda:at,run_forever=False)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            yield "http://127.0.0.1:"+str(server.server_address[1]),root,credentials,pub
        finally:
            if server:
                server.shutdown()
                server.server_close()
            if thread:
                thread.join(timeout=3)
            test_owner.doCleanups()


def fetch(base,path,auth=None):
    try:
        request=Request(base+path,headers=auth or {})
        with urlopen(request,timeout=5) as response:
            return response.status,response.read(),dict(response.headers)
    except HTTPError as error:
        return error.code,error.read(),dict(error.headers)


class SingleFeedServiceTests(unittest.TestCase):
    def test_one_credentialed_feed_contains_ip_and_phishing_domain(self):
        with running_service() as (base,root,config,pub):
            uri="/v1/tenants/corp-alpha/feeds/stellar-ti.tsv"
            status,body,headers=fetch(base,uri,basic("corp-alpha-bot",PASSWORD_A))
            self.assertEqual(status,200)
            self.assertEqual(headers["Content-Type"],"text/tab-separated-values; charset=utf-8")
            self.assertEqual(headers["Cache-Control"],"no-store, max-age=0")
            self.assertEqual(body,current_unified_tsv(root/"origin",pub,NOW))
            rows=[line.split("\t") for line in body.decode().splitlines()]
            self.assertTrue(all(len(row)==4 and row[3].isdigit() for row in rows))
            self.assertEqual({row[0] for row in rows},{"ip","domain"})
            self.assertEqual(len(rows),103)
            self.assertEqual(sum(row[0]=="ip" for row in rows),2)
            self.assertEqual(sum(row[0]=="domain" for row in rows),101)
            # Former category URLs are deliberately not public endpoints.
            for path in ("/v1/tenants/corp-alpha/feeds/attackers.tsv",
                         "/v1/tenants/corp-alpha/feeds/phishing.tsv",
                         "/feeds/recent-attackers.tsv",
                         "/feeds/recent-phishing.tsv"):
                self.assertEqual(fetch(base,path,basic("corp-alpha-bot",PASSWORD_A))[0],404)

    def test_unified_feed_auth_per_customer_no_cross_tenant_credentials(self):
        with running_service() as (base,root,config,pub):
            a="/v1/tenants/corp-alpha/feeds/stellar-ti.tsv"
            b="/v1/tenants/corp-beta/feeds/stellar-ti.tsv"
            self.assertEqual(fetch(base,a)[0],401)
            self.assertEqual(fetch(base,a,basic("corp-alpha-bot","invalid-password"))[0],401)
            self.assertEqual(fetch(base,a,basic("corp-beta-bot",PASSWORD_B))[0],401)
            self.assertEqual(fetch(base,b,basic("corp-alpha-bot",PASSWORD_A))[0],401)
            self.assertEqual(fetch(base,b,basic("corp-beta-bot",PASSWORD_B))[0],200)
            self.assertEqual(fetch(base,a,basic("corp-alpha-bot",PASSWORD_A))[0],200)
            self.assertEqual(fetch(base,"/v1/tenants/corp-gamma/feeds/stellar-ti.tsv",
                                   basic("corp-alpha-bot",PASSWORD_A))[0],401)
            self.assertEqual(fetch(base,a,{"Authorization":"Basic !!!!"})[0],401)
            self.assertEqual(fetch(base,a,{"Authorization":"Bearer unknown"})[0],401)

    def test_registry_hot_rotation_revoke_and_fail_closed(self):
        with running_service() as (base,root,config,pub):
            a="/v1/tenants/corp-alpha/feeds/stellar-ti.tsv"
            auth=basic("corp-alpha-bot",PASSWORD_A)
            self.assertEqual(fetch(base,a,auth)[0],200)
            set_config(config,tenant_config(a_secret="synthetic-rotated-password-AAAAA"))
            self.assertEqual(fetch(base,a,auth)[0],401)
            new_auth=basic("corp-alpha-bot","synthetic-rotated-password-AAAAA")
            self.assertEqual(fetch(base,a,new_auth)[0],200)
            set_config(config,tenant_config(a_enabled=False,
                                            a_secret="synthetic-rotated-password-AAAAA"))
            self.assertEqual(fetch(base,a,new_auth)[0],401)
            set_config(config,tenant_config(a_feeds=["bogus"]))
            self.assertEqual(fetch(base,a,auth)[0],503)
            self.assertEqual(fetch(base,"/internal/healthz")[0],503)

    def test_loopback_signed_origin_fail_closed_and_health(self):
        with running_service() as (base,root,config,pub):
            path="/v1/tenants/corp-alpha/feeds/stellar-ti.tsv"
            auth=basic("corp-alpha-bot",PASSWORD_A)
            self.assertEqual(fetch(base,"/internal/healthz")[0],200)
            self.assertEqual(fetch(base,path,auth)[0],200)
            self.assertEqual(fetch(base,"/internal/metrics")[0],200)
            state=root/"origin"/"state.json"
            payload=json.loads(state.read_text())
            payload["last_sequence"]+=1
            state.write_text(json.dumps(payload))
            self.assertEqual(fetch(base,path,auth)[0],503)
            self.assertEqual(fetch(base,"/internal/healthz")[0],503)

    def test_expired_unified_snapshot_not_issued(self):
        with running_service(NOW+timedelta(days=2)) as (base,root,config,pub):
            path="/v1/tenants/corp-alpha/feeds/stellar-ti.tsv"
            self.assertEqual(fetch(base,path,basic("corp-alpha-bot",PASSWORD_A))[0],503)

    def test_credentials_require_restricted_file_and_strong_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"registry.json"
            set_config(path,tenant_config())
            self.assertEqual(len(registry(path)),2)
            self.assertTrue(verify_secret(PASSWORD_A,registry(path)["corp-alpha"]["password_hash"]))
            self.assertFalse(verify_secret("wrong",registry(path)["corp-alpha"]["password_hash"]))
            os.chmod(path,0o644)
            with self.assertRaisesRegex(ValueError,"restricted"):
                registry(path)
            os.chmod(path,0o600)
            path.write_text('{"schema": "forged", "tenants": []}')
            with self.assertRaisesRegex(ValueError,"schema"):
                registry(path)
            self.assertIsNone(basic_auth("Basic !!!"))

if __name__=="__main__":
    unittest.main(verbosity=2)

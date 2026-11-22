#!/usr/bin/env python3
"""Customer-isolated *single combined* Stellar Cyber TSV service, loopback-only behind HTTPS proxy.

This service never collects sources, creates signing keys, signs releases, or
changes the Stellar tenant. It only authenticates tenant-scoped HTTP Basic
credentials then re-verifies the approved signed TI snapshot on each GET.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading

from strict_ti_gateway import current_unified_tsv

SCHEMA = "stellar-ti-tenants.v1"
ITERATIONS = 260_000
MAX_CONFIG = 256 * 1024
SLUG = re.compile(r"[a-z][a-z0-9-]{1,62}\Z")
PATH = re.compile(r"/v1/tenants/([a-z][a-z0-9-]{1,62})/feeds/stellar-ti\.tsv\Z")
SOURCES = {"unified"}
DUMMY_HASH = "pbkdf2_sha256$260000$" + "00"*16 + "$" + "00"*32


def make_password_hash(secret: str, salt: bytes | None = None) -> str:
    if not isinstance(secret,str) or not 24 <= len(secret) <= 256:
        raise ValueError("Credential secret must have 24-256 characters")
    salt = os.urandom(16) if salt is None else salt
    if len(salt) != 16:
        raise ValueError("Invalid PBKDF2 salt")
    token = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, ITERATIONS)
    return "pbkdf2_sha256$" + str(ITERATIONS) + "$" + salt.hex() + "$" + token.hex()


def verify_secret(secret: str, encoded: str) -> bool:
    try:
        algo,count,salt,hash_value=encoded.split("$")
        if algo != "pbkdf2_sha256" or int(count) != ITERATIONS:
            raise ValueError("Unsupported PBKDF2 iteration count")
        if not re.fullmatch(r"[0-9a-f]{32}",salt) or not re.fullmatch(r"[0-9a-f]{64}",hash_value):
            raise ValueError("Malformed stored secret hash")
        actual=hashlib.pbkdf2_hmac("sha256",secret.encode("utf-8"),
                                  bytes.fromhex(salt),ITERATIONS)
        return secrets.compare_digest(actual,bytes.fromhex(hash_value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Invalid stored credential") from exc


def registry(path: Path) -> dict[str,dict]:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Credential registry must be absolute and not symlinked")
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_CONFIG:
        raise ValueError("Credential registry must be restricted regular file (0600)")
    raw=path.read_bytes()
    if len(raw)>MAX_CONFIG:
        raise ValueError("Oversized credential registry")
    config=json.loads(raw)
    if config.get("schema") != SCHEMA or not isinstance(config.get("tenants"),list):
        raise ValueError("Unknown registry schema")
    rows=config["tenants"]
    if not 0 < len(rows) <= 500:
        raise ValueError("Empty or oversized customer registry")
    seen={};users=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)!={"id","username","password_hash","enabled","feeds"}:
            raise ValueError("Malformed customer registry row")
        tid,user=row["id"],row["username"]
        if (not isinstance(tid,str) or not SLUG.fullmatch(tid) or
            not isinstance(user,str) or not SLUG.fullmatch(user) or
            tid in seen or user in users or type(row["enabled"]) is not bool or
            not isinstance(row["feeds"],list)):
            raise ValueError("Duplicate/invalid customer registration")
        if len(row["feeds"]) != len(set(row["feeds"])) or not row["feeds"] or not set(row["feeds"]) <= SOURCES:
            raise ValueError("Invalid tenant subscription")
        # Validate the stored digest shape without running PBKDF2 for every
        # tenant on every request (could permit costly authentication DoS).
        if not isinstance(row["password_hash"],str) or not re.fullmatch(
            r"pbkdf2_sha256\$260000\$[0-9a-f]{32}\$[0-9a-f]{64}",
            row["password_hash"]):
            raise ValueError("Malformed stored tenant password digest")
        seen[tid]=row
        users.add(user)
    return seen


def basic_auth(header: str | None):
    if not isinstance(header,str) or len(header)>750 or not header.startswith("Basic "):
        return None
    try:
        decoded=base64.b64decode(header[6:],validate=True).decode("utf-8")
    except (binascii.Error,UnicodeError,ValueError):
        return None
    if ":" not in decoded or len(decoded)>384 or "\n" in decoded or "\r" in decoded:
        return None
    username,secret=decoded.split(":",1)
    return (username,secret) if username and secret else None


def authorized(rows,tenant,feed,header):
    parsed=basic_auth(header)
    record=rows.get(tenant)
    digest=record["password_hash"] if record else DUMMY_HASH
    try:
        valid=verify_secret(parsed[1] if parsed else "",digest)
    except ValueError:
        return False
    return bool(parsed and record and valid and
                secrets.compare_digest(parsed[0],record["username"]) and
                record["enabled"] and feed in record["feeds"])


def serve(origin: Path,pubkey: Path,config: Path,port=18332,clock=None,run_forever=True):
    if not (1024 <= port <= 65535 or port==0 and not run_forever):
        raise ValueError("Invalid loopback port")
    if not origin.is_absolute() or not pubkey.is_absolute():
        raise ValueError("Origin and public key paths must be absolute")
    registry(config)
    now=clock or (lambda:datetime.now(timezone.utc))
    counters={"requests":0,"ok":0,"auth_denied":0,"unavailable":0}
    lock=threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version="StellarTIP/1.0"
        sys_version=""
        def log_message(self,format,*args):
            # Auth and user-controlled paths must never be logged.
            return
        def reply(self,code,blob,mime="text/plain; charset=utf-8",challenge=False):
            self.send_response(code)
            self.send_header("Content-Type",mime)
            self.send_header("Content-Length",str(len(blob)))
            self.send_header("Cache-Control","no-store, max-age=0")
            self.send_header("Pragma","no-cache")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("X-Frame-Options","DENY")
            if challenge:
                self.send_header("WWW-Authenticate",
                                 'Basic realm="Stellar TI Customer Feed", charset="UTF-8"')
            self.end_headers()
            self.wfile.write(blob)
        def count(self,result):
            with lock:
                counters["requests"]+=1
                counters[result]+=1
        def do_GET(self):
            if self.path == "/internal/healthz":
                try:
                    registry(config)
                    current_unified_tsv(origin,pubkey,now())
                    self.reply(200,b'{"status":"ready"}\n',"application/json")
                except (ValueError,OSError,KeyError,TypeError,json.JSONDecodeError):
                    self.reply(503,b'{"status":"unavailable"}\n',"application/json")
                return
            if self.path == "/internal/metrics":
                with lock: payload=json.dumps(counters,sort_keys=True).encode()+b"\n"
                self.reply(200,payload,"application/json")
                return
            matched=PATH.fullmatch(self.path)
            if not matched:
                self.reply(404,b"Not Found\n")
                return
            tenant=matched.group(1)
            kind="unified"
            try:
                rows=registry(config)
            except (ValueError,OSError,KeyError,TypeError,json.JSONDecodeError):
                self.count("unavailable")
                self.reply(503,b"Feed temporarily unavailable\n")
                return
            if not authorized(rows,tenant,kind,self.headers.get("Authorization")):
                self.count("auth_denied")
                self.reply(401,b"Unauthorized\n",challenge=True)
                return
            try:
                content=current_unified_tsv(origin,pubkey,now())
            except (ValueError,OSError,KeyError,TypeError,json.JSONDecodeError):
                self.count("unavailable")
                self.reply(503,b"Feed temporarily unavailable\n")
                return
            self.count("ok")
            self.reply(200,content,"text/tab-separated-values; charset=utf-8")
        def do_HEAD(self): self.reply(405,b"Method Not Allowed\n")
        def do_POST(self): self.reply(405,b"Method Not Allowed\n")
        def do_PUT(self): self.reply(405,b"Method Not Allowed\n")
        def do_DELETE(self): self.reply(405,b"Method Not Allowed\n")

    server=ThreadingHTTPServer(("127.0.0.1",port),Handler)
    if run_forever:
        try: server.serve_forever()
        finally: server.server_close()
    return server


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--origin",type=Path,required=True)
    parser.add_argument("--public-key",type=Path,required=True)
    parser.add_argument("--registry",type=Path,required=True)
    parser.add_argument("--port",type=int,default=18332)
    args=parser.parse_args()
    serve(args.origin,args.public_key,args.registry,args.port)


if __name__=="__main__":
    main()

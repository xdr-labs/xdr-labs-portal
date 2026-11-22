#!/usr/bin/env python3
"""QA-only signed Stellar TIP promotion + localhost read-only gateway.

No server is started and no tenant is changed by importing this module.
Production use requires separately approved infrastructure, keys, credentials,
TLS termination and customer validation. The gateway binds loopback ONLY.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from verify_ti_release import verify

TSV_FILES = {
    "/feeds/recent-attackers.tsv": "strict-recent-attackers-DRAFT.tsv",
    "/feeds/recent-phishing.tsv": "strict-recent-phishing-DRAFT.tsv",
}
EVIDENCE = {"strict-ip-evidence.csv", "strict-domain-evidence.csv"}
SIGNED_FILES = set(TSV_FILES.values()) | EVIDENCE
STRONG_TAGS = {"shell-commands", "db-ransom", "mirai-like", "sip-fraud"}
SOURCES = {"OffSeqMirage", "JacobHoneypot", "Corroborated"}
MANIFEST = "strict-manifest.json"
SIGNATURE = "strict-manifest.sig"
STATE = "state.json"

def observed(ts):
    d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    if d.tzinfo is None:
        raise ValueError("Missing timezone in observation")
    return d.astimezone(timezone.utc)

def strict_observation_gate(stage: Path, manifest: dict, now: datetime):
    """Cross-check signed evidence against every emitted IOC and current clock."""
    generated = observed(manifest["generated_at"])
    if not isinstance(manifest.get("data_rights"), dict) or not {"CERTPolska", "OffSeqMirage", "JacobHoneypot"} <= set(manifest["data_rights"]):
        raise ValueError("Source commercial-use attribution missing")
    if not isinstance(manifest.get("source_sha256"), dict) or not {
        "manifest", "attackers", "scanners", "anonymizers", "cert", "jacob_json", "jacob_csv"
    } <= set(manifest["source_sha256"]):
        raise ValueError("Source provenance incomplete")
    for digest in manifest["source_sha256"].values():
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Bad source digest format")
    offseq_generated = observed(manifest["offseq"]["source_generated"])
    jacob_generated = observed(manifest["jacob_honeypot"]["source_updated"])
    if not (now - timedelta(hours=36) <= offseq_generated <= generated and
            now - timedelta(hours=8) <= jacob_generated <= generated):
        raise ValueError("Current-source evidence exceeded declared refresh age")

    ip_values = {}
    for line in (stage / TSV_FILES["/feeds/recent-attackers.tsv"]).read_text(encoding="utf-8").splitlines():
        kind, value, source, score = line.split("\t")
        ip = ipaddress.ip_address(value)
        if kind != "ip" or ip.version != 4 or not ip.is_global or source not in SOURCES:
            raise ValueError("Bad IP or source in signed feed")
        ip_values[value] = (source, int(score))
    with (stage / "strict-ip-evidence.csv").open(newline="", encoding="utf-8") as stream:
        rows = csv.DictReader(stream)
        required = {"ip","source","first_seen","last_seen","score","confidence",
                    "sensors","networks","tags","tier","bans","attempts",
                    "jacob_last_seen","jacob_tier"}
        if not rows.fieldnames or not required <= set(rows.fieldnames):
            raise ValueError("Missing signed per-IP observation columns")
        seen = set()
        for row in rows:
            ip, src = row["ip"], row["source"]
            if ip in seen or ip_values.get(ip) != (src, int(row["score"])):
                raise ValueError("Unmatched/duplicated IP evidence")
            seen.add(ip)
            first, last = observed(row["first_seen"]), observed(row["last_seen"])
            if not first <= last <= generated or not now - timedelta(hours=24) <= last <= now:
                raise ValueError("IP observation is stale or from the future")
            if src in ("OffSeqMirage", "Corroborated"):
                if int(row["confidence"]) < 85 or int(row["sensors"]) < 3 or int(row["networks"]) < 2:
                    raise ValueError("Insufficient independent original-sensor observations")
                if not STRONG_TAGS.intersection(row["tags"].split(";")):
                    raise ValueError("Only scanning/weak behavior in high-confidence IP")
            else:
                if row["tier"] != "loader":
                    raise ValueError("Uncorroborated single-sensor credential IPs are hunting-only")
            if src == "Corroborated":
                other = observed(row["jacob_last_seen"])
                if not now - timedelta(hours=24) <= other <= generated:
                    raise ValueError("Corroborating sensor has stale observation")
                if row["jacob_tier"] not in ("loader", "credential"):
                    raise ValueError("Missing corroboration type")
        if set(ip_values) != seen:
            raise ValueError("IP evidence does not cover entire signed feed")

    domains = {row.split("\t")[1] for row in
               (stage / TSV_FILES["/feeds/recent-phishing.tsv"]).read_text(encoding="utf-8").splitlines()}
    with (stage / "strict-domain-evidence.csv").open(newline="", encoding="utf-8") as stream:
        rows = csv.DictReader(stream)
        if not rows.fieldnames or not {"domain", "added_at", "removed_at"} <= set(rows.fieldnames):
            raise ValueError("Missing signed domain evidence")
        seen = set()
        for row in rows:
            domain = row["domain"]
            if domain not in domains or domain in seen or row["removed_at"]:
                raise ValueError("Removed or duplicated domain in signed feed")
            seen.add(domain)
            first_seen = observed(row["added_at"])
            if not now - timedelta(hours=24) <= first_seen <= generated:
                raise ValueError("Phishing domain outside 24h admission window")
        if seen != domains:
            raise ValueError("Signed domain evidence does not match feed")

def validate(stage: Path, pubkey: Path, min_sequence: int, now: datetime) -> dict:
    if any((stage / f).is_symlink() for f in SIGNED_FILES | {MANIFEST,SIGNATURE}):
        raise ValueError("Symlinked stage artifact is not allowed")
    meta = json.loads((stage / MANIFEST).read_text(encoding="utf-8"))
    if meta.get("schema") != "stellar-strict-live-stage.v1" or set(meta.get("files",{})) != SIGNED_FILES:
        raise ValueError("Unexpected strict-only signed inventory")
    verify(stage/MANIFEST, stage/SIGNATURE, pubkey, stage, min_sequence, now, True)
    strict_observation_gate(stage, meta, now)
    return meta

def _existing_seq(root: Path):
    value = 0
    state = root/STATE
    if state.exists():
        payload = json.loads(state.read_text(encoding="utf-8"))
        value = int(payload["last_sequence"])
    current = root/"current"
    if current.is_symlink():
        target = current.readlink()
        if target.is_absolute() or ".." in target.parts or target.parts[0] != "releases" or len(target.parts) != 2:
            raise ValueError("Unsafe current release symlink")
        value = max(value, int(target.parts[1]))
    elif current.exists():
        raise ValueError("Current release is not an atomic symlink")
    return value

def current_file(root: Path, pubkey: Path, request_path: str, now: datetime) -> Path:
    if request_path not in TSV_FILES:
        raise ValueError("Unrecognized TIP endpoint")
    current = root/"current"
    if not current.is_symlink():
        raise ValueError("No approved strict TI release")
    # Read path is determined only by the checked current symlink, never by URL.
    seq = _existing_seq(root)
    stage = root/current.readlink()
    meta = validate(stage, pubkey, 0, now)
    if int(meta["sequence"]) != seq:
        raise ValueError("Release-state rollback or pointer mismatch")
    return stage/TSV_FILES[request_path]

def promote(stage: Path, root: Path, pubkey: Path, now: datetime, apply: bool = False):
    # Dry-run does not create release paths or touch persistent state.
    if not apply:
        baseline = _existing_seq(root) if root.exists() else 0
        meta = validate(stage, pubkey, baseline, now)
        return {"result": "DRY_RUN_VALID", "sequence": int(meta["sequence"]),
                "file_counts": meta["feed_counts"]}
    root.mkdir(parents=True, exist_ok=True)
    releases = root/"releases"
    releases.mkdir(exist_ok=True)
    with (root/".release.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        last = _existing_seq(root)
        meta = validate(stage, pubkey, last, now)
        seq = int(meta["sequence"])
        target = releases/str(seq)
        if target.exists() or target.is_symlink():
            raise ValueError("Replay: release directory already present")
        candidate = Path(tempfile.mkdtemp(prefix=".candidate-", dir=releases))
        try:
            for name in SIGNED_FILES | {MANIFEST,SIGNATURE}:
                if not (stage/name).is_file():
                    raise ValueError("Missing signed release member " + name)
                shutil.copyfile(stage/name, candidate/name, follow_symlinks=False)
            # Check copied bytes again: prevents source changing during copy.
            validate(candidate, pubkey, last, now)
            os.rename(candidate, target)
            for member in target.iterdir():
                member.chmod(0o440)
            target.chmod(0o550)
        finally:
            if candidate.exists():
                shutil.rmtree(candidate)
        temp_link = root/(".current-" + str(os.getpid()))
        try:
            os.symlink("releases/"+str(seq), temp_link)
            os.replace(temp_link, root/"current")
        finally:
            if temp_link.is_symlink():
                temp_link.unlink()
        state = root/(".state-" + str(os.getpid()) + ".json")
        try:
            state.write_text(json.dumps({"last_sequence":seq,"sha256":meta["files"],
                                        "promoted_at":now.isoformat()},sort_keys=True)+"\n",
                             encoding="utf-8")
            os.replace(state, root/STATE)
        finally:
            if state.exists():
                state.unlink()
        return {"result":"TEMPORARY_RELEASE_PROMOTED", "sequence":seq,
                "file_counts":meta["feed_counts"]}

def serve_local(root: Path, pubkey: Path, port: int):
    if not (1024 <= port <= 65535):
        raise ValueError("Invalid loopback port")
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                selected = current_file(root,pubkey,self.path,datetime.now(timezone.utc))
                body = selected.read_bytes()
            except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
                self.send_error(503,"Signed fresh TIP snapshot not available")
                return
            self.send_response(200)
            self.send_header("Content-Type","text/tab-separated-values; charset=utf-8")
            self.send_header("Cache-Control","no-store, max-age=0")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            self.send_error(405)
        def do_PUT(self):
            self.send_error(405)
        def do_DELETE(self):
            self.send_error(405)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode",required=True)
    for cmd in ("audit","promote"):
        sp = sub.add_parser(cmd)
        sp.add_argument("--stage",type=Path,required=True)
        sp.add_argument("--origin",type=Path,required=True)
        sp.add_argument("--public-key",type=Path,required=True)
        if cmd == "promote":
            sp.add_argument("--apply",action="store_true",help="Local test origin only; production requires approval")
    server = sub.add_parser("serve-loopback")
    server.add_argument("--origin",type=Path,required=True)
    server.add_argument("--public-key",type=Path,required=True)
    server.add_argument("--port",type=int,default=18331)
    args = p.parse_args()
    if args.mode == "serve-loopback":
        serve_local(args.origin,args.public_key,args.port)
    else:
        result = promote(args.stage,args.origin,args.public_key,datetime.now(timezone.utc),
                         getattr(args,"apply",False) if args.mode=="promote" else False)
        print(json.dumps(result,sort_keys=True))

if __name__=="__main__":
    main()

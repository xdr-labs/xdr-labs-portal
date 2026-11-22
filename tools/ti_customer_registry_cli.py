#!/usr/bin/env python3
"""Offline tenant credential registry administration for single Custom TI feed.

Do not run against production without authorization. No secrets are passed as
CLI arguments or stored in plaintext. A customer has ONE subscription:
unified Stellar Cyber ip/domain/URL/hash TSV (types enabled only when verified).
"""
import argparse
import fcntl
import getpass
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile

from ti_customer_service import SCHEMA, SLUG, make_password_hash, registry

def input_secret():
    a=getpass.getpass("New customer feed password (24+ chars): ")
    b=getpass.getpass("Repeat customer feed password: ")
    if not secrets.compare_digest(a,b):
        raise ValueError("Confirmation mismatch; no registry change")
    return make_password_hash(a)

def ensure_directory(path: Path):
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Use an absolute non-symlink path")
    directory=path.parent
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Invalid registry directory")
    permissions=directory.stat()
    if permissions.st_mode & 0o022:
        raise ValueError("Registry directory must not be group/world writable")
    if path.exists():
        registry(path)  # Fully validate existing file before any mutation.

def read_data(path: Path) -> dict:
    if path.exists():
        # registry() has already validated each tenant's identity, subscription,
        # KDF shape, permissions, and uniqueness.
        registry(path)
        return json.loads(path.read_text(encoding="utf-8"))
    return {"schema": SCHEMA, "tenants": []}

def atomic_save(path: Path, data: dict):
    if not data["tenants"]:
        raise ValueError("Refusing to create an empty account registry")
    import copy
    copy_path=path.parent / (".tenant-validate-"+str(os.getpid()))
    if copy_path.exists():
        raise ValueError("Unexpected pre-existing tenant staging file")
    encoded=(json.dumps(data,indent=2,sort_keys=True)+"\n").encode()
    if len(encoded)>256*1024:
        raise ValueError("Registry exceeds allowed size")
    fd=None
    try:
        fd=os.open(copy_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd,"wb") as stream:
            fd=None
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        registry(copy_path)
        os.replace(copy_path,path)
        fd_dir=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd_dir)
        finally: os.close(fd_dir)
    finally:
        if fd is not None:
            os.close(fd)
        if copy_path.exists():
            copy_path.unlink()

def update(path: Path, action: str, tenant_id: str, username=None,
           secret_hash=None):
    ensure_directory(path)
    if not isinstance(tenant_id,str) or not SLUG.fullmatch(tenant_id):
        raise ValueError("Invalid tenant ID")
    if action not in {"add","rotate","disable","enable"}:
        raise ValueError("Unknown administrative action")
    lock=path.with_suffix(path.suffix+".lock")
    if lock.is_symlink():
        raise ValueError("Tenant lock must not be a symlink")
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        if os.fstat(fd).st_mode & 0o077:
            raise ValueError("Tenant lock must be restricted")
        fcntl.flock(fd,fcntl.LOCK_EX)
        current=read_data(path)
        records=current["tenants"]
        match=[item for item in records if item["id"]==tenant_id]
        if action=="add":
            if match or not isinstance(username,str) or not SLUG.fullmatch(username):
                raise ValueError("Existing tenant or invalid new username")
            if any(item["username"]==username for item in records):
                raise ValueError("Duplicate username")
            if not secret_hash:
                raise ValueError("Missing hashed credential")
            records.append({"id":tenant_id,"username":username,
                            "password_hash":secret_hash,
                            "enabled":True,"feeds":["unified"]})
        else:
            if len(match)!=1:
                raise ValueError("Tenant not found")
            record=match[0]
            if action=="rotate":
                if not secret_hash:
                    raise ValueError("Missing new hashed credential")
                record["password_hash"]=secret_hash
            elif action=="disable":
                record["enabled"]=False
            elif action=="enable":
                record["enabled"]=True
        atomic_save(path,current)
        return {"tenant_id":tenant_id,"action":action,
                "status":"REGISTRY_UPDATED_OFFLINE","subscriptions":["unified"]}
    finally:
        os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--registry",required=True,type=Path,
                   help="Absolute path to protected 0600 tenant registry")
    sub=p.add_subparsers(dest="operation",required=True)
    for action in ("add","rotate","disable","enable"):
        command=sub.add_parser(action)
        command.add_argument("--tenant",required=True)
        if action=="add":
            command.add_argument("--username",required=True)
    args=p.parse_args()
    hashed=input_secret() if args.operation in ("add","rotate") else None
    result=update(args.registry,args.operation,args.tenant,
                  getattr(args,"username",None),hashed)
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":
    main()

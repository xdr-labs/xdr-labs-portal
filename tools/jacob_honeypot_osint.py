#!/usr/bin/env python3
"""Conservative, freshness-qualified, original-sensor IP evidence from Jacobrakai.

No scanner-only entries. No source bundling. Original source data CC0 1.0.
"""
from datetime import datetime, timedelta, timezone
import csv
import io
import ipaddress
import json

def stamp(value):
    d = datetime.fromisoformat(value.replace("Z","+00:00"))
    if d.tzinfo is None: raise ValueError("Timestamp without timezone")
    return d.astimezone(timezone.utc)

def select(csv_bytes:bytes, json_bytes:bytes, now:datetime):
    meta=json.loads(json_bytes.decode("utf-8"))
    header=meta.get("meta",{})
    if header.get("license")!="CC0-1.0" or header.get("update_frequency")!="hourly":
        raise ValueError("Jacobrakai licence or refresh schema changed")
    generated=stamp(header["updated"])
    if not generated<=now+timedelta(minutes=5) or now-generated>timedelta(hours=8):
        raise ValueError("Jacobrakai source is stale")
    src=csv.DictReader(io.StringIO(csv_bytes.decode("utf-8-sig")))
    expected={"ip","tier","bans","attempts","first_seen","last_seen","first_banned","asn"}
    if not src.fieldnames or not expected.issubset(src.fieldnames):
        raise ValueError("Jacobrakai CSV schema changed")
    rows=list(src)
    if len(rows)<30 or len(rows)!=header.get("count"):
        raise ValueError("Jacobrakai source row count changed")
    json_rows=meta.get("ips")
    if not isinstance(json_rows,list) or len(json_rows)!=len(rows):
        raise ValueError("Jacobrakai source JSON mismatch")
    index={}
    for obj in json_rows:
        ip=obj.get("ip")
        if not ip or ip in index: raise ValueError("Duplicate JSON IP")
        index[ip]=obj
    chosen=[]
    seen=set()
    for row in rows:
        ip=row["ip"]
        addr=ipaddress.ip_address(ip)
        if addr.version!=4 or not addr.is_global or ip in seen:
            raise ValueError("Jacobrakai non-global/duplicate IP")
        seen.add(ip)
        other=index.get(ip)
        if other is None or other.get("tier")!=row["tier"] or other.get("last_seen")!=row["last_seen"]:
            raise ValueError("Jacobrakai origin inconsistent across CSV/JSON")
        first,last=stamp(row["first_seen"]),stamp(row["last_seen"])
        if not first<=last<=now+timedelta(minutes=5):
            raise ValueError("Invalid event chronology")
        if not now-timedelta(hours=24)<=last<=now: continue
        tier=row["tier"]
        if tier=="scanner": continue
        bans,attempts=int(row["bans"]),int(row["attempts"])
        if bans<0 or attempts<0: raise ValueError("Negative attacks")
        # Credential bans/attempts are cumulative, not necessarily from last 24h.
        if tier=="credential" and not (bans>=3 and attempts>=100): continue
        if tier not in ("credential","loader"): raise ValueError("Unknown Jacob tier")
        chosen.append(dict(value=ip,source="JacobHoneypot",score=90 if tier=="loader" else 83,
                           last_seen=last.isoformat(),first_seen=first.isoformat(),
                           tier=tier,bans=bans,attempts=attempts))
    if not chosen or len(chosen)>120:
        raise ValueError("Jacobrakai strict IOC volume out of policy")
    return sorted(chosen,key=lambda x:x["value"]),{
        "source_updated":generated.isoformat(),"source_total":len(rows),
        "selected":len(chosen),
        "attribution":"Jacobrakai original Cowrie/Heralding honeypot (https://jacobrakai.org/feed/)",
        "data_license":"CC0 1.0",
        "policy":"last_seen 24h, loader or repeated-credential, no scanner-only"
    }

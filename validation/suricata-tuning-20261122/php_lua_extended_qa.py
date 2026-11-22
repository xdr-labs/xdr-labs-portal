#!/usr/bin/env python3
"""QA-only HTTP multipart edge corpus for Suricata 8 Lua rule.

All packets are synthetic and inert (RFC 5737 IPs). No network transmission.
These fixtures test exact 100-file thresholds, disjoint headers, quoted boundary,
mixed case, and multi-segment TCP reassembly. Not a CVE exploitation PoC.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SID = 9005055
GENERATOR = ROOT/"validation/qa-suricata-last-two/generate_risk_fixtures.py"
SOURCE_SHA = "0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
RAW = ROOT/"downloads/local-web-attack-ai-v1.2-383-rc1.rules"

CASES = {
    "compact-100": {"count":100,"padding":0,"positive":True},
    "wide-105": {"count":105,"padding":180,"positive":True},
    "quoted-boundary-105": {"count":105,"padding":0,"quote_boundary":True,"positive":True},
    "mixed-case-105": {"count":105,"padding":0,"mixed_case":True,"positive":True},
    "whitespace-filename-100": {"count":100,"padding":0,"spaces":True,"positive":True},
    "segmented-tcp-100": {"count":100,"padding":0,"segment":True,"positive":True},
    "segmented-tcp-99": {"count":99,"padding":0,"segment":True,"positive":False},
    "compact-99": {"count":99,"padding":0,"positive":False},
    "last-nonempty-100": {"count":100,"padding":0,"last_nonempty":True,"positive":False},
    "nonempty-105": {"count":105,"padding":0,"all_nonempty":True,"positive":False},
    "filename-only-in-xheader-105": {"count":105,"padding":0,"camouflage":True,"positive":False},
    "wrong-outer-content-type-105": {"count":105,"padding":0,"wrong_ct":True,"positive":False},
    "missing-boundary-param-105": {"count":105,"padding":0,"no_boundary":True,"positive":False},
    "wrong-boundary-param-105": {"count":105,"padding":0,"wrong_boundary":True,"positive":False},
}

def load_generator():
    spec=importlib.util.spec_from_file_location("qa_original",GENERATOR)
    assert spec and spec.loader
    g=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    return g

def request(config:dict) -> bytes:
    boundary=b"qaBOUND123"
    body=bytearray()
    count=config["count"]
    for index in range(count):
        mixed=config.get("mixed_case",False)
        cd=b"cOnTeNt-DisPosiTion" if mixed else b"Content-Disposition"
        form=b"FoRm-DaTa" if mixed else b"form-data"
        if config.get("camouflage"):
            disposition=cd+b": "+form+b"; name=\"upload\"\r\nX-Tracking: filename=\"\""
        elif config.get("all_nonempty") or (config.get("last_nonempty") and index==count-1):
            disposition=cd+b": "+form+b"; name=\"upload\"; filename=\"normal.txt\""
        else:
            sep=b" = " if config.get("spaces") else b"="
            disposition=cd+b": "+form+b"; name=\"upload\"; filename"+sep+b"\"\""
        header=(b"--"+boundary+b"\r\n"+disposition+b"\r\n"
                +b"Content-Type: application/octet-stream\r\n"
                +b"X-Padding: "+b"A"*config.get("padding",0)+b"\r\n\r\n")
        body+=header+b"harmless test data\r\n"
    body+=b"--"+boundary+b"--\r\n"
    if config.get("wrong_ct"):
        ct=b"text/plain"
    elif config.get("no_boundary"):
        ct=b"multipart/form-data"
    elif config.get("wrong_boundary"):
        ct=b"multipart/form-data; boundary=wrongqa"
    elif config.get("quote_boundary"):
        ct=b'multipart/form-data; boundary="'+boundary+b'"'
    else:
        ct=b"multipart/form-data; boundary="+boundary
    headers=(b"POST /qa-multipart HTTP/1.1\r\nHost: test.invalid\r\n"
             +b"Content-Type: "+ct+b"\r\nContent-Length: "+str(len(body)).encode()
             +b"\r\nConnection: close\r\n\r\n")
    return headers+body

def segmented_pcap(g, raw:bytes, port:int, segment_size:int=720)->bytes:
    src, dst, dp = "192.0.2.101", "198.51.100.101", 18881
    cs,ss=10000+port*1000,90000+port*1000
    response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    frames=[
      (src,dst,port,dp,cs,0,0x02,b""),
      (dst,src,dp,port,ss,cs+1,0x12,b""),
      (src,dst,port,dp,cs+1,ss+1,0x10,b""),
    ]
    for offset in range(0,len(raw),segment_size):
        data=raw[offset:offset+segment_size]
        frames.append((src,dst,port,dp,cs+1+offset,ss+1,0x18,data))
    frames.append((dst,src,dp,port,ss+1,cs+1+len(raw),0x18,response))
    frames.append((src,dst,port,dp,cs+1+len(raw),ss+1+len(response),0x10,b""))
    result=bytearray(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1))
    for i,(a,b,sp,dp,seq,ack,flags,data) in enumerate(frames):
        frame=g.ip_tcp(a,b,sp,dp,seq,ack,flags,data,i+1)
        result+=struct.pack("<IIII",g.START_TS+i//1000,(i%1000)*1000,len(frame),len(frame))
        result+=frame
    return bytes(result)

def generate(root:Path):
    assert hashlib.sha256(RAW.read_bytes()).hexdigest()==SOURCE_SHA
    root.mkdir(parents=True,exist_ok=True)
    g=load_generator()
    manifest={}
    for index,(name,config) in enumerate(CASES.items()):
        raw=request(config)
        data=segmented_pcap(g,raw,44000+index) if config.get("segment") else g.pcap([(44000+index,raw)])
        (root/(name+".pcap")).write_bytes(data)
        manifest[name]={"positive":config["positive"],"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
    (root/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    print("PHP_EXTENDED_PCAP_GENERATED",json.dumps({"cases":len(manifest),
          "positive":sum(x["positive"] for x in manifest.values()),
          "negative":sum(not x["positive"] for x in manifest.values()),
          "segmented":sum(x.get("segment",False) for x in CASES.values())},sort_keys=True))

def verify(out:Path):
    failures=[]
    observations={}
    for name,c in CASES.items():
        log=out/name/"eve.json"
        if not log.exists():
            failures.append(name+": no EVE log")
            continue
        alerts=0
        for line in log.read_text().splitlines():
            ev=json.loads(line)
            if ev.get("event_type")=="alert" and int(ev["alert"]["signature_id"])==SID:
                alerts+=1
        observations[name]=alerts
        if bool(alerts)!=c["positive"]:
            failures.append(f"{name}: expected={c['positive']} found={alerts}")
    result={"test_count":len(CASES),"observed":observations,"failures":failures,
            "requires_lua_script_and_http_body_limit":True,"production_ready":False}
    print("PHP_LUA_EXTENDED_RESULT",json.dumps(result,sort_keys=True))
    assert not failures,"\n".join(failures)
    print("PHP_LUA_EXTENDED_PASS",len(CASES))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--generate",type=Path)
    p.add_argument("--verify",type=Path)
    a=p.parse_args()
    if a.generate:generate(a.generate)
    if a.verify:verify(a.verify)
    if not (a.generate or a.verify):p.error("specify --generate or --verify")

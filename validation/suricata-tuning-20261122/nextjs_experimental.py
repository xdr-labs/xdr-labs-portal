#!/usr/bin/env python3
"""QA-only WebSocket SSRF to metadata/loopback candidate, NOT full Next.js CVE detection.

Excludes normal external WebSocket proxies and demands a local/metadata URI.
Original SID 9005017 was never confirmed with the published signature.
This script is not a Suricata production installer.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import hashlib
import re
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SRC=ROOT/"downloads/local-web-attack-ai-v1.2-383-rc1.rules"
EXPECTED_SHA="0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
RULE=HERE/"suricata-nextjs-websocket-internal-review.rules"
SID=9005017
# All content is harmless; RFC5737 source IPs and synthetic HTTP strings.
CASES={
  "aws-metadata-http":("http://169.254.169.254/latest/meta-data/",True,()),
  "aws-metadata-https":("https://169.254.169.254/latest/meta-data/",True,()),
  "loopback-websocket":("http://127.0.0.1:8080/admin",True,()),
  "localhost-websocket":("http://localhost:3000/internal",True,()),
  "gcp-metadata":("http://metadata.google.internal/computeMetadata/v1/",True,()),
  "normal-external-http":("http://example.invalid/ws",False,()),
  "normal-external-https":("https://example.invalid/ws",False,()),
  "lookalike-evil-suffix":("http://169.254.169.254.attacker.invalid/ws",False,()),
  "lookalike-loopback-suffix":("http://127.0.0.1.attacker.invalid/ws",False,()),
  "metadata-no-upgrade":("http://169.254.169.254/latest/meta-data/",False,("no_upgrade",)),
  "metadata-no-key":("http://169.254.169.254/latest/meta-data/",False,("no_key",)),
  "metadata-no-version":("http://169.254.169.254/latest/meta-data/",False,("no_version",)),
  "metadata-post-method":("http://169.254.169.254/latest/meta-data/",False,("post",)),
  "origin-form-path":("/latest/meta-data/",False,()),
}
# The URI alone cannot establish Next.js version, SSRF success, or exploited CVE.
SIGNATURE=(
  'alert http any any -> any any (msg:"XDR QA WebSocket Upgrade to metadata or loopback URI (CVE-2026-44578 probe only)"; '
  'flow:established,to_server; http.method; content:"GET"; startswith; '
  'http.uri.raw; content:"http"; startswith; '
  r'pcre:"/^https?:\/\/(?:169\.254\.169\.254|127\.0\.0\.1|localhost|metadata\.google\.internal)(?::[0-9]{1,5})?(?:\/|\?|$)/i"; '
  'http.header; to_lowercase; content:"upgrade|3a 20|websocket"; fast_pattern; '
  'content:"sec-websocket-version|3a 20|13"; content:"sec-websocket-key|3a 20|"; '
  'classtype:attempted-recon; sid:9005017; rev:2; '
  'metadata:confidence Medium, tag qa_review_only, cve CVE_2026_44578;)'
)
def source_ok():
    assert hashlib.sha256(SRC.read_bytes()).hexdigest()==EXPECTED_SHA
    rules=[l for l in SRC.read_text().splitlines() if l.startswith("alert ") and re.search(r"\bsid:9005017;",l)]
    assert len(rules)==1 and 'http.uri;' in rules[0]
def expected_rule():
    return "# QA-ONLY, may alert on authorized metadata/loopback WebSocket proxy. Do not install without approval.\n"+SIGNATURE+"\n"
def generator():
    source=ROOT/"validation/qa-suricata-last-two/generate_risk_fixtures.py"
    spec=importlib.util.spec_from_file_location("old_fixture_generator",source)
    module=importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module
def generate(out:Path):
    source_ok()
    out.mkdir(parents=True,exist_ok=True)
    g=generator()
    for index,(name,(uri,_,flags)) in enumerate(CASES.items()):
        request=g.websocket(uri)
        if "no_upgrade" in flags:
            request=request.replace(b"Upgrade: websocket\r\n",b"")
        if "no_key" in flags:
            request=request.replace(b"Sec-WebSocket-Key: QUFBQUFBQUFBQUFBQQ==\r\n",b"")
        if "no_version" in flags:
            request=request.replace(b"Sec-WebSocket-Version: 13\r\n",b"")
        if "post" in flags:
            request=request.replace(b"GET ",b"POST ",1)
        (out/(name+".pcap")).write_bytes(g.pcap([(42000+index,request)]))
    print("NEXTJS_PCAP_GENERATED",len(CASES))
def verify(log:Path):
    source_ok()
    assert RULE.read_text()==expected_rule()
    bad=[]
    for name,(_,expected,__) in CASES.items():
        path=log/name/"eve.json"
        if not path.is_file():
            bad.append(f"{name}: no EVE")
            continue
        found=0
        for line in path.read_text().splitlines():
            event=json.loads(line)
            if event.get("event_type")=="alert" and event["alert"]["signature_id"]==SID:
                found+=1
        if bool(found)!=expected:bad.append(f"{name}: expected {expected} got {found}")
    result={"cases":len(CASES),"positives":sum(x[1] for x in CASES.values()),"failures":bad,
            "release_ready":False,"evidence":"CVE-specific exploit and affected Next.js version NOT established"}
    print("NEXTJS_EXPERIMENTAL_REPORT",json.dumps(result,sort_keys=True))
    assert not bad,"\n".join(bad)
    print("NEXTJS_EXPERIMENTAL_PASS",len(CASES))
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--write",action="store_true")
    p.add_argument("--generate",type=Path)
    p.add_argument("--verify",type=Path)
    a=p.parse_args()
    source_ok()
    if a.write:RULE.write_text(expected_rule())
    if a.generate:generate(a.generate)
    if a.verify:verify(a.verify)
    if not (a.write or a.generate or a.verify):
        p.error("choose --write, --generate and/or --verify")
if __name__=="__main__":main()

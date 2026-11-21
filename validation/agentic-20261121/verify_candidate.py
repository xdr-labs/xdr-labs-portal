#!/usr/bin/env python3
"""Static additive-integrity checks (not a replacement for Suricata -T or PCAP QA)."""
import re
import hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'downloads/local-web-attack-ai-v1.1-339.rules'
CAND=ROOT/'downloads/local-web-attack-ai-v1.2-369-rc1.rules'
HUNT=ROOT/'validation/agentic-20261121/agentic-hunting-optional-14.rules'
def rules(text):
    return [x for x in text.splitlines() if x.startswith('alert ')]
def sids(lines):
    result=[]
    for x in lines:
        m=re.search(r'\bsid:(\d+);',x)
        assert m, f'missing SID: {x[:90]}'
        assert x.endswith(')'), f'incomplete rule {m.group(1)}'
        assert x.startswith('alert '), 'unexpected blocking action'
        result.append(int(m.group(1)))
    return result
def verify():
    base=BASE.read_bytes()
    cand=CAND.read_bytes()
    assert cand.startswith(base), 'v1.1 bytes were changed'
    old=sids(rules(base.decode()))
    fresh=sids(rules(cand[len(base):].decode()))
    hunt=sids(rules(HUNT.read_text()))
    assert len(old)==339 and len(set(old))==339
    assert fresh==list(range(9876001,9876031))
    assert hunt==list(range(9876101,9876115))
    assert len(set(old+fresh+hunt))==383, 'SID collision'
    assert len(rules(cand.decode()))==369
    for line in rules(cand[len(base):].decode())+rules(HUNT.read_text()):
        proto=line.split()[1]
        if proto=='http': assert 'http.' in line
        if proto=='tls': assert 'tls.' in line
        if proto=='dns': assert 'dns.query' in line
    print('STATIC_PASS: 339 identical + 30 default + 14 isolated optional; 383 unique SIDs')
    print('BASE_SHA256',hashlib.sha256(base).hexdigest())
    print('RC_SHA256',hashlib.sha256(cand).hexdigest())
if __name__=='__main__': verify()

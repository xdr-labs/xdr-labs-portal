#!/usr/bin/env python3
"""Offline additive 369-rule engine syntax and harmless PCAP replays."""
import argparse, json, subprocess, tempfile
from pathlib import Path
from verify_candidate import verify
from generate_inert_pcap import CASES,generate

ROOT=Path(__file__).resolve().parents[2]
RULES=ROOT/'downloads/local-web-attack-ai-v1.2-369-rc1.rules'
p=argparse.ArgumentParser()
p.add_argument('--static-only',action='store_true')
p.add_argument('--config',default='/etc/suricata/suricata.yaml')
args=p.parse_args()
verify()
if args.static_only: raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix='agentic-qa-') as tmp:
    tmp=Path(tmp)
    pcaps=tmp/'pcaps'
    generate(pcaps)
    syntax=tmp/'syntax'
    syntax.mkdir()
    cmd=['suricata','-T','-c',args.config,'-S',str(RULES),'-l',str(syntax)]
    x=subprocess.run(cmd,text=True,capture_output=True,timeout=90)
    assert x.returncode==0,'suricata -T failed:\n'+x.stdout+x.stderr
    out={}
    for name,(_,__,___,expected) in CASES.items():
        log=tmp/name
        log.mkdir()
        cmd=['suricata','-r',str(pcaps/(name+'.pcap')),'--runmode=single','-c',args.config,'-S',str(RULES),'-l',str(log),'-k','none']
        x=subprocess.run(cmd,text=True,capture_output=True,timeout=90)
        assert x.returncode==0,name+' replay failed:\n'+x.stdout+x.stderr
        seen=set()
        for line in (log/'eve.json').read_text().splitlines():
            e=json.loads(line)
            if e.get('event_type')=='alert':
                sid=int(e['alert']['signature_id'])
                if 9876001<=sid<=9876030: seen.add(sid)
        assert expected.issubset(seen),f'{name}: missing {expected-seen}; observed {seen}'
        if not expected: assert not seen,f'{name}: benign fixture triggered {seen}'
        out[name]=sorted(seen)
    print('ENGINE_PASS: suricata -T; %d/%d inert PCAP fixtures; benign negative clean'%(len(out),len(CASES)))
    print(json.dumps(out,sort_keys=True))

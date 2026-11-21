#!/usr/bin/env python3
"""Run the 13 preserved historical risk PCAPs through the UNMODIFIED 383 rules.

No expected Alert assertions are made for old SIDs 9005017 and 9005055:
the published signatures are not approved or individually reproduced.
This run observes the real current behavior and records the gaps.
"""
import argparse
import collections
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PCAP_ROOT = ROOT / "validation/qa-suricata-last-two"
RULES = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
BASE = ROOT / "downloads/local-web-attack-ai-v1.0-333.rules"
SIDS = (9005017, 9005055)

def parse_signatures(path):
    return {int(p.split("sid:")[-1].split(";")[0]):p for p in path.read_text().splitlines() if p.startswith("alert ")}

def manifest_and_preflight():
    pub = parse_signatures(RULES)
    orig = parse_signatures(BASE)
    for sid in SIDS:
        assert pub[sid] == orig[sid], f"{sid} was modified in the current published candidate"
    manifest = json.loads((PCAP_ROOT/"manifest.json").read_text())
    assert len(manifest) == 13
    for name, meta in manifest.items():
        data=(PCAP_ROOT/name).read_bytes()
        assert len(data)==meta["bytes"] and hashlib.sha256(data).hexdigest()==meta["sha256"]
    return sorted(manifest)

def verify(root, engine_name):
    names=manifest_and_preflight()
    all_alerts={}
    for name in names:
        eve=root/"logs"/name/"eve.json"
        assert eve.exists(),name+" missing EVE"
        alerts=collections.Counter()
        for line in eve.read_text().splitlines():
            record=json.loads(line)
            if record.get("event_type")=="alert" and int(record["alert"]["signature_id"]) in SIDS:
                alerts[int(record["alert"]["signature_id"])]+=1
        all_alerts[name]={str(sid):alerts[sid] for sid in SIDS}
    positives=["nextjs-positive.pcap","php-empty100.pcap","php-empty105.pcap"]
    result={
        "engine":engine_name,"candidate":"unmodified public 383 rules",
        "original_two_signatures_unchanged":True,"fixture_count":len(names),
        "unreproduced_sid_tests":all_alerts,
        "historical_positive_fixtures":{n:all_alerts[n] for n in positives},
        "release_ready":False,
        "interpretation":"Observation only: reported Alert counts are not evidence of safe behavior or production acceptance",
    }
    (root/"legacy-current-observations.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("LEGACY_ORIGINAL_383_OBSERVATIONS",json.dumps(result,sort_keys=True))
    return result

def run(root, engine, config):
    names=manifest_and_preflight()
    for name in names:
        log=root/"logs"/name
        log.mkdir(parents=True,exist_ok=True)
        cmd=[engine,"-r",str(PCAP_ROOT/name),"--runmode=single","-c",config,
             "-S",str(RULES),"-l",str(log),"-k","none"]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=100)
        assert p.returncode==0, f"{name}: {p.stderr[-2000:]}"
    v=subprocess.run([engine,"-V"],capture_output=True,text=True).stdout.strip()
    verify(root,v)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=["run","verify"],default="run")
    p.add_argument("--root",type=Path,default=Path("/tmp/suricata-383-original-legacy"))
    p.add_argument("--engine",default="suricata")
    p.add_argument("--config",default="/etc/suricata/suricata.yaml")
    p.add_argument("--version-name",default="Suricata engine")
    a=p.parse_args()
    a.root.mkdir(parents=True,exist_ok=True)
    if a.mode=="run":run(a.root,a.engine,a.config)
    else:verify(a.root,a.version_name)

if __name__=="__main__":main()

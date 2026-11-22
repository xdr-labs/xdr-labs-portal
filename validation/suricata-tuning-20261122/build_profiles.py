#!/usr/bin/env python3
"""Build review-only Suricata quality profiles from byte-immutable public 383 source."""
from pathlib import Path
import argparse, hashlib, csv, io, re
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SRC = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
PREV = ROOT / "downloads/local-web-attack-ai-v1.1-339.rules"
SHA = "0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
OLD = "2478ffd6b3dbdfbb527695f07e00e1a106a554d8bb898a0f9584bb3845b07483"
PREFIX = "# REVIEW ONLY: generated from immutable 383-rule v1.2 SHA256 " + SHA + "\n# Not approved for production, public download or live Sensor import.\n"
EXCLUDE = {9005017,9005055,9876104,9876109,9876110,9876111}
HISTORICAL = {9876029,9876030}
OPTIN = (set(range(9876101,9876115))-EXCLUDE)|HISTORICAL
REASONS = {
 "legacy": "unreproduced original: unsafe to promote",
 "oast": "overlapping legacy OAST DNS signature",
 "port": "port-only indicator with no protocol evidence",
 "historical": "historical non-ARTEX IOC",
 "hunting": "opt-in non-exclusive hunting indicator",
 "original": "original rule retained",
 "specific": "framework-specific agentic indicator",
}
def sid(line):
    return int(re.search(r"\bsid:(\d+);",line).group(1))
def generate():
    s,old=SRC.read_bytes(),PREV.read_bytes()
    assert hashlib.sha256(s).hexdigest()==SHA
    assert hashlib.sha256(old).hexdigest()==OLD and s.startswith(old)
    lines=[x for x in s.decode().splitlines() if x.startswith("alert ")]
    ids=[sid(l) for l in lines]
    assert len(ids)==len(set(ids))==383
    core,hunt,rows=[],[],[]
    for l in lines:
        i=sid(l)
        if i in EXCLUDE:
            group="excluded"
            reason=REASONS["legacy"] if i in {9005017,9005055} else REASONS["port"] if i==9876104 else REASONS["oast"]
        elif i in OPTIN:
            group="opt-in"
            reason=REASONS["historical"] if i in HISTORICAL else REASONS["hunting"]
            if i in {9876105,9876106}:
                old='content:"update.pentagi.com"; nocase; endswith; fast_pattern;'
                assert l.count(old)==1
                l=l.replace(old,old+r' pcre:"/^update\.pentagi\.com$/i";')
            if i in HISTORICAL:
                l=l.replace("(ARTEX campaign)","(historical C2 IOC; ARTEX linkage unverified)").replace("confidence High,","confidence Medium,")
                assert "ARTEX linkage unverified" in l
            hunt.append(l)
        else:
            group="core"
            reason=REASONS["specific"] if 9876001<=i<=9876028 else REASONS["original"]
            core.append(l)
        rows.append((i,group,reason))
    assert len(core)==365 and len(hunt)==12 and len(rows)==383
    assert len({sid(l) for l in core+hunt})==377
    table=io.StringIO()
    writer=csv.writer(table,lineterminator="\n")
    writer.writerow(["sid","review_disposition","reason"])
    writer.writerows(rows)
    return {
      "suricata-core-365-review.rules":PREFIX+"# Core default candidate: 365 alert signatures.\n"+"\n".join(core)+"\n",
      "suricata-hunting-12-optin.rules":PREFIX+"# Opt-in-only 12 hunting indicators; legitimate use may trigger.\n"+"\n".join(hunt)+"\n",
      "suricata-core-plus-hunting-377-review.rules":PREFIX+"# Core 365 plus opt-in hunting 12. Review-only combined candidate.\n"+"\n".join(core+hunt)+"\n",
      "review-disposition-383.csv":table.getvalue(),
    }
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--write",action="store_true")
    ap.add_argument("--verify",action="store_true")
    a=ap.parse_args()
    if not a.write and not a.verify: ap.error("use --write or --verify")
    for name,data in generate().items():
        f=HERE/name
        if a.write:f.write_text(data,encoding="utf-8",newline="\n")
        if a.verify:assert f.is_file() and f.read_bytes()==data.encode(),name+" drift"
        print(name,len(data.encode()),hashlib.sha256(data.encode()).hexdigest())
    print("REVIEW_PROFILE_PASS core=365 opt_in=12 union=377 excluded=6; source=383 unchanged")
if __name__=="__main__":main()

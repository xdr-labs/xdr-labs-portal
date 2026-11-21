#!/usr/bin/env python3
"""Offline publication parity: v1.2 rules, catalog, bilingual pages."""
from pathlib import Path
import csv,hashlib,re

ROOT=Path(__file__).resolve().parents[2]
D=ROOT/"downloads"
RULE="local-web-attack-ai-v1.2-383-rc1.rules"
CAT="local-web-attack-ai-v1.2-383-catalog.csv"
SHA="0cb8e39aef5251f28d0a12354797c2068812bdb6d9be8ec911fb43baee1f4d92"
def verify():
    data=(D/RULE).read_bytes()
    assert hashlib.sha256(data).hexdigest()==SHA
    base=(D/"local-web-attack-ai-v1.1-339.rules").read_bytes()
    assert data.startswith(base)
    signatures=[x for x in data.decode().splitlines() if x.startswith("alert ")]
    sids=[int(re.search(r"\bsid:(\d+);",x).group(1)) for x in signatures]
    assert len(sids)==len(set(sids))==383
    with (D/CAT).open(newline="") as f: catalog=list(csv.DictReader(f))
    assert len(catalog)==383
    assert [int(x["sid"]) for x in catalog]==sids
    assert sum(x["group"]=="v1.1 preserved" for x in catalog)==339
    assert sum(x["group"]!="v1.1 preserved" for x in catalog)==44
    import zipfile
    with zipfile.ZipFile(D/"local-web-attack-ai-v1.2-383.zip") as z:
        assert z.testzip() is None
        assert z.read(RULE)==data
        assert z.read(CAT)==(D/CAT).read_bytes()
        assert z.read("source-map.csv")==(ROOT/"validation/agentic-20261121/source-map.csv").read_bytes()
        assert z.read("SHA256SUMS-v1.2.txt")==f"{SHA}  {RULE}\n".encode()
        assert {"README-v1.2-KO.txt","README-v1.2-EN.txt","LICENSE-THREATDEFENCE.txt"}.issubset(z.namelist())
    for f in ("products/ai-assisted-attack-detection-rules.mdx",
              "ko/products/ai-assisted-attack-detection-rules.mdx"):
        src=(ROOT/f).read_text()
        assert "previously optional hunting" not in src
        assert "선택적 헌팅 14개" not in src
        assert "별도의 선택적 파일을 병합" not in src
        assert all(x.strip() == "</Card>" for x in src.splitlines() if "</Card>" in x), f"Invalid mixed Card closing tag: {f}"
        for item in (RULE,CAT,"local-web-attack-ai-v1.2-383.zip",SHA,"49/49","383","44","9005017","9005055"):
            assert item in src, (f,item)
    print("PUBLICATION_PASS 383 rules, catalog and EN/KR pages; original 339 bytes preserved")
if __name__=="__main__": verify()

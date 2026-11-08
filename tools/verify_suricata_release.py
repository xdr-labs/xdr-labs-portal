#!/usr/bin/env python3
"""Verify Suricata v1.0 distribution and user-facing download destinations.

Default offline mode reads only repository content. --live additionally checks
published GitHub Release assets and the public bilingual product pages.
"""
import argparse
import hashlib
import json
import re
import urllib.request
from urllib.parse import urlparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DL = ROOT / "downloads"
PREFIX = "local-web-attack-ai-v1.0-333"
ORIGINAL_SHA = "5947a64a6b45ee122537a1ea166ebf383307302cf210b63d24b350b0df98eb96"
RELEASE = "https://github.com/xdr-labs/xdr-labs-portal/releases/download/v1.0/"
RULES = PREFIX + ".rules"
ZIP = PREFIX + ".zip"
BOTH_SIDS = {9005017, 9005055}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_bytes(data):
    assert sha(data) == ORIGINAL_SHA, "Published ruleset does not match approved baseline"
    signatures = [line for line in data.splitlines() if line.startswith(b"alert ")]
    sids = [int(re.search(rb"\bsid:(\d+);", line).group(1)) for line in signatures]
    assert len(sids) == len(set(sids)) == 333, "Expected 333 unique alert signatures"
    assert BOTH_SIDS.issubset(sids), "Both two unverified signatures must be included"


def verify_local():
    source = (DL / RULES).read_bytes()
    validate_bytes(source)
    with zipfile.ZipFile(DL / ZIP) as z:
        assert z.testzip() is None
        assert z.read(RULES) == source, "ZIP and .rules mismatch"
        names = set(z.namelist())
        assert {"README-v1.0-EN.txt", "README-v1.0-KO.txt", "VALIDATION-v1.0.txt",
                "SHA256SUMS-v1.0.txt"}.issubset(names)
        assert b"331 of 333" in z.read("README-v1.0-EN.txt")
        assert "331개".encode() in z.read("README-v1.0-KO.txt")
        assert b"331/333" in z.read("VALIDATION-v1.0.txt")
        assert b"315/333" not in z.read("VALIDATION-v1.0.txt")
        assert z.read("SHA256SUMS-v1.0.txt").decode() == ORIGINAL_SHA + "  " + RULES + "\n"
    for lang in ("products", "ko/products"):
        page = (ROOT / lang / "ai-assisted-attack-detection-rules.mdx").read_text()
        for asset in (RULES, ZIP):
            assert RELEASE + asset in page, f"{lang}: asset link missing"
            assert "raw.githubusercontent.com" not in page, f"{lang}: text-rendering raw GitHub link"
        assert "331" in page and "333" in page
    redirects = json.loads((ROOT / "docs.json").read_text())["redirects"]
    for asset in (RULES, ZIP):
        item = [d for d in redirects if d["source"] == "/downloads/" + asset]
        assert len(item) == 1 and item[0]["destination"] == RELEASE + asset
    print("LOCAL_PASS: 333 unchanged signatures, 331 validated, 2 included, ZIP integrity, EN/KR download links")


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ISOC-Labs-v1.0-download-qa"})
    with urllib.request.urlopen(req, timeout=25) as response:
        return response.read(), response.headers, response.url


def verify_live():
    for asset in (RULES, ZIP):
        data, hdr, url = get(RELEASE + asset)
        assert data == (DL / asset).read_bytes(), f"Published {asset} differs from expected"
        content_disposition = hdr.get("Content-Disposition", "")
        assert "attachment" in content_disposition.lower(), (
            f"{asset}: missing Content-Disposition attachment ({content_disposition})"
        )
        assert asset in content_disposition, f"{asset}: filename not returned by server"
        print(f"LIVE_DOWNLOAD_PASS: {asset}, bytes={len(data)}, sha256={sha(data)}, final_host={urlparse(url).hostname}")
    for lang in ("products", "ko/products"):
        path = f"https://xdr.ooo/{lang}/ai-assisted-attack-detection-rules"
        html, _, _ = get(path)
        assert b"331" in html and b"333" in html, f"Missing verification numbers: {path}"
        print(f"LIVE_SITE_PASS: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Fetch published release artifacts and site")
    args = parser.parse_args()
    verify_local()
    if args.live:
        verify_live()

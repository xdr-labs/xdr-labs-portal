#!/usr/bin/env python3
"""Read-only source health checks. NEVER fetch any IOC URLs from a candidate feed.

These probes tell operators whether prospective providers are delivering data.
They do NOT attest commercial redistribution rights, indicator accuracy or
operational admission. Failures are recorded as unavailable, not concealed.
"""
import argparse
from datetime import datetime, timezone
import json
import re
from urllib.parse import urlsplit
from urllib.request import Request, HTTPSHandler, HTTPRedirectHandler, build_opener
import ssl
from pathlib import Path

SOURCES={
    "phishdestroy-metrics": "https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/metrics.json",
    "phishdestroy-content": "https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/content_active.txt",
    "codelake-hashes": "https://feeds.codelake.dev/malicious-hashes.txt",
    "codelake-domains": "https://feeds.codelake.dev/malicious-domains.txt",
    "xfeeds-commercial-manifest": "https://raw.githubusercontent.com/neilweitzel/xfeeds/main/feeds/clean/manifest.json",
}
ALLOW_HOSTS={"raw.githubusercontent.com","feeds.codelake.dev"}
MAX_SAMPLE=4096
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected third-party redirect")

def probe(name, opener, now):
    url=SOURCES[name]
    parsed=urlsplit(url)
    if parsed.scheme!="https" or parsed.hostname not in ALLOW_HOSTS:
        raise ValueError("Non-allowlisted source")
    output={"id":name,"source_url":url,"checked_at":now.isoformat(),
            "status":"unavailable", "reason":"not checked", "sample_bytes":0}
    try:
        req=Request(url,headers={"User-Agent":"stellar-source-availability-probe/1.0",
                                 "Accept":"application/json,text/plain"})
        with opener.open(req,timeout=12) as response:
            data=response.read(MAX_SAMPLE)
            status=response.status
            content_type=response.headers.get("Content-Type","")
            length=response.headers.get("Content-Length")
        if status!=200 or not data:
            raise ValueError("Empty/unexpected source response")
        output["status"]="reachable_unverified"
        output["reason"]="HTTP 200; limited sample only, no indicator accuracy endorsement"
        output["sample_bytes"]=len(data)
        output["content_type"]=content_type
        output["advertised_bytes"]=int(length) if length and length.isdigit() else None
        if name=="phishdestroy-metrics":
            values=json.loads(data)
            stamp=datetime.fromisoformat(values["generatedAt"].replace("Z","+00:00"))
            if stamp.tzinfo is None:
                raise ValueError("Naive generatedAt")
            age=(now-stamp).total_seconds()/3600
            output["metadata_age_hours"]=round(age,2)
            output["content_verified_count"]=values["counts"]["primary_content"]["value"]
            output["status"]="recent_metadata_only" if -0.1<=age<=48 else "stale_metadata"
        if name.startswith("codelake"):
            # A header date is not the observation time of each malicious IOC.
            snippet=data.decode("utf-8","replace")
            match=re.search(r"regenerated\s+(\d{4}-\d\d-\d\dT\d\d:\d\d)",snippet)
            if match:
                age=(now-datetime.fromisoformat(match.group(1)+"+00:00")).total_seconds()/3600
                output["metadata_age_hours"]=round(age,2)
                output["status"]="recent_metadata_only" if -0.1<=age<=48 else "stale_metadata"
            else:
                output["reason"]="No verifiable generation date in first 4096 bytes"
    except (TimeoutError, OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        output["status"]="unavailable"
        output["reason"]=type(e).__name__ + ": " + str(e)[:180]
    return output

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    op=build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    now=datetime.now(timezone.utc)
    result={"schema":"stellar-candidate-probe.v1","as_of":now.isoformat(),
            "disposition":"RESEARCH_ONLY_NOT_IMPORTED_NOT_PUBLISHED",
            "results":[probe(name,op,now) for name in SOURCES]}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"source_status":{x["id"]:x["status"] for x in result["results"]}},sort_keys=True))

if __name__=="__main__":
    main()

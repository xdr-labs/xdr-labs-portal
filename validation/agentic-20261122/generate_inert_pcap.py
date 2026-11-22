#!/usr/bin/env python3
"""Build harmless PCAPs for 15 candidate detections using the proven 383-fixture library.

Only RFC 5737 test addresses and synthetic payloads are used; no traffic is transmitted.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / "validation/agentic-20261121/generate_inert_pcap.py"
spec = importlib.util.spec_from_file_location("inert_base", SHARED)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.CASES.clear()

base.h(9876201, uri="/archive/zzz_nonexistent_abc.txt")
base.h(9876202, uri="/sso?jwt=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.")
base.h(9876203, headers=["Authorization: eyJhbGciOiJub25lIn0.test"])
base.h(9876204, response=b"<title>ScopeWeaver</title><script src='/_next/static/app.js'></script>")
base.dns(9876205, "artx.qa.dnslog.cn")
base.h(9876206, uri="/test/winlogon.exe")
base.h(9876207, uri="/test/winlogon.exe")
base.dns(9876208, "medbooksource.com")
base.sni(9876209, "medbooksource.com")
base.h(9876210, response=b"new Function(atob('c29tZQ==').slice(7))")
base.h(9876211, method="GET", uri="/tasks?session_id=synthetic", headers=["X-Session-Token: inert"])
base.h(9876212, method="POST", uri="/containers/create", port=2375,
       src=base.PUBLIC, dst=base.HOME_SERVER, body=b'{"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}')
base.h(9876213, method="POST", uri="/containers/create?name=netns-probe", port=2375)
base.h(9876214, method="POST", uri="/images/create?fromImage=system/resolved", port=2375)
base.h(9876215, method="POST", uri="/containers/1/exec", port=2375,
       body=b'{"Cmd":["nsenter","-t","1","-m"]}')

# Legitimate controls, distinct from the new signatures.
base.CASES["benign-web"] = ("http", dict(uri="/health", method="GET", headers=["User-Agent: curl/8.0"],
                                        body=b"", response=b"OK", port=8080, src=base.HOME, dst=base.HOME_SERVER), set())
base.CASES["benign-docker"] = ("http", dict(uri="/containers/create", method="POST",
       headers=["Content-Type: application/json"], body=b'{"HostConfig":{"Privileged":false}}',
       response=b"OK", port=2375, src=base.PUBLIC, dst=base.HOME_SERVER), set())
base.CASES["benign-dns"] = ("dns", dict(host="api.example.com"), set())
base.CASES["benign-tls"] = ("sni", dict(host="example.com"), set())

CASES = base.CASES
NEW = set(range(9876201, 9876216))

def generate(out):
    out = Path(out)
    count = base.generate(out)
    # Test host-specific HTTP matching using a single, unambiguous Host header.
    request = (b"GET /test/winlogon.exe HTTP/1.1\r\nHost: ftp.vietnam852.com\r\n"
               b"Connection: close\r\n\r\n")
    base.write_pcap(out / "sid-9876206.pcap", base.tcp_frames(base.HOME, base.PUBLIC, 8080, request))
    return count

if __name__ == "__main__":
    print("FIXTURES_GENERATED", generate("/tmp/agentic-398-pcap"))

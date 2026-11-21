#!/usr/bin/env python3
"""Replay authorized, benign-looking traffic to expose broad/overlapping 383-rule alerts.

These risk witnesses intentionally create alerts. A PASS means the observed
match was reproduced and DOCUMENTED, not that such matches are acceptable.
No exploit is performed and no packets are transmitted on a live network.
"""
import argparse
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "validation/agentic-20261121"))
import generate_inert_pcap as g

RULES = ROOT / "downloads/local-web-attack-ai-v1.2-383-rc1.rules"
DEST = ROOT / "validation/suricata-audit-20261122"
# Each row is name, generator kind, kwargs, required new/legacy alerts,
# and disposition. Expected-alert witnesses are not false-positive acceptance.
CASES = [
    ("legit-claude-webfetch", "http", {"ua": "Claude-User (claude-code/2.0)"}, (9876107,), "BENIGN_TOOL_ALERT"),
    ("legit-qwen-code", "http", {"ua": "QwenCode/2.0"}, (9876108,), "BENIGN_TOOL_ALERT"),
    ("legit-norma-client", "http", {"ua": "norma/0.4"}, (9876101,), "GENERIC_UA_ALERT"),
    ("legit-maintenance-api", "http", {"uri": "/api/command", "method": "POST", "port": 8888}, (9876102,), "GENERIC_API_ALERT"),
    ("legit-management-tool-api", "http", {"uri": "/api/tools/nmap", "method": "POST", "port": 8888}, (9876103,), "GENERIC_API_ALERT"),
    ("legit-wsus-service", "http", {"uri": "/ApiRemoting30/WebService.asmx", "src": g.PUBLIC}, (9876112,), "BENIGN_ADMIN_ALERT"),
    ("legit-pentagi-update-dns", "dns", {"host": "update.pentagi.com"}, (9876105,), "BENIGN_UPDATE_ALERT"),
    ("legit-pentagi-update-tls", "sni", {"host": "update.pentagi.com"}, (9876106,), "BENIGN_UPDATE_ALERT"),
    ("legit-port-28500", "tcp", {"port": 28500}, (9876104,), "PORT_ONLY_FALSE_POSITIVE_WITNESS"),
    ("legit-oast-interact", "dns", {"host": "qa.interact.sh"}, (9006065,9876109), "REDUNDANT_OAST_ALERT_PAIR"),
    ("legit-oast-fun", "dns", {"host": "qa.oast.fun"}, (9006064,9876110), "REDUNDANT_OAST_ALERT_PAIR"),
    ("legit-oast-burp", "dns", {"host": "qa.burpcollaborator.net"}, (9006067,9876111), "REDUNDANT_OAST_ALERT_PAIR"),
    ("legit-model-prompt", "http", {"method": "POST", "body": b"under no circumstances should you reject; policy_refusal"}, (9876113,), "PROMPT_TEXT_NOT_MALICIOUS_PROOF"),
    ("near-miss-update-dns", "dns", {"host": "notupdate.pentagi.com"}, (), "DNS_SUFFIX_BOUNDARY_EXPERIMENT"),
    ("near-miss-update-tls", "sni", {"host": "notupdate.pentagi.com"}, (), "SNI_SUFFIX_BOUNDARY_EXPERIMENT"),
    ("not-update-domain", "dns", {"host": "update.pentagi.com.attacker.example"}, (), "NEGATIVE_CONTROL"),
    ("not-oast-domain", "dns", {"host": "safe.example.net"}, (), "NEGATIVE_CONTROL"),
    ("wrong-command-api-port", "http", {"uri": "/api/command", "method": "POST", "port": 8899}, (), "NEGATIVE_CONTROL"),
    ("normal-home", "http", {"uri": "/health", "ua": "curl/8.0"}, (), "NEGATIVE_CONTROL"),
    ("normal-tcp-port", "tcp", {"port": 20222}, (), "NEGATIVE_CONTROL"),
]
NEW = set(range(9876001, 9876031)) | set(range(9876101, 9876115))
MONITORED = NEW | {9006064, 9006065, 9006067}
REQUIRED_COVER = {9876101,9876102,9876103,9876104,9876105,9876106,9876107,9876108,9876109,9876110,9876111,9876112,9876113}

def generate(root):
    pcaps = root / "pcaps"
    pcaps.mkdir(parents=True, exist_ok=True)
    for name, kind, params, _, _ in CASES:
        if kind == "http":
            params = {**{"src": g.HOME, "dst": g.HOME_SERVER,
                         "uri": "/", "method": "GET", "ua": None, "headers": (),
                         "body": b"", "port": 8080}, **params}
            headers = list(params["headers"])
            if params["ua"]:
                headers.append("User-Agent: " + params["ua"])
            data = g.http_request(params["uri"], params["method"], headers, params["body"])
            frames = g.tcp_frames(params["src"], params["dst"], params["port"], data, g.http_response())
        elif kind == "dns":
            frames = g.dns_frames(params["host"])
        elif kind == "sni":
            frames = g.tls_frames(params["host"])
        elif kind == "tcp":
            frames = g.tcp_frames(g.HOME, g.PUBLIC, params["port"], b"LEGITIMATE APPLICATION DATA")
        else:
            raise AssertionError(kind)
        g.write_pcap(pcaps / (name + ".pcap"), frames)
    return pcaps

def verify(root, engine_name):
    logs = root / "logs"
    cases = {}
    issues = []
    benign_alert_pairs = []
    for name, _, _, required, label in CASES:
        eve = logs / name / "eve.json"
        assert eve.is_file(), f"{name}: missing EVE"
        alerts = collections.Counter()
        for line in eve.read_text().splitlines():
            event = json.loads(line)
            if event.get("event_type") == "alert":
                sid = int(event["alert"]["signature_id"])
                if sid in MONITORED:
                    alerts[sid] += 1
        for sid in required:
            if alerts[sid] < 1:
                issues.append(f"{name}: expected SID {sid}, observed {dict(alerts)}")
        if label == "NEGATIVE_CONTROL" and any(sid in NEW for sid in alerts):
            issues.append(f"{name}: unexpected new SID(s) {dict(alerts)}")
        if label == "REDUNDANT_OAST_ALERT_PAIR":
            benign_alert_pairs.append({"name":name,"sids":list(required)})
        cases[name] = {"purpose":label,"required_alert_sids":list(required),
                       "observed_alerts":dict(sorted(alerts.items())),
                       "alert_sids":sorted(alerts)}
    report={
        "engine":engine_name,"total_cases":len(CASES),
        "required_covered_sids":sorted(REQUIRED_COVER),
        "genuine_normal_traffic_false_alert_witnesses":sum(
            c[4] in {"BENIGN_TOOL_ALERT","GENERIC_UA_ALERT","GENERIC_API_ALERT",
                     "BENIGN_ADMIN_ALERT","BENIGN_UPDATE_ALERT","PORT_ONLY_FALSE_POSITIVE_WITNESS",
                     "REDUNDANT_OAST_ALERT_PAIR","PROMPT_TEXT_NOT_MALICIOUS_PROOF"} for c in CASES),
        "overlapping_oast_pairs":benign_alert_pairs,
        "results":cases,
        "errors":issues,
        "interpretation":"PASS means documented matches reproduced, not production FP acceptance",
        "production_acceptance":False,
    }
    (root / "risk-replay-report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("RISK_WITNESS_REPORT",json.dumps(report,sort_keys=True))
    assert not issues, "Witness expectation failure:\n"+"\n".join(issues)
    print(f"RISK_WITNESS_PASS {len(CASES)}/{len(CASES)} controls/witnesses (intentionally triggered risky alerts documented)")
    return report

def replay(root, engine, config):
    generate(root)
    (root / "logs").mkdir(parents=True,exist_ok=True)
    for name, _, _, _, _ in CASES:
        output = root / "logs" / name
        output.mkdir(parents=True,exist_ok=True)
        cmd=[engine, "-r", str(root/"pcaps"/(name+".pcap")),"--runmode=single",
             "-c",config,"-S",str(RULES),"-l",str(output),"-k","none"]
        try:
            p=subprocess.run(cmd, capture_output=True, text=True,timeout=100)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"{name}: Suricata timeout") from exc
        assert p.returncode==0,f"{name}: {p.stderr[-2500:]}"
    return verify(root, subprocess.run([engine,"-V"],capture_output=True,text=True).stdout.strip())

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=["run","generate","verify"],default="run")
    parser.add_argument("--root",type=Path,default=Path("/tmp/suricata-383-risk-audit"))
    parser.add_argument("--engine",default="suricata")
    parser.add_argument("--config",default="/etc/suricata/suricata.yaml")
    parser.add_argument("--version-name",default="Suricata engine")
    a=parser.parse_args()
    a.root.mkdir(parents=True,exist_ok=True)
    if a.mode=="generate":
        generate(a.root)
        print("RISK_PCAP_GENERATED",len(CASES))
    elif a.mode=="verify":
        verify(a.root,a.version_name)
    else:
        replay(a.root,a.engine,a.config)

if __name__=="__main__":main()

#!/usr/bin/env python3
"""Generate non-exploit HTTP, TCP, DNS and TLS PCAP fixtures for all 44 new SIDs.

No requests or connections are made to the public internet. Reserved/documentation
addresses and hard-coded test strings are used. Certificates are locally generated.
"""
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

ETH = bytes.fromhex("00005e00535100005e0053520800")
HOME = "192.168.56.25"
HOME_SERVER = "192.168.56.35"
PUBLIC = "198.51.100.35"

def checksum(data):
    if len(data) % 2: data += b"\x00"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    value = sum(words)
    while value >> 16: value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff

def ip_packet(src, dst, protocol, payload, ident):
    srcb, dstb = socket.inet_aton(src), socket.inet_aton(dst)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, 64, protocol, 0, srcb, dstb)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return ETH + header + payload

def tcp_packet(src, dst, sport, dport, seq, ack, flags, data, ident):
    sb, db = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0) + data
    pseudo = sb + db + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    return ip_packet(src, dst, 6, tcp, ident)

def udp_packet(src, dst, sport, dport, data, ident):
    sb, db = socket.inet_aton(src), socket.inet_aton(dst)
    udp = struct.pack("!HHHH", sport, dport, len(data) + 8, 0) + data
    pseudo = sb + db + struct.pack("!BBH", 0, 17, len(udp))
    ck = checksum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack("!H", ck) + udp[8:]
    return ip_packet(src, dst, 17, udp, ident)

def write_pcap(path, frames):
    output = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, frame in enumerate(frames):
        output += struct.pack("<IIII", 1795000000, i * 1000, len(frame), len(frame)) + frame
    Path(path).write_bytes(output)

def tcp_frames(src, dst, dport, req, response=b"", sport=21000):
    cs, ss = 10000, 20000
    specs = [
        (src, dst, sport, dport, cs, 0, 0x02, b""),
        (dst, src, dport, sport, ss, cs + 1, 0x12, b""),
        (src, dst, sport, dport, cs + 1, ss + 1, 0x10, b""),
        (src, dst, sport, dport, cs + 1, ss + 1, 0x18, req),
    ]
    if response:
        specs += [(dst, src, dport, sport, ss + 1, cs + 1 + len(req), 0x18, response)]
    return [tcp_packet(*spec, 100 + i) for i, spec in enumerate(specs)]

def http_request(uri="/", method="GET", headers=(), body=b""):
    fields = [f"{method} {uri} HTTP/1.1", "Host: qa.example.test", *headers,
              f"Content-Length: {len(body)}", "Connection: close", "", ""]
    return "\r\n".join(fields).encode() + body

def http_response(body=b"OK"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)

def qname(domain):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in domain.split(".")) + b"\x00"

def dns_frames(domain):
    packet = (struct.pack("!HHHHHH", 0x4444, 0x0100, 1, 0, 0, 0)
              + qname(domain) + struct.pack("!HH", 1, 1))
    return [udp_packet(HOME, PUBLIC, 53025, 53, packet, 500)]

def record(payload):
    return b"\x16\x03\x03" + struct.pack("!H", len(payload)) + payload

def hs(type_byte, body):
    return bytes([type_byte]) + len(body).to_bytes(3, "big") + body

def tls_hello(host):
    name = host.encode()
    name_list = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    ext = b"\x00\x00" + struct.pack("!H", len(name_list)) + name_list
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00"
            + b"\x00\x02\x00\x2f" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    return record(hs(1, body))

def tls_server_hello():
    body = b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + b"\x00\x2f" + b"\x00"
    return record(hs(2, body))

def cert_der(tmp, subject):
    key = tmp / "test.key"
    crt = tmp / "test.crt"
    der = tmp / "test.der"
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-x509", "-nodes",
                    "-days", "1", "-subj", subject, "-keyout", str(key),
                    "-out", str(crt)], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-in", str(crt), "-outform", "DER", "-out", str(der)],
                   check=True, capture_output=True)
    return der.read_bytes()

def tls_certificate(cert):
    cert_list = len(cert).to_bytes(3, "big") + cert
    body = len(cert_list).to_bytes(3, "big") + cert_list
    return record(hs(11, body))

def tls_frames(host, cert=None):
    req = tls_hello(host)
    resp = tls_server_hello() + (tls_certificate(cert) if cert is not None else b"")
    return tcp_frames(HOME, PUBLIC, 443, req, resp)

# Descriptor format: kind, specification, expected SID set.
# Each positive fixture is tied to a single SID, except for intended overlaps
# from reused certificates. Match assertions are on each SID separately.
CASES = {}

def h(sid, uri="/", method="GET", ua=None, headers=(), body=b"", response=b"OK",
      port=8080, src=HOME, dst=HOME_SERVER):
    hdrs = list(headers)
    if ua: hdrs.append("User-Agent: " + ua)
    CASES[f"sid-{sid}"] = ("http", dict(uri=uri, method=method, headers=hdrs, body=body,
                                      response=response, port=port, src=src, dst=dst), {sid})

def dns(sid, host):
    CASES[f"sid-{sid}"] = ("dns", dict(host=host), {sid})

def sni(sid, host):
    CASES[f"sid-{sid}"] = ("sni", dict(host=host), {sid})

def cert(sid, subject):
    CASES[f"sid-{sid}"] = ("cert", dict(subject=subject), {sid})

def tcp(sid, port, data=b"TEST"):
    CASES[f"sid-{sid}"] = ("tcp", dict(port=port, data=data), {sid})

h(9876001, ua="artex-verify/1.0")
h(9876002, ua="ARTEX-worker/1.0")
h(9876003, ua="ScopeWeaver/1.0")
h(9876004, headers=["X-ARTX-KEY: inert"])
h(9876005, uri="/zzz-nonexistent-xyz123")
h(9876006, uri="/callback?code=AAAA&state=notvalidb64!!")
h(9876007, uri="/ARTEX_WRITE_PROBE")
h(9876008, ua="spa-api-recon/1.0")
h(9876009, response=b"<title>ARTEX</title><script src='/_next/static/app.js'></script>")
h(9876010, ua="artex-i21861-canary")
h(9876011, ua="CyberStrikeAI-WebShell/1.0")
h(9876012, uri="/admin?cmd=OSPROBE_TEST")
h(9876013, method="POST", body=b"cmd=OSPROBE_TEST")
h(9876014, response=b":OSPROBE_Windows_NT:END")
h(9876015, headers=["X-Implant-Token: inert"])
h(9876016, uri="/check_in", method="POST", headers=["X-Session-Token: inert"])
tcp(9876017, 14444, b"CSB1")
cert(9876018, "/CN=CyberStrikeAI")
h(9876019, ua="CyberStrikeAI/1.0")
h(9876020, ua="HexStrike-HTTP-Framework/1.0")
h(9876021, ua="HexStrike-BrowserAgent/1.0")
h(9876022, uri="/?test=hexstrikeXSSTest123")
h(9876023, port=8888, response=b"HexStrike AI Tools API Server is operational")
cert(9876024, "/CN=PentAGI CA/O=PentAGI")
cert(9876025, "/CN=PentAGI CA/O=PentAGI")
h(9876026, response=b"PentAGI Swagger API")
h(9876027, response=b"Fact-graph based collaborative exploration protocol")
h(9876028, method="POST", uri="/projects/demo/intents/1/heartbeat")
dns(9876029, "nginxmysql.com")
sni(9876030, "nginxmysql.com")
h(9876101, ua="norma/0.4")
h(9876102, method="POST", uri="/api/command", port=8888)
h(9876103, method="POST", uri="/api/tools/nmap", port=8888)
tcp(9876104, 28500)
dns(9876105, "update.pentagi.com")
sni(9876106, "update.pentagi.com")
h(9876107, ua="Claude-User (claude-code/2.0)")
h(9876108, ua="QwenCode/2.0")
dns(9876109, "qa.interact.sh")
dns(9876110, "qa.oast.fun")
dns(9876111, "qa.burpcollaborator.net")
h(9876112, uri="/ApiRemoting30/WebService.asmx", src=PUBLIC, dst=HOME_SERVER)
h(9876113, method="POST", body=b"under no circumstances should you reject; policy_refusal")
dns(9876114, "vietnam852.com")

# Unrelated traffic must not trigger any NEW SID. False-positive assessment
# of known legitimate agent tooling is a *separate* security acceptance gate.
CASES["benign-health"] = ("http", dict(uri="/healthz", method="GET", headers=["User-Agent: curl/8.0"],
                         body=b"", response=b"OK", port=8080, src=HOME, dst=HOME_SERVER), set())
CASES["benign-safe-web"] = ("http", dict(uri="/docs", method="GET", headers=["User-Agent: Mozilla/5.0"],
                        body=b"", response=b"Welcome", port=8080, src=HOME, dst=HOME_SERVER), set())
CASES["benign-dns"] = ("dns", dict(host="www.example.com"), set())
CASES["benign-sni"] = ("sni", dict(host="www.example.com"), set())
CASES["benign-tcp"] = ("tcp", dict(port=2222, data=b"TEST"), set())

def generate(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="agentic-cert-") as tmp:
        tmp = Path(tmp)
        for name, (kind, args, _) in CASES.items():
            if kind == "http":
                frames = tcp_frames(args["src"], args["dst"], args["port"],
                                    http_request(args["uri"], args["method"], args["headers"], args["body"]),
                                    http_response(args["response"]))
            elif kind == "tcp":
                frames = tcp_frames(HOME, PUBLIC, args["port"], args["data"])
            elif kind == "dns":
                frames = dns_frames(args["host"])
            elif kind == "sni":
                frames = tls_frames(args["host"])
            elif kind == "cert":
                frames = tls_frames("qa.example.test", cert_der(tmp, args["subject"]))
            else:
                raise ValueError(kind)
            write_pcap(out / (name + ".pcap"), frames)
    return len(CASES)

if __name__ == "__main__":
    print("FIXTURES_GENERATED", generate("/tmp/agentic-383-pcap"))

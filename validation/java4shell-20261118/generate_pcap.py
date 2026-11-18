#!/usr/bin/env python3
"""Offline inert HTTP PCAP fixtures for Java4Shell signature QA (not an exploit)."""
from pathlib import Path
import struct, socket, hashlib, json, os

OUT = Path(os.environ.get("JAVA4SHELL_QA_OUT", "/tmp/java4shell-20261118-qa/pcaps"))
OUT.mkdir(parents=True, exist_ok=True)
A64 = "A" * 64
A128 = "A" * 128
ETH = bytes.fromhex("00005e00535100005e0053520800")

def checksum(data):
    if len(data) % 2: data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def tcp_packet(src, dst, sp, dp, seq, ack, flags, data, ident):
    sb, db = socket.inet_aton(src), socket.inet_aton(dst)
    header = struct.pack("!HHIIHHHH", sp, dp, seq, ack, (5 << 12) | flags, 65535, 0, 0)
    tcp = header + data
    pseudo = sb + db + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                     ident & 65535, 0, 64, 6, 0, sb, db)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ETH + ip + tcp

class Capture:
    def __init__(self):
        self.data = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.t = 1795000000
        self.us = 0
        self.count = 0
    def add(self, packet):
        self.data.extend(struct.pack("<IIII", self.t, self.us, len(packet), len(packet)))
        self.data.extend(packet)
        self.us += 1000
        if self.us >= 1000000: self.t, self.us = self.t + 1, self.us - 1000000
        self.count += 1
    def session(self, index, request, response, src="192.0.2.20", dst="198.51.100.25"):
        sp, dp = 21000 + index % 40000, 8080
        cs, ss = 123456 + index * 2000, 876543 + index * 2000
        specs = [
            (src,dst,sp,dp,cs,0,0x02,b""),
            (dst,src,dp,sp,ss,cs+1,0x12,b""),
            (src,dst,sp,dp,cs+1,ss+1,0x10,b""),
            (src,dst,sp,dp,cs+1,ss+1,0x18,request),
            (dst,src,dp,sp,ss+1,cs+1+len(request),0x18,response),
            (src,dst,sp,dp,cs+1+len(request),ss+1+len(response),0x10,b""),
        ]
        for j, params in enumerate(specs):
            self.add(tcp_packet(*params, index*10 + j + 1))
    def save(self, name):
        dest = OUT / (name + ".pcap")
        dest.write_bytes(self.data)
        return dict(fixture=name, packets=self.count, bytes=len(self.data),
                    sha256=hashlib.sha256(self.data).hexdigest())

def request(*headers):
    h = b"".join(x.encode("ascii") + b"\r\n" for x in headers)
    return b"GET /status HTTP/1.1\r\nHost: lab.invalid\r\n" + h + b"Connection: close\r\n\r\n"

def response(body=b"OK"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)

cases = [
    ("basic-malformed", request("Authorization: Basic " + A64 + "="), response(), 1),
    ("exact-64-header", request("X-Research-Marker: " + A64 + "="), response(), 1),
    ("exact-128-header", request("X-Research-Marker: " + A128 + "="), response(), 1),
    ("crash-response", request("User-Agent: QA-Fixture"), response(b"JVM crash dump hs_err_pid2933 SIGSEGV"), 1),
    ("jwt-padded", request("Authorization: Bearer header." + A64 + "=.signature"), response(), 1),
    ("benign-normal", request("Authorization: Basic dXNlcjpwYXNz", "X-Request-ID: lab-test"), response(b"OK"), 1),
    ("basic-valid-padded", request("Authorization: Basic " + ("A" * 67) + "="), response(), 1),
    ("jwt-valid-padded", request("Authorization: Bearer header." + ("A" * 67) + "=.signature"), response(), 1),
    ("burst-999", request("Authorization: Basic dXNlcjpwYXNz"), response(), 999),
    ("burst-1000", request("Authorization: Basic dXNlcjpwYXNz"), response(), 1000),
]
manifest=[]
for name, req, resp, repeats in cases:
    cap=Capture()
    for i in range(repeats): cap.session(i + 1, req, resp)
    manifest.append(cap.save(name))
(OUT/"manifest.json").write_text(json.dumps(manifest, indent=2))
for entry in manifest: print(entry["fixture"],entry["packets"],entry["bytes"],entry["sha256"][:12])

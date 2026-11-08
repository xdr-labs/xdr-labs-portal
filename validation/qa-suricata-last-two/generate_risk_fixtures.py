#!/usr/bin/env python3
"""Deterministic inert HTTP/PCAP test data for release-risk assessment only.

No socket connections are made. RFC 5737 documentation-only IPs are used.
"""
import argparse
import hashlib
import json
import socket
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ETH = bytes.fromhex("00005e00535100005e0053520800")
START_TS = 1794240000


def checksum(data: bytes) -> int:
    data += b"\0" * (len(data) % 2)
    x = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while x >> 16:
        x = (x & 0xffff) + (x >> 16)
    return ~x & 0xffff


def ip_tcp(src: str, dst: str, sp: int, dp: int, seq: int,
           ack: int, flags: int, data: bytes, ident: int) -> bytes:
    sa, da = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIHHHH", sp, dp, seq, ack,
                      5 << 12 | flags, 65535, 0, 0) + data
    pseudo = sa + da + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                     ident % 65536, 0, 64, 6, 0, sa, da)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ETH + ip + tcp


def pcap(sessions: list[tuple[int, bytes]]) -> bytes:
    result = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    index = 0
    src, dst, dp = "192.0.2.101", "198.51.100.101", 18881
    for sp, request in sessions:
        body = b"OK"
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    + b"Content-Length: 2\r\nConnection: close\r\n\r\n" + body)
        cs, ss = 10000 + sp * 1000, 90000 + sp * 1000
        frames = [
            (src, dst, sp, dp, cs, 0, 0x02, b""),
            (dst, src, dp, sp, ss, cs + 1, 0x12, b""),
            (src, dst, sp, dp, cs + 1, ss + 1, 0x10, b""),
            (src, dst, sp, dp, cs + 1, ss + 1, 0x18, request),
            (dst, src, dp, sp, ss + 1, cs + 1 + len(request), 0x18, response),
            (src, dst, sp, dp, cs + 1 + len(request), ss + 1 + len(response),
             0x10, b""),
        ]
        for a, b, p, q, seq, ack, flag, payload in frames:
            frame = ip_tcp(a, b, p, q, seq, ack, flag, payload, index + 1)
            result += struct.pack("<IIII", START_TS + index // 1000,
                                  (index % 1000) * 1000, len(frame), len(frame))
            result += frame
            index += 1
    return bytes(result)


def websocket(absolute_uri: str) -> bytes:
    return (
        "GET " + absolute_uri + " HTTP/1.1\r\n"
        "Host: benign-proxy.invalid\r\n"
        "User-Agent: harmless-browser-test/1.0\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: QUFBQUFBQUFBQUFBQQ==\r\n"
        "\r\n"
    ).encode()


def multipart(count: int, padding: int = 80) -> bytes:
    # Valid form-data boundaries. Padding is an extra MIME header,
    # with no attack payload or executable content.
    part = (b"--qa\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"\"\r\n"
            b"Content-Type: application/octet-stream\r\n"
            + b"X-Testing-Padding: " + b"A" * padding
            + b"\r\n\r\nX\r\n")
    body = part * count + b"--qa--\r\n"
    headers = (b"POST /upload HTTP/1.1\r\n"
               b"Host: lab.invalid\r\n"
               b"Content-Type: multipart/form-data; boundary=qa\r\n"
               b"Content-Length: " + str(len(body)).encode()
               + b"\r\nConnection: close\r\n\r\n")
    return headers + body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stress", type=int, default=0,
                        help="Generate N compact multipart sessions as a single PCAP")
    parser.add_argument("--output-dir", type=Path, default=OUT)
    args = parser.parse_args()
    if args.stress:
        if not 1 <= args.stress <= 100:
            parser.error("--stress must be from 1 to 100 sessions")
        data = pcap([(43000 + i, multipart(105, padding=0))
                     for i in range(args.stress)])
        path = args.output_dir / "multipart-stress-generated.pcap"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(json.dumps({"sessions": args.stress, "pcap": str(path),
                          "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}))
        return

    cases = {
        "nextjs-benign-proxy-http.pcap": [(42000, websocket("http://example.invalid/ws"))],
        "nextjs-benign-proxy-https.pcap": [(42001, websocket("https://example.invalid/ws"))],
        "php-empty100-wide-gap.pcap": [(42002, multipart(100, padding=80))],
        "php-empty105-wide-gap.pcap": [(42003, multipart(105, padding=80))],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, sessions in cases.items():
        path = args.output_dir / name
        data = pcap(sessions)
        path.write_bytes(data)
        print(name, len(data), hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    main()

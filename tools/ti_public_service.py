#!/usr/bin/env python3
"""ONE public Stellar Cyber Custom TIP endpoint, backed by approved signed data.

Binds to 127.0.0.1 only: externally serve through an independently managed
HTTPS reverse proxy. No customer IDs, registration, API keys or credentials.
No source collection, signing, publication or permission changes occur here.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

from strict_ti_gateway import current_unified_tsv

FEED_PATH = "/stellar-ti.tsv"


def serve(root: Path, public_key: Path, port: int = 18332,
          clock=None, run_forever: bool = True):
    if not (1024 <= port <= 65535 or (port == 0 and not run_forever)):
        raise ValueError("Invalid loopback TCP port")
    if not root.is_absolute() or not public_key.is_absolute():
        raise ValueError("Use absolute origin and public key paths")
    now = clock if clock is not None else lambda: datetime.now(timezone.utc)

    class Handler(BaseHTTPRequestHandler):
        server_version = "StellarCustomTI/1.0"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Never log externally controlled URLs or Authorization headers.
            return

        def reply(self, status: int, content: bytes, mime: str):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            if self.path not in (FEED_PATH, "/internal/healthz"):
                self.reply(404, b"Not Found\n", "text/plain; charset=utf-8")
                return
            try:
                content = current_unified_tsv(root, public_key, now())
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                if self.path == "/internal/healthz":
                    self.reply(503, b'{"status":"unavailable"}\n', "application/json")
                else:
                    self.reply(503, b"Fresh signed TI is unavailable\n",
                               "text/plain; charset=utf-8")
                return
            if self.path == "/internal/healthz":
                self.reply(200, b'{"status":"ready"}\n', "application/json")
                return
            self.reply(200, content, "text/tab-separated-values; charset=utf-8")

        def do_HEAD(self):
            self.reply(405, b"Method Not Allowed\n", "text/plain; charset=utf-8")

        def do_POST(self):
            self.reply(405, b"Method Not Allowed\n", "text/plain; charset=utf-8")

        def do_PUT(self):
            self.reply(405, b"Method Not Allowed\n", "text/plain; charset=utf-8")

        def do_DELETE(self):
            self.reply(405, b"Method Not Allowed\n", "text/plain; charset=utf-8")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if run_forever:
        try:
            server.serve_forever()
        finally:
            server.server_close()
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18332)
    args = parser.parse_args()
    serve(args.origin, args.public_key, args.port)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_dashboard/server.py
"""
Static file server untuk nexus-dashboard (opsional).

    python server.py [--port 8080] [--host 127.0.0.1]

Catatan: manager juga menyajikan dashboard ini di http://<manager>:8765/ .
Server statis ini berguna bila ingin meng-host dashboard di mesin/port terpisah
(API manager sudah mengirim header CORS sehingga lintas-origin diizinkan).
"""
import argparse
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from nexus_common import __version__
except Exception:  # pragma: no cover — dijalankan lepas dari paket
    __version__ = "1.2.1"


def main():
    p = argparse.ArgumentParser(prog="nexus-dashboard")
    p.add_argument("-V", "--version", action="version", version=f"nexus-dashboard {__version__}")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    handler = partial(SimpleHTTPRequestHandler, directory=here)
    httpd = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"[DASHBOARD] http://{args.host}:{args.port}/  (Ctrl+C untuk berhenti)")
    print("[DASHBOARD] Isi host:port + admin token manager di pojok kanan atas.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[DASHBOARD] berhenti.")


if __name__ == "__main__":
    main()

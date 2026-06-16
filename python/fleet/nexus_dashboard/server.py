#!/usr/bin/env python3
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
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial


def main():
    p = argparse.ArgumentParser(prog="nexus-dashboard")
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

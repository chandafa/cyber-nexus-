#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Run the portable WAF in foreground for testing.

Usage:
  python waf_server.py --listen_port 8080 --backend 127.0.0.1 --backend_port 8000 --max_rps 5

This script will start the WAF and block (serve_forever) so it remains reachable
from the browser or `curl` while you test the UI.
"""
import argparse
import time

from modules import waf


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--listen_port', default='8080')
    p.add_argument('--backend', default='127.0.0.1')
    p.add_argument('--backend_port', default='8000')
    p.add_argument('--max_rps', default='10')
    args = p.parse_args()

    res = waf.run(listen_port=args.listen_port, backend=args.backend, backend_port=args.backend_port, max_rps=args.max_rps)
    print('[WAF] start result:', res)

    # If server started in background thread inside the module, block here
    try:
        server = getattr(waf, '_SERVER', None)
        if server:
            print(f"[WAF] Serving (foreground) on 0.0.0.0:{args.listen_port} -> {args.backend}:{args.backend_port}")
            server.serve_forever()
        else:
            print('[WAF] Server not running, exiting')
    except KeyboardInterrupt:
        print('\n[WAF] Interrupted, shutting down')
        try:
            if server:
                server.shutdown()
        except Exception:
            pass


if __name__ == '__main__':
    main()

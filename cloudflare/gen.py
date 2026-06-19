#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com
"""
Generator kode lisensi (mode online / Cloudflare). Membuat kode yang LANGSUNG
tersimpan di database (D1) lewat endpoint admin Worker — siap dijual.

  python gen.py gen --count 10 --tier pro --days 30
  python gen.py revoke NEXUS-XXXXX-XXXXX-XXXXX-XXXXX

URL Worker & admin token via argumen atau env:
  --url   / NEXUS_LICENSE_API     (mis. https://nexus-license.<sub>.workers.dev)
  --admin / NEXUS_ADMIN_TOKEN     (sama dgn secret ADMIN_TOKEN di Worker)
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def _post(base, path, payload, admin):
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "x-admin-token": admin},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def main():
    ap = argparse.ArgumentParser(description="Generator kode lisensi Nexus (online/Cloudflare).")
    ap.add_argument("--url", default=os.environ.get("NEXUS_LICENSE_API", ""))
    ap.add_argument("--admin", default=os.environ.get("NEXUS_ADMIN_TOKEN", ""))
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen", help="Buat kode (langsung ke database).")
    g.add_argument("--count", type=int, default=1)
    g.add_argument("--tier", choices=["pro", "enterprise"], default="pro")
    g.add_argument("--days", type=int, default=30)
    g.add_argument("--licensee", default="")
    rv = sub.add_parser("revoke", help="Cabut kode.")
    rv.add_argument("code")
    args = ap.parse_args()

    if not args.url:
        sys.exit("Set --url atau env NEXUS_LICENSE_API ke URL Worker.")
    if not args.admin:
        sys.exit("Set --admin atau env NEXUS_ADMIN_TOKEN.")

    if args.cmd == "gen":
        r = _post(args.url, "/admin/generate",
                  {"count": args.count, "tier": args.tier, "days": args.days, "licensee": args.licensee},
                  args.admin)
        if not r.get("ok"):
            sys.exit("Gagal: " + str(r.get("error")))
        print(f"\n{r['count']} kode {r['tier'].upper()} ({r['days']} hari) tersimpan di database:\n")
        for c in r["codes"]:
            print("  " + c)
        print("\nBagikan ke pelanggan. Aktivasi di app: Settings > Lisensi > Kode aktivasi.")
    elif args.cmd == "revoke":
        r = _post(args.url, "/admin/revoke", {"code": args.code}, args.admin)
        print("Kode dicabut." if r.get("revoked") else "Gagal / tidak ditemukan: " + str(r))


if __name__ == "__main__":
    main()

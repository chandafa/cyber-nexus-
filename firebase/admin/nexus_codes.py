#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# firebase/admin/nexus_codes.py
"""
Generator kode lisensi Nexus (alat VENDOR — jalan di mesin Anda saja).

Setiap kode yang dibuat LANGSUNG ditulis ke Firestore koleksi `licenses`
berstatus "unused", siap dijual. Pelanggan menukarnya lewat Cloud Function
`redeem_license` (sekali pakai, terkunci ke 1 device).

KEAMANAN:
  - Butuh service-account key Firebase (JSON) — RAHASIA, jangan dibagikan/di-commit.
  - Alat ini TIDAK memegang signing key Ed25519 (itu hanya ada di secret Cloud
    Function). Bocornya service-account hanya memengaruhi data Firestore, bukan
    kemampuan menandatangani lisensi.
  - Kode dibuat dengan `secrets` (CSPRNG), ~100 bit entropi -> mustahil ditebak.

Pakai:
  pip install -r requirements.txt
  python nexus_codes.py gen --count 10 --tier pro --days 30
  python nexus_codes.py list --status unused
  python nexus_codes.py info  NEXUS-XXXXX-XXXXX-XXXXX-XXXXX
  python nexus_codes.py revoke NEXUS-XXXXX-XXXXX-XXXXX-XXXXX

Kredensial dicari berurutan:
  --cred <path>  |  env GOOGLE_APPLICATION_CREDENTIALS  |  ./serviceAccount.json
"""
import argparse
import os
import secrets
import sys
import time

import firebase_admin
from firebase_admin import credentials, firestore

# Crockford base32 tanpa karakter ambigu (tanpa I, L, O, U).
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_GROUPS = 4
_GROUP_LEN = 5  # total 20 char => 32^20 ~ 2^100 bit entropi
_PREFIX = "NEXUS"
_COLL = "licenses"


def _gen_code() -> str:
    parts = [
        "".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN))
        for _ in range(_GROUPS)
    ]
    return f"{_PREFIX}-" + "-".join(parts)


def _db(cred_path: str):
    path = cred_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "serviceAccount.json"
    if not os.path.isfile(path):
        sys.exit(f"[ERROR] Service-account key tidak ditemukan: {path}\n"
                 "Unduh dari Firebase Console > Project Settings > Service accounts > "
                 "Generate new private key, lalu beri lewat --cred atau "
                 "env GOOGLE_APPLICATION_CREDENTIALS.")
    firebase_admin.initialize_app(credentials.Certificate(path))
    return firestore.client()


def cmd_gen(args):
    db = _db(args.cred)
    coll = db.collection(_COLL)
    created = []
    for _ in range(args.count):
        # Hindari tabrakan (sangat kecil kemungkinannya, tapi pastikan).
        for _try in range(5):
            code = _gen_code()
            ref = coll.document(code)
            if not ref.get().exists:
                break
        ref.set({
            "tier": args.tier,
            "status": "unused",
            "durationDays": args.days,
            "deviceId": None,
            "licensee": args.licensee or "",
            "note": args.note or "",
            "createdAt": int(time.time()),
            "redeemedAt": None,
            "expiresAt": None,
        })
        created.append(code)

    print(f"\n{len(created)} kode {args.tier.upper()} ({args.days} hari) dibuat & "
          f"tersimpan di Firestore:\n")
    for c in created:
        print("  " + c)
    print("\nBagikan kode di atas ke pelanggan. Mereka aktifkan di app: "
          "Settings > Lisensi > Masukkan kode.")


def cmd_list(args):
    db = _db(args.cred)
    q = db.collection(_COLL)
    if args.status:
        q = q.where("status", "==", args.status)
    docs = list(q.limit(args.limit).stream())
    if not docs:
        print("(tidak ada)")
        return
    print(f"{'KODE':<28} {'TIER':<10} {'STATUS':<14} {'DEVICE':<14} EXPIRES")
    for d in docs:
        x = d.to_dict()
        dev = (x.get("deviceId") or "")[:12]
        exp = x.get("expiresAt")
        exp_s = time.strftime("%Y-%m-%d", time.localtime(exp)) if exp else "-"
        print(f"{d.id:<28} {x.get('tier',''):<10} {x.get('status',''):<14} {dev:<14} {exp_s}")


def cmd_info(args):
    db = _db(args.cred)
    snap = db.collection(_COLL).document(args.code.strip().upper()).get()
    if not snap.exists:
        sys.exit("Kode tidak ditemukan.")
    x = snap.to_dict()
    for k in ("tier", "status", "durationDays", "deviceId", "licensee", "note",
              "createdAt", "redeemedAt", "expiresAt"):
        v = x.get(k)
        if k in ("createdAt", "redeemedAt", "expiresAt") and v:
            v = f"{v} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(v))})"
        print(f"  {k:<13}: {v}")


def cmd_revoke(args):
    db = _db(args.cred)
    ref = db.collection(_COLL).document(args.code.strip().upper())
    if not ref.get().exists:
        sys.exit("Kode tidak ditemukan.")
    ref.update({"status": "revoked", "revokedAt": int(time.time())})
    print(f"Kode {args.code} DICABUT. App pelanggan akan turun ke Free saat cek online berikutnya.")


def main():
    ap = argparse.ArgumentParser(description="Generator kode lisensi Nexus (vendor).")
    ap.add_argument("--cred", default="", help="Path service-account JSON.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="Buat kode baru (langsung ke Firestore).")
    g.add_argument("--count", type=int, default=1)
    g.add_argument("--tier", choices=["pro", "enterprise"], default="pro")
    g.add_argument("--days", type=int, default=30)
    g.add_argument("--licensee", default="")
    g.add_argument("--note", default="")
    g.set_defaults(func=cmd_gen)

    li = sub.add_parser("list", help="Daftar kode.")
    li.add_argument("--status", choices=["unused", "redeemed", "revoked"], default="")
    li.add_argument("--limit", type=int, default=50)
    li.set_defaults(func=cmd_list)

    inf = sub.add_parser("info", help="Detail satu kode.")
    inf.add_argument("code")
    inf.set_defaults(func=cmd_info)

    rv = sub.add_parser("revoke", help="Cabut satu kode.")
    rv.add_argument("code")
    rv.set_defaults(func=cmd_revoke)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

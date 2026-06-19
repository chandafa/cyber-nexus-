# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_license/__main__.py
"""
nexus-license — alat VENDOR (Anda) untuk mengelola lisensi Nexus.

    # 1) Buat sepasang kunci (SEKALI). Simpan private key BAIK-BAIK & RAHASIA.
    nexus-license keygen --out vendor_private.key
    #    -> menulis vendor_private.key (RAHASIA) + menanam public key ke paket
    #       (nexus_common/vendor_public.key) agar manager bisa verifikasi.

    # 2) Terbitkan lisensi untuk pelanggan yang sudah bayar:
    nexus-license issue --key vendor_private.key --licensee "PT Contoh" \
        --tier pro --days 365 --max-agents 50 --out pt-contoh.license

    # 3) Pelanggan memasang lisensi di manager:
    #    NEXUS_LICENSE=/path/pt-contoh.license  (atau isi tokennya) lalu jalankan manager.

    # Cek isi lisensi:
    nexus-license info --token pt-contoh.license
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nexus_common import license as lic  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-license", description="Penerbit lisensi Nexus (vendor)")
    sub = p.add_subparsers(dest="action", required=True)

    kg = sub.add_parser("keygen", help="buat keypair + tanam public key ke paket")
    kg.add_argument("--out", default="vendor_private.key")
    kg.add_argument("--no-embed", action="store_true",
                    help="jangan tanam public key ke paket (manual)")

    iss = sub.add_parser("issue", help="terbitkan token lisensi")
    iss.add_argument("--key", required=True, help="file/heks private key vendor")
    iss.add_argument("--licensee", required=True)
    iss.add_argument("--tier", default="pro", choices=["free", "pro", "enterprise"])
    iss.add_argument("--days", type=int, default=365, help="0 = tanpa kedaluwarsa")
    iss.add_argument("--max-agents", type=int, default=50)
    iss.add_argument("--out", default="")

    inf = sub.add_parser("info", help="verifikasi & tampilkan isi lisensi")
    inf.add_argument("--token", required=True, help="token atau file lisensi")
    inf.add_argument("--pubkey", default="", help="public key hex (default: bundle)")

    args = p.parse_args(argv)

    if args.action == "keygen":
        seed_hex, pk_hex = lic.generate_keypair()
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(seed_hex + "\n")
        try:
            os.chmod(args.out, 0o600)
        except Exception:
            pass
        if not args.no_embed:
            lic.save_vendor_pubkey(pk_hex)
        print(json.dumps({"private_key_file": args.out, "public_key": pk_hex,
                          "embedded": not args.no_embed,
                          "warning": "SIMPAN private key ini rahasia & cadangkan; "
                                     "kehilangannya = tak bisa menerbitkan lisensi baru."},
                         indent=2))
        return 0

    if args.action == "issue":
        seed = args.key
        if os.path.isfile(seed):
            seed = open(seed, encoding="utf-8").read().strip()
        token = lic.issue(seed, args.licensee, args.tier, args.days, args.max_agents)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(token + "\n")
            print(json.dumps({"licensee": args.licensee, "tier": args.tier,
                              "days": args.days, "file": args.out}, indent=2))
        else:
            print(token)
        return 0

    if args.action == "info":
        ent = lic.entitlements(args.token, args.pubkey)
        ent = {**ent, "features": sorted(ent["features"])}
        print(json.dumps(ent, indent=2, ensure_ascii=False))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

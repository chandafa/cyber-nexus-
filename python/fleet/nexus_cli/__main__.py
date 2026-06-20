# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_cli/__main__.py
"""
nexus-cli — console keamanan & admin Nexus Fleet.

Interaktif (menu jaringan & website, ala-Wazuh):
    python -m nexus_cli                     # buka menu
    python -m nexus_cli menu

Non-interaktif (scripting/admin):
    python -m nexus_cli agents      --token <ADMIN_TOKEN>
    python -m nexus_cli events      --token <ADMIN_TOKEN> --limit 50
    python -m nexus_cli stats       --token <ADMIN_TOKEN>
    python -m nexus_cli policy-get
    python -m nexus_cli policy-set  --token <ADMIN_TOKEN> --file policy.json
    python -m nexus_cli command      --token <ADMIN_TOKEN> --agent agt_xxx --cmd collect_now

Opsi global: --host (default 127.0.0.1) --port (8765) --token (atau env NEXUS_ADMIN_TOKEN)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_common import protocol as fc  # noqa: E402
from nexus_common import __version__  # noqa: E402
from nexus_cli import admin, menu  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-cli", description="Console keamanan & admin Nexus Fleet")
    p.add_argument("-V", "--version", action="version", version=f"nexus-cli {__version__}")
    p.add_argument("--host", default=fc.DEFAULT_MANAGER_HOST)
    p.add_argument("--port", default=str(fc.DEFAULT_MANAGER_PORT))
    p.add_argument("--token", default=os.environ.get("NEXUS_ADMIN_TOKEN", ""))
    p.add_argument("--tls", action="store_true", help="hubungi manager via HTTPS")
    p.add_argument("--cacert", default="", help="CA/cert untuk verifikasi TLS")
    p.add_argument("--insecure", action="store_true", help="HTTPS tanpa verifikasi cert (uji saja)")
    sub = p.add_subparsers(dest="action")

    sub.add_parser("menu")
    sub.add_parser("agents")
    e = sub.add_parser("events"); e.add_argument("--limit", type=int, default=100)
    al = sub.add_parser("alerts")
    al.add_argument("--limit", type=int, default=100); al.add_argument("--status", default="")
    ak = sub.add_parser("ack")
    ak.add_argument("--id", required=True); ak.add_argument("--status", default="ack")
    rp = sub.add_parser("report"); rp.add_argument("--scope", default="fleet")
    sub.add_parser("stats")
    sub.add_parser("health")
    sub.add_parser("policy-get")
    ps = sub.add_parser("policy-set"); ps.add_argument("--file"); ps.add_argument("--json")
    cm = sub.add_parser("command")
    cm.add_argument("--agent", required=True); cm.add_argument("--cmd", required=True)
    cm.add_argument("--args", default="")
    apl = sub.add_parser("apply-license", help="pasang lisensi ke manager (hot-reload)")
    apl.add_argument("--file"); apl.add_argument("--token", dest="lic")
    rma = sub.add_parser("remove-agent", help="hapus pendaftaran agent (bebaskan seat)")
    rma.add_argument("--agent", required=True); rma.add_argument("--purge", action="store_true")
    inc = sub.add_parser("incidents", help="alert dikelompokkan jadi insiden")
    inc.add_argument("--status", default="open")
    au = sub.add_parser("add-user", help="buat token RBAC (admin|viewer)")
    au.add_argument("--role", default="viewer", choices=["admin", "viewer"])
    args = p.parse_args(argv)

    # Konfigurasi TLS untuk transport admin (Fix: TLS untuk CLI/dashboard).
    if args.tls or args.insecure:
        admin.set_scheme("https")
        fc.set_client_tls(cafile=args.cacert, insecure=args.insecure or not args.cacert)

    # default / 'menu' -> interaktif
    if args.action in (None, "menu"):
        return menu.run(args.host, args.port, args.token)

    try:
        if args.action == "agents":
            out = admin.agents(args.host, args.port, args.token)
        elif args.action == "events":
            out = admin.events(args.host, args.port, args.token, args.limit)
        elif args.action == "alerts":
            out = admin.alerts(args.host, args.port, args.token, args.limit, args.status)
        elif args.action == "ack":
            out = admin.ack(args.host, args.port, args.token, args.id, args.status)
        elif args.action == "report":
            out = admin.report(args.host, args.port, args.token, args.scope)
        elif args.action == "stats":
            out = admin.stats(args.host, args.port, args.token)
        elif args.action == "health":
            out = admin.health(args.host, args.port)
        elif args.action == "policy-get":
            out = admin.policy_get(args.host, args.port)
        elif args.action == "policy-set":
            if args.file:
                with open(args.file, encoding="utf-8") as f:
                    pol = json.load(f)
            elif args.json:
                pol = json.loads(args.json)
            else:
                raise SystemExit("policy-set butuh --file atau --json")
            out = admin.policy_set(args.host, args.port, args.token, pol)
        elif args.action == "command":
            out = admin.command(args.host, args.port, args.token, args.agent, args.cmd,
                                json.loads(args.args) if args.args else {})
        elif args.action == "apply-license":
            lic = args.lic or ""
            if args.file:
                with open(args.file, encoding="utf-8") as f:
                    lic = f.read().strip()
            out = admin.apply_license(args.host, args.port, args.token, lic)
        elif args.action == "remove-agent":
            out = admin.remove_agent(args.host, args.port, args.token, args.agent, args.purge)
        elif args.action == "incidents":
            out = admin.incidents(args.host, args.port, args.token, args.status)
        elif args.action == "add-user":
            out = admin.add_user(args.host, args.port, args.token, args.role)
        else:
            raise SystemExit(f"aksi tidak dikenal: {args.action}")
    except fc.HttpError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

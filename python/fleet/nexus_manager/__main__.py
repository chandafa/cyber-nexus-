# nexus_manager/__main__.py
"""
nexus-manager — entrypoint standalone.

    python -m nexus_manager run    [--host 0.0.0.0] [--port 8765]
    python -m nexus_manager info             # tampilkan enrollment key & admin token
    python -m nexus_manager status [--host --port]

Env:
    NEXUS_FLEET_DB   path file SQLite (default ./fleet_manager.db)
    NEXUS_FLEET_HOME folder data bila NEXUS_FLEET_DB tak diset
"""
import argparse
import json
import os
import sys

# Pastikan paket fleet (nexus_common, dst.) ada di sys.path saat dijalankan langsung.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_manager import server  # noqa: E402
from nexus_common import protocol as fc  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-manager",
                                description="Server pusat Nexus Fleet (penerima event & policy).")
    sub = p.add_subparsers(dest="action", required=True)
    r = sub.add_parser("run", help="jalankan server (blocking)")
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", default=str(fc.DEFAULT_MANAGER_PORT))
    sub.add_parser("info", help="tampilkan enrollment key & admin token")
    s = sub.add_parser("status", help="cek apakah manager hidup")
    s.add_argument("--host", default=fc.DEFAULT_MANAGER_HOST)
    s.add_argument("--port", default=str(fc.DEFAULT_MANAGER_PORT))
    args = p.parse_args(argv)

    if args.action == "run":
        res = server.serve_blocking(args.host, args.port)
        return 0 if res.get("status") != "error" else 1
    if args.action == "info":
        print(json.dumps({"enroll_key": server.get_enroll_key(),
                          "admin_token": server.get_admin_token(),
                          "db": fc.manager_db_path()}, indent=2))
        return 0
    if args.action == "status":
        print(json.dumps(server.manager_status(args.host, args.port), indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

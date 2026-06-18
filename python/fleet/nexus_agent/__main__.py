# nexus_agent/__main__.py
"""
nexus-agent — entrypoint standalone (daemon endpoint ringan).

    python -m nexus_agent enroll --host <manager> --port 8765 --key <ENROLL_KEY> [--name myhost]
    python -m nexus_agent start              # jalankan daemon (blocking)
    python -m nexus_agent status
    python -m nexus_agent reset              # lupakan enrollment
    python -m nexus_agent collect            # sekali jalan: cetak telemetri (tanpa kirim)

Env:
    NEXUS_AGENT_DB   path file state SQLite (default ./fleet_agent.db)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_agent import agent  # noqa: E402
from nexus_common import protocol as fc  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-agent",
                                description="Daemon endpoint Nexus Fleet (ala-Wazuh agent).")
    sub = p.add_subparsers(dest="action", required=True)
    e = sub.add_parser("enroll", help="daftar ke manager")
    e.add_argument("--host", required=True)
    e.add_argument("--port", default=str(fc.DEFAULT_MANAGER_PORT))
    e.add_argument("--key", required=True, help="enrollment key dari manager")
    e.add_argument("--name", default="")
    e.add_argument("--labels", default="", help="label/grup, dipisah koma (mis. prod,web)")
    e.add_argument("--tls", action="store_true", help="hubungkan via HTTPS (pin sertifikat manager)")
    e.add_argument("--watch", default="",
                   help="path project/log untuk dipantau otomatis (FIM/web-audit/log), dipisah koma")
    sub.add_parser("start", help="jalankan daemon (blocking)")
    sub.add_parser("status")
    sub.add_parser("reset")
    sub.add_parser("collect", help="kumpulkan telemetri sekali & cetak")
    args = p.parse_args(argv)

    if args.action == "enroll":
        print(json.dumps(agent.enroll(args.host, args.port, args.key, args.name,
                                      args.labels, tls=args.tls, watch=args.watch), indent=2))
        return 0
    if args.action == "start":
        agent.run_foreground()
        return 0
    if args.action == "status":
        print(json.dumps(agent.status(), indent=2))
        return 0
    if args.action == "reset":
        print(json.dumps(agent.reset(), indent=2))
        return 0
    if args.action == "collect":
        print(json.dumps(agent.collect_all(), indent=2, ensure_ascii=False))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

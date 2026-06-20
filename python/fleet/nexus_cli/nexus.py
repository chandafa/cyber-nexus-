# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_cli/nexus.py
"""
`nexus` — perintah payung Nexus Fleet.

Satu entry-point yang mendispatch ke sub-perintah, plus `--version`:

    nexus --version                         # cetak versi paket
    nexus manager run --host 0.0.0.0 --port 8765
    nexus agent run --manager https://host:8765
    nexus cli agents --token <ADMIN_TOKEN>
    nexus dashboard
    nexus license issue --key <seed> --licensee "ACME"

Tanpa argumen menampilkan bantuan ringkas. Setiap sub-perintah meneruskan
sisa argumen apa adanya ke CLI komponen terkait (mis. `nexus-manager`).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_common import __version__  # noqa: E402

# nama-sub -> (modul, fungsi, prog yang dipakai sub-CLI saat parse argv)
_SUBCOMMANDS = {
    "manager":   ("nexus_manager.__main__", "main", "nexus-manager"),
    "agent":     ("nexus_agent.__main__", "main", "nexus-agent"),
    "cli":       ("nexus_cli.__main__", "main", "nexus-cli"),
    "dashboard": ("nexus_dashboard.server", "main", "nexus-dashboard"),
    "license":   ("nexus_license.__main__", "main", "nexus-license"),
}

_USAGE = """nexus - platform keamanan endpoint Nexus Fleet (v{ver})

Penggunaan:
  nexus <perintah> [opsi...]
  nexus --version

Perintah:
  manager      Jalankan/kelola Manager (server pusat).  contoh: nexus manager run --host 0.0.0.0 --port 8765
  agent        Jalankan/daftarkan Agent endpoint.       contoh: nexus agent run --manager https://HOST:8765
  cli          Console admin (agents, events, alerts).  contoh: nexus cli agents --token <ADMIN_TOKEN>
  dashboard    Buka dashboard web read-only.            contoh: nexus dashboard
  license      Terbitkan/verifikasi token lisensi.      contoh: nexus license verify --token <TOKEN>

Opsi global:
  -V, --version   Tampilkan versi lalu keluar
  -h, --help      Tampilkan bantuan ini
"""


def _print_help():
    print(_USAGE.format(ver=__version__))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_help()
        return 0
    if argv[0] in ("-V", "--version", "version"):
        print(f"nexus {__version__}")
        return 0

    cmd, rest = argv[0], argv[1:]
    if cmd not in _SUBCOMMANDS:
        print(f"[error] perintah tidak dikenal: {cmd}\n", file=sys.stderr)
        _print_help()
        return 2

    mod_name, func_name, prog = _SUBCOMMANDS[cmd]
    mod = __import__(mod_name, fromlist=[func_name])
    func = getattr(mod, func_name)

    # Sub-CLI memakai argparse dgn prog masing-masing; samakan argv[0] agar pesan
    # bantuan/error menampilkan nama yang benar (mis. "nexus-manager").
    saved = sys.argv
    sys.argv = [prog, *rest]
    try:
        try:
            rc = func(rest)          # main(argv) — jalur umum
        except TypeError:
            rc = func()              # main() tanpa argv (mis. dashboard)
    finally:
        sys.argv = saved
    return int(rc or 0)


if __name__ == "__main__":
    raise SystemExit(main())

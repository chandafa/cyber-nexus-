# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/nexus_tools/cli.py
"""
nexus-tools — CLI untuk perangkat keamanan desktop Nexus.

Setiap subperintah memetakan ke satu command runner.dispatch (jalur kode yang sama
dengan GUI). Output live tool dialihkan ke stderr; hasil terstruktur akhir dicetak
sebagai JSON ke stdout — aman untuk piping (mis. `| jq`).

Contoh:
    python -m nexus_tools port-scan --target 192.168.1.1 --mode full
    python -m nexus_tools dns-recon --domain example.com
    python -m nexus_tools vuln-scan --target https://example.com   # Pro
    python -m nexus_tools license-status
    python -m nexus_tools --list                                   # daftar semua tool

Gerbang lisensi Pro & fallback demo (saat tool eksternal absen) berlaku otomatis,
identik dengan GUI — keduanya lewat runner.dispatch.
"""
import argparse
import json
import os
import sys

# runner.py memakai impor top-level (`from modules import ...`, `from core import ...`),
# jadi direktori python/ harus ada di sys.path. nexus_tools berada di python/nexus_tools/.
_PY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PY_ROOT not in sys.path:
    sys.path.insert(0, _PY_ROOT)

__version__ = "2.2.1"

# --------------------------------------------------------------------------- registry
# Tiap entri: (subperintah, command-dispatch, help, [argumen]).
# Argumen: (flag, opsi-add_argument). Nama dest (flag tanpa "--", "-"→"_") HARUS sama
# dengan kunci kwargs yang dibaca runner/module. Nilai dikirim sebagai STRING — sama
# seperti GUI (buildArgs → Rust → Python menerima string) demi paritas perilaku penuh.
_S = {}  # opsi string biasa
_REQ = {"required": True}
_FLAG = {"action": "store_true"}  # toggle → "true" saat aktif

TOOLS = [
    # ---- Recon & Scan ----
    ("port-scan", "port_scan", "Pemindaian port berbasis Nmap", [
        ("--target", _REQ),
        ("--mode", {"default": "standard",
                    "choices": ["quick", "standard", "os", "full", "vuln", "stealth", "udp"]}),
    ]),
    ("network-scan", "network_scan", "Sniffing paket langsung (butuh hak istimewa)", [
        ("--interface", {"default": "1"}),
        ("--filter", _S),
        ("--pcap-file", _S),
        ("--packet-limit", {"default": "40"}),
    ]),
    ("dns-recon", "dns_recon", "Enumerasi DNS & subdomain", [
        ("--domain", _REQ),
        ("--wordlist", _S),
    ]),
    ("network-map", "network_map", "Pemetaan aset/topologi jaringan [Pro]", [
        ("--target", _REQ),
    ]),
    ("asset-inventory", "asset_inventory", "Inventaris aset [Pro]", [
        ("--submode", {"default": "list", "choices": ["list", "export"]}),
    ]),
    # ---- Web & API ----
    ("vuln-scan", "vuln_scan", "Pemindai kerentanan web (nikto/gobuster/nuclei) [Pro]", [
        ("--target", _REQ),
        ("--tools", {"default": "nikto,gobuster,nuclei"}),
        ("--wordlist", _S),
    ]),
    ("ssl-audit", "ssl_audit", "Audit sertifikat & cipher TLS/SSL [Pro]", [
        ("--target", _REQ),
        ("--port", {"default": "443"}),
    ]),
    ("api-test", "api_test", "Uji/fuzz endpoint REST [Pro]", [
        ("--target", _REQ),
        ("--submode", {"default": "endpoints", "choices": ["endpoints", "security"]}),
        ("--wordlist", _S),
    ]),
    ("dir-fuzz", "dir_fuzz", "Brute-force direktori (gobuster) [Pro]", [
        ("--target", _REQ),
        ("--wordlist", _S),
        ("--extensions", _S),
    ]),
    # ---- Offensive ----
    ("password-audit", "password_audit", "Audit kekuatan kredensial (hydra) [Pro]", [
        ("--target", _REQ),
        ("--submode", {"default": "hydra"}),
        ("--protocol", {"default": "ssh"}),
        ("--username", _S),
        ("--user-list", _S),
        ("--password-list", _S),
        ("--port", _S),
    ]),
    ("hash-tool", "hash_tool", "Identifikasi/crack hash", [
        ("--submode", {"default": "identify", "choices": ["identify", "crack", "generate"]}),
        ("--hash", _S),
        ("--wordlist", _S),
    ]),
    ("exploit-lookup", "exploit_lookup", "Pencarian CVE/exploit [Pro]", [
        ("--services", _S),
        ("--service", _S),
        ("--version", _S),
    ]),
    ("attack-sim", "attack_sim", "Simulasi serangan (Atomic Red Team) [Pro]", [
        ("--submode", {"default": "catalog", "choices": ["catalog", "run"]}),
        ("--simulation", _S),
        ("--target", _S),
        ("--confirmed", {"default": "false", "choices": ["true", "false"]}),
    ]),
    ("listener", "listener", "Generator payload / listener reverse shell [Pro]", [
        ("--submode", {"default": "payload", "choices": ["payload", "listen"]}),
        ("--lhost", _S),
        ("--lport", {"default": "4444"}),
        ("--shell", {"default": "bash"}),
        ("--duration", _S),
    ]),
    ("wireless-scan", "wireless_scan", "Audit Wi-Fi (aircrack-ng, Linux) [Pro]", [
        ("--interface", {"default": "wlan0"}),
        ("--duration", {"default": "12"}),
    ]),
    # ---- Cloud & Container ----
    ("container-scan", "container_scan", "Pemindai keamanan kontainer (trivy) [Pro]", [
        ("--image", {"default": "nginx:latest"}),
    ]),
    ("cloud-check", "cloud_check", "Audit konfigurasi cloud [Pro]", [
        ("--provider", {"default": "aws", "choices": ["aws", "azure", "gcp"]}),
    ]),
    # ---- Analisis ----
    ("log-analyze", "log_analyze", "Parsing & analisis log", [
        ("--log-path", _REQ),
        ("--log-type", {"default": "auto",
                        "choices": ["auto", "apache", "nginx", "windows", "syslog"]}),
    ]),
    ("sbom", "sbom_scan", "SBOM & dependency-risk scanner (supply-chain)", [
        ("--path", {"default": "."}),
        ("--manifest", _S),
        ("--vulndb", _S),
        ("--emit-sbom", _FLAG),
    ]),
    ("scan", "sbom_scan", "CI gate: SBOM scan; exit!=0 saat temuan high/critical", [
        ("--path", {"default": "."}),
        ("--manifest", _S),
        ("--vulndb", _S),
        ("--emit-sbom", _FLAG),
    ]),
    ("scan-diff", "scan_diff", "Bandingkan dua hasil pemindaian [Pro]", [
        ("--old-session", _REQ),
        ("--new-session", _REQ),
    ]),
    ("security-score", "security_score", "Skor keamanan keseluruhan (0-100)", [
        ("--submode", {"default": "run", "choices": ["run", "history"]}),
    ]),
    # ---- Defense & Laporan ----
    ("defense-check", "defense_check", "Audit pertahanan lokal (Lynis) [Pro]", [
        ("--submode", {"default": "all", "choices": ["all", "av", "firewall", "updates"]}),
    ]),
    ("ids-monitor", "ids_monitor", "Analisis IDS/anomali (Linux) [Pro]", [
        ("--interface", {"default": "eth0"}),
        ("--duration", {"default": "15"}),
    ]),
    ("firewall-advisor", "firewall_advisor", "Saran kebijakan port/firewall [Pro]", [
        ("--ports", _S),
        ("--essential", {"default": "22,80,443"}),
    ]),
    ("patch-advisor", "patch_advisor", "Prioritas patch dari temuan [Pro]", [
        ("--findings", _S),
    ]),
    ("scheduler", "scheduler", "Penjadwal scan/command berulang [Pro]", [
        ("--submode", {"default": "list"}),
        ("--schedule", _S),
        ("--command", _S),
    ]),
    ("human-element", "human_element", "Drill kesadaran/anti-phishing", [
        ("--submode", {"default": "list", "choices": ["list", "create", "record"]}),
        ("--name", _S),
        ("--target-group", _S),
        ("--schedule", _S),
    ]),
    ("generate-report", "generate_report", "Buat laporan PDF/teknis [Pro]", [
        ("--session", _S),
        ("--report-type", {"default": "full", "choices": ["full", "executive", "technical"]}),
        ("--output-path", _S),
    ]),
    # ---- WAF (Web Application Firewall) [Pro] ----
    ("waf", "waf", "Jalankan WAF reverse-proxy [Pro]", [
        ("--listen-port", {"default": "8080"}),
        ("--backend", {"default": "127.0.0.1"}),
        ("--backend-port", {"default": "8000"}),
        ("--max-rps", _S),
        ("--learning-mode", _FLAG),
        ("--foreground", _FLAG),
    ]),
    ("waf-stop", "waf_stop", "Hentikan WAF [Pro]", []),
    ("waf-status", "waf_status", "Status WAF", []),
    ("waf-logs", "waf_logs", "Ambil log WAF", [("--limit", {"default": "200"})]),
    ("waf-clear-logs", "waf_clear_logs", "Bersihkan log WAF [Pro]", []),
    ("waf-get-vhosts", "waf_get_vhosts", "Daftar vhost WAF", []),
    ("waf-save-vhost", "waf_save_vhost", "Tambah/ubah vhost WAF [Pro]", [
        ("--hostname", _REQ),
        ("--backend-host", _S),
        ("--backend-port", _S),
        ("--max-rps", _S),
        ("--learning-mode", _FLAG),
        ("--rules-json", _S),
        ("--vhost-type", _S),
        ("--root-directory", _S),
    ]),
    ("waf-delete-vhost", "waf_delete_vhost", "Hapus vhost WAF [Pro]", [("--hostname", _REQ)]),
    ("waf-get-rules", "waf_get_rules", "Daftar rule kustom WAF", []),
    ("waf-save-rule", "waf_save_rule", "Tambah/ubah rule WAF [Pro]", [
        ("--name", _REQ),
        ("--pattern", _REQ),
        ("--description", _S),
        ("--enabled", _FLAG),
    ]),
    ("waf-delete-rule", "waf_delete_rule", "Hapus rule WAF [Pro]", [("--name", _REQ)]),
    # ---- Sistem / utilitas ----
    ("check-deps", "check_deps", "Cek dependensi tool eksternal", []),
    ("install-info", "install_info", "Tampilkan perintah pemasangan tool", [("--missing", _S)]),
    ("install-tools", "install_tools", "Pasang tool eksternal", [("--tools", _S)]),
    ("privileges", "privileges", "Cek hak istimewa (admin/root/raw-socket)", []),
    ("list-interfaces", "list_interfaces", "Daftar antarmuka jaringan", []),
    ("wordlist", "wordlist", "Kelola wordlist fuzzing", [
        ("--submode", {"default": "list", "choices": ["list", "add", "remove"]}),
        ("--name", _S),
    ]),
    # ---- Lisensi ----
    ("license-status", "license_status", "Tampilkan status & fitur lisensi", []),
    ("license-apply", "license_apply", "Pasang token lisensi (JWT/berkas)", [
        ("--token", _S), ("--path", _S),
    ]),
    ("license-redeem", "license_redeem", "Tukarkan kode aktivasi", [("--code", _REQ)]),
    ("license-validate", "license_validate", "Validasi lisensi ke server", []),
    ("license-clear", "license_clear", "Hapus lisensi (kembali ke Free)", []),
    ("license-device-id", "license_device_id", "Tampilkan device-id (untuk aktivasi)", []),
]

_CMD_BY_NAME = {name: cmd for name, cmd, _h, _a in TOOLS}


def build_parser():
    p = argparse.ArgumentParser(
        prog="nexus-tools",
        description="Perangkat keamanan desktop Nexus (recon · web · offensive · defense · WAF).",
        epilog="Output live → stderr; hasil JSON akhir → stdout (aman untuk | jq).")
    p.add_argument("-V", "--version", action="version", version=f"nexus-tools {__version__}")
    p.add_argument("--list", action="store_true", help="daftar semua subperintah lalu keluar")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="sembunyikan output live; cetak hanya JSON hasil")
    sub = p.add_subparsers(dest="cmd", metavar="<perintah>")
    for name, _cmd, help_text, arglist in TOOLS:
        sp = sub.add_parser(name, help=help_text)
        for flag, opts in arglist:
            sp.add_argument(flag, **opts)
    return p


def _print_list():
    width = max(len(n) for n, *_ in TOOLS)
    print("Perintah nexus-tools:\n")
    for name, _cmd, help_text, _a in TOOLS:
        print(f"  {name.ljust(width)}  {help_text}")
    print("\nDetail opsi: python -m nexus_tools <perintah> --help")


def _to_kwargs(args):
    """Namespace argparse → dict kwargs string (mirror perilaku GUI buildArgs)."""
    skip = {"cmd", "quiet", "list", "version"}
    kwargs = {}
    for k, v in vars(args).items():
        if k in skip or v is None or v is False:
            continue
        kwargs[k] = "true" if v is True else str(v)
    return kwargs


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        _print_list()
        return 0
    if not args.cmd:
        parser.print_help()
        return 1

    command = _CMD_BY_NAME[args.cmd]
    kwargs = _to_kwargs(args)

    # Impor runner SETELAH sys.path siap. dispatch sudah menerapkan gerbang lisensi Pro
    # secara internal (mengembalikan dict terkunci) — jadi cukup panggil dispatch.
    try:
        from runner import dispatch
    except Exception as e:  # pragma: no cover
        print(json.dumps({"ok": False, "error": f"gagal memuat runner: {e}"}), file=sys.stderr)
        return 1

    # Alihkan output live (emit_line menulis ke sys.stdout) ke stderr / devnull,
    # agar stdout menyisakan JSON hasil yang bersih untuk piping.
    real_stdout = sys.stdout
    sink = open(os.devnull, "w", encoding="utf-8") if args.quiet else sys.stderr
    try:
        sys.stdout = sink
        result = dispatch(command, kwargs)
    except KeyboardInterrupt:
        sys.stdout = real_stdout
        print(json.dumps({"ok": False, "error": "dibatalkan"}), file=sys.stderr)
        return 130
    except Exception as e:
        sys.stdout = real_stdout
        print(json.dumps({"ok": False, "error": str(e), "kind": "runtime"},
                         ensure_ascii=False), file=sys.stderr)
        return 1
    finally:
        sys.stdout = real_stdout
        if args.quiet:
            sink.close()

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    if isinstance(result, dict) and (result.get("locked") or result.get("ok") is False):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

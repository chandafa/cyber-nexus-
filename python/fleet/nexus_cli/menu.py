# nexus_cli/menu.py
"""
Console keamanan interaktif Nexus (ala-Wazuh / tooling SOC industri).

Menu:
  1) Network Security    — port scan, host discovery, DNS recon, firewall advisor
  2) Website Security     — vuln scan, SSL/TLS audit, directory fuzzing, API test
  3) Fleet / Agent Manager— kelola agent, lihat event, policy, kirim perintah
  4) Endpoint Posture     — jalankan collector lokal (port, user, disk, firewall)
  5) Settings             — alamat manager & admin token

Menu Network/Website memakai mesin Nexus (runner.py) bila tersedia; bila CLI
di-install terpisah tanpa mesin, menu tsb. dinonaktifkan dgn pesan jelas,
sedangkan Fleet & Endpoint Posture tetap berfungsi.
"""
import json
import os
import sys

from nexus_common import protocol as fc
from nexus_cli import admin

# --------------------------------------------------------------------------- warna
_TTY = sys.stdout.isatty()


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else s


def cyan(s): return _c("96", s)
def green(s): return _c("92", s)
def yellow(s): return _c("93", s)
def red(s): return _c("91", s)
def dim(s): return _c("90", s)
def bold(s): return _c("1", s)


SEV_COLOR = {"critical": "91", "high": "91", "medium": "93", "low": "96", "info": "90"}


# --------------------------------------------------------------------------- engine (runner.py)
def _load_engine():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # python/fleet
    for base in (os.path.dirname(here),):                              # python/
        if os.path.isfile(os.path.join(base, "runner.py")):
            if base not in sys.path:
                sys.path.insert(0, base)
            try:
                import runner
                return runner
            except Exception as e:
                print(red(f"[!] Gagal memuat mesin Nexus: {e}"))
                return None
    return None


# --------------------------------------------------------------------------- input helpers
def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    try:
        v = input(cyan(f"  {prompt}{suffix}: ")).strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return v or default


def pause():
    try:
        input(dim("\n  Tekan Enter untuk kembali..."))
    except (EOFError, KeyboardInterrupt):
        pass


def banner():
    print(cyan(r"""
  _   _ _______  ___   _ ___    ___ _    ___
 | \ | | ____\ \/ / | | / __|  / __| |  |_ _|
 |  \| |  _|  \  /| | | \__ \ | (__| |__ | |
 |_|\_|_____| /_/ \___/ |___/  \___|____|___|
""") + dim("  Nexus Security CLI — SOC console (network & web)  ·  ethical use only\n"))


# --------------------------------------------------------------------------- result summary
def _summarize(result):
    if not isinstance(result, dict):
        return
    if result.get("error"):
        print(red(f"  [!] {result.get('error')}"))
        return
    interesting = []
    for k, v in result.items():
        if isinstance(v, list):
            interesting.append(f"{k}={len(v)}")
        elif isinstance(v, dict) and k in ("by_severity", "summary", "counts"):
            interesting.append(f"{k}={json.dumps(v)}")
    if interesting:
        print(green("  [=] Ringkasan: ") + ", ".join(interesting))


def run_engine(engine, command, kwargs, title):
    print(bold(cyan(f"\n=== {title} ===")))
    if engine is None:
        print(red("  [!] Mesin Nexus (runner.py) tidak ditemukan di instalasi ini.\n"
                  "      Jalankan nexus-cli dari dalam repo Nexus untuk fitur scan."))
        return
    try:
        from core.sanitizer import SanitizeError  # type: ignore
    except Exception:
        SanitizeError = Exception
    try:
        result = engine.dispatch(command, kwargs)
        _summarize(result)
    except SanitizeError as e:
        print(red(f"  [validation] {e}"))
    except Exception as e:
        print(red(f"  [!] {e}"))


# --------------------------------------------------------------------------- menus
def menu_network(engine):
    while True:
        print(bold("\n  NETWORK SECURITY"))
        print("   1) Port Scan (Nmap)")
        print("   2) Host Discovery / Network Map")
        print("   3) DNS & Subdomain Recon")
        print("   4) Firewall Rule Advisor")
        print("   0) Kembali")
        c = ask("Pilih")
        if c == "1":
            t = ask("Target (IP/host)", "127.0.0.1")
            m = ask("Mode (fast/standard/full)", "standard")
            run_engine(engine, "port_scan", {"target": t, "mode": m}, "Port Scan")
            pause()
        elif c == "2":
            t = ask("Target / subnet (mis. 192.168.1.0/24)", "127.0.0.1")
            run_engine(engine, "network_map", {"target": t}, "Network Map")
            pause()
        elif c == "3":
            d = ask("Domain", "example.com")
            run_engine(engine, "dns_recon", {"domain": d}, "DNS Recon")
            pause()
        elif c == "4":
            ports = ask("Port terbuka (csv)", "22,80,443,3389")
            ess = ask("Port esensial (csv)", "22,80,443")
            run_engine(engine, "firewall_advisor", {"ports": ports, "essential": ess},
                       "Firewall Advisor")
            pause()
        elif c == "0":
            return


def menu_web(engine):
    while True:
        print(bold("\n  WEBSITE / WEB-APP SECURITY"))
        print("   1) Vulnerability Scan (Nikto/Nuclei/Gobuster)")
        print("   2) SSL/TLS Audit")
        print("   3) Directory / Content Fuzzing")
        print("   4) API Endpoint Test")
        print("   0) Kembali")
        c = ask("Pilih")
        if c == "1":
            t = ask("URL target", "http://127.0.0.1")
            tools = ask("Tools (csv)", "nikto,nuclei,gobuster")
            run_engine(engine, "vuln_scan", {"target": t, "tools": tools}, "Vulnerability Scan")
            pause()
        elif c == "2":
            t = ask("Host", "example.com")
            port = ask("Port", "443")
            run_engine(engine, "ssl_audit", {"target": t, "port": port}, "SSL/TLS Audit")
            pause()
        elif c == "3":
            t = ask("URL target", "http://127.0.0.1")
            ext = ask("Ekstensi (csv, opsional)", "php,html,txt")
            run_engine(engine, "dir_fuzz", {"target": t, "extensions": ext},
                       "Directory Fuzzing")
            pause()
        elif c == "4":
            t = ask("Base URL API", "http://127.0.0.1/api")
            run_engine(engine, "api_test", {"target": t, "submode": "endpoints"},
                       "API Endpoint Test")
            pause()
        elif c == "0":
            return


def menu_fleet(cfg):
    host, port = cfg["host"], cfg["port"]
    while True:
        print(bold("\n  FLEET / AGENT MANAGER"))
        print("   1) Daftar agent")
        print("   2) Event terbaru")
        print("   3) " + bold("Alerts (rule engine + MITRE)"))
        print("   4) Statistik / risk score")
        print("   5) Lihat policy")
        print("   6) Set heartbeat/collect interval")
        print("   7) Kirim perintah ke agent (collect_now)")
        print("   8) Ack / resolve alert")
        print("   9) Generate report (schema konsisten)")
        print("   0) Kembali")
        c = ask("Pilih")
        try:
            if c == "1":
                r = admin.agents(host, port, cfg["token"])
                for a in r.get("agents", []):
                    st = green(a["status"]) if a["status"] == "online" else dim(a["status"])
                    print(f"   - {bold(a['name'] or a['hostname'])}  {a['os']}  {st}  "
                          f"{dim(a['agent_id'])}  last={a['last_seen_iso']}")
                if not r.get("agents"):
                    print(dim("   (belum ada agent)"))
            elif c == "2":
                n = int(ask("Berapa event", "20") or "20")
                r = admin.events(host, port, cfg["token"], n)
                for e in r.get("events", []):
                    col = SEV_COLOR.get(e["severity"], "90")
                    print(f"   {e['ts_iso']}  {_c(col, e['severity'].upper().ljust(8))} "
                          f"{e['type']:<16} {e['title']}")
            elif c == "3":
                r = admin.alerts(host, port, cfg["token"], 30, ask("filter status (open/ack/resolved/kosong)", ""))
                for a in r.get("alerts", []):
                    col = SEV_COLOR.get(a["severity"], "90")
                    mitre = ",".join(a.get("mitre", []))
                    print(f"   {_c(col, ('L%d ' % a['level']) + a['severity'].upper())}  "
                          f"{dim(a['rule_id'])}  {a['title']}  {dim('['+a['status']+'] '+mitre)}")
                    if a.get("recommendation"):
                        print(dim(f"        fix: {a['recommendation']}"))
                if not r.get("alerts"):
                    print(dim("   (belum ada alert)"))
            elif c == "4":
                s = admin.stats(host, port, cfg["token"])
                print(f"   agents {green(str(s.get('agents_online')))}/{s.get('agents_total')} online · "
                      f"events {s.get('events_total')} · "
                      f"alerts {red(str(s.get('alerts_open')))} open / {s.get('alerts_total')} · "
                      f"risk {bold(str(s.get('risk_score')))}")
            elif c == "5":
                print(json.dumps(admin.policy_get(host, port).get("policy", {}), indent=2))
            elif c == "6":
                pol = admin.policy_get(host, port).get("policy", {})
                pol["heartbeat_interval"] = int(ask("heartbeat_interval (detik)",
                                                    str(pol.get("heartbeat_interval", 30))))
                pol["collect_interval"] = int(ask("collect_interval (detik)",
                                                  str(pol.get("collect_interval", 120))))
                r = admin.policy_set(host, port, cfg["token"], pol)
                print(green(f"   policy -> versi {r.get('policy_version')}"))
            elif c == "7":
                aid = ask("agent_id")
                if aid:
                    admin.command(host, port, cfg["token"], aid, "collect_now")
                    print(green("   perintah collect_now diantri."))
            elif c == "8":
                aid = ask("alert_id")
                st = ask("status (ack/resolved/open)", "ack")
                if aid:
                    admin.ack(host, port, cfg["token"], aid, st)
                    print(green(f"   alert {aid} -> {st}"))
            elif c == "9":
                rep = admin.report(host, port, cfg["token"])
                sm = rep.get("summary", {})
                print(green(f"   report {rep.get('schema')}: {sm.get('alerts_total')} alert, "
                            f"risk {sm.get('risk_score')}, MITRE {sm.get('mitre_techniques')}"))
            elif c == "0":
                return
        except fc.HttpError as e:
            print(red(f"   [!] {e}  (cek host/port/admin token di Settings)"))
        except Exception as e:
            print(red(f"   [!] {e}"))
        pause()


def menu_posture():
    from nexus_agent import collectors
    print(bold(cyan("\n=== ENDPOINT POSTURE (host ini) ===")))
    pol = {"risky_ports": [21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017]}
    for name in collectors.NAMES:
        try:
            for e in collectors.REGISTRY[name](pol):
                col = SEV_COLOR.get(e["severity"], "90")
                print(f"   {_c(col, e['severity'].upper().ljust(8))} {e['type']:<16} {e['title']}")
        except Exception as ex:
            print(red(f"   {name}: {ex}"))
    pause()


def menu_settings(cfg):
    print(bold("\n  SETTINGS — koneksi manager"))
    cfg["host"] = ask("Manager host", cfg["host"])
    cfg["port"] = ask("Manager port", cfg["port"])
    cfg["token"] = ask("Admin token", cfg["token"]) or cfg["token"]
    try:
        h = admin.health(cfg["host"], cfg["port"])
        print(green(f"   manager OK (server time {h.get('time')})"))
    except Exception as e:
        print(yellow(f"   manager belum terjangkau: {e}"))
    pause()


def run(host=None, port=None, token=None):
    engine = _load_engine()
    cfg = {
        "host": host or os.environ.get("NEXUS_MANAGER_HOST", fc.DEFAULT_MANAGER_HOST),
        "port": str(port or os.environ.get("NEXUS_MANAGER_PORT", fc.DEFAULT_MANAGER_PORT)),
        "token": token or os.environ.get("NEXUS_ADMIN_TOKEN", ""),
    }
    banner()
    if engine is None:
        print(yellow("  Catatan: mesin scan tidak terdeteksi — menu 1 & 2 nonaktif.\n"))
    while True:
        print(bold("\n  MAIN MENU"))
        print("   1) Network Security")
        print("   2) Website / Web-App Security")
        print("   3) Fleet / Agent Manager")
        print("   4) Endpoint Posture (host ini)")
        print("   5) Settings")
        print("   0) Keluar")
        c = ask("Pilih")
        if c == "1":
            menu_network(engine)
        elif c == "2":
            menu_web(engine)
        elif c == "3":
            menu_fleet(cfg)
        elif c == "4":
            menu_posture()
        elif c == "5":
            menu_settings(cfg)
        elif c in ("0", "q", "exit"):
            print(dim("  bye.\n"))
            return 0

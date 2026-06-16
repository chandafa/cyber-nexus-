# nexus_agent/collectors.py
"""
Collectors telemetri keamanan endpoint (stdlib + perintah OS bawaan).

Setiap collector mengembalikan list event:
    {type, severity, title, detail, data}
Severity: info | low | medium | high | critical.
"""
import os
import platform
import shutil
import subprocess

from nexus_common import protocol as fc

_RISK_NOTE = {
    21: "FTP (kredensial polos)", 23: "Telnet (tanpa enkripsi)", 25: "SMTP terbuka",
    135: "MSRPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 6379: "Redis (sering tanpa auth)",
    27017: "MongoDB (sering tanpa auth)",
}


def _run(cmd, timeout=8) -> str:
    try:
        kw = {}
        if platform.system() == "Windows":
            kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, **kw)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def c_system(policy):
    fp = fc.host_fingerprint()
    return [{"type": "system", "severity": "info",
             "title": f"Host {fp['hostname']} ({fp['os']} {fp['os_release']})",
             "detail": f"arch={fp['arch']} python={fp['python']} ip={fc.local_ip()}",
             "data": fp}]


def c_listening_ports(policy):
    risky_ports = set(policy.get("risky_ports", []))
    ports = set()
    if platform.system() == "Windows":
        out = _run(["netstat", "-ano", "-p", "TCP"])
        for line in out.splitlines():
            if "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 2 and ":" in parts[1]:
                    try:
                        ports.add(int(parts[1].rsplit(":", 1)[1]))
                    except ValueError:
                        pass
    else:
        out = _run(["ss", "-tlnH"]) or _run(["netstat", "-tlnp"])
        for line in out.splitlines():
            for tok in line.split():
                if ":" in tok and tok.rsplit(":", 1)[-1].isdigit():
                    try:
                        ports.add(int(tok.rsplit(":", 1)[-1]))
                    except ValueError:
                        pass
    risky = sorted(p for p in ports if p in risky_ports)
    events = [{"type": "listening_ports", "severity": "info",
               "title": f"{len(ports)} port TCP listening",
               "detail": "ports: " + ",".join(str(p) for p in sorted(ports)[:40]),
               "data": {"ports": sorted(ports), "risky": risky}}]
    for p in risky:
        events.append({"type": "exposure", "severity": "medium",
                       "title": f"Port berisiko terbuka: {p} ({_RISK_NOTE.get(p, '')})",
                       "detail": "Tinjau apakah layanan ini perlu terekspos.",
                       "data": {"port": p}})
    return events


def c_logged_users(policy):
    if platform.system() == "Windows":
        out = _run(["query", "user"])
        users = [l.split()[0].lstrip(">") for l in out.splitlines()[1:] if l.strip()]
    else:
        out = _run(["who"])
        users = list({l.split()[0] for l in out.splitlines() if l.strip()})
    return [{"type": "logged_users", "severity": "info",
             "title": f"{len(users)} sesi pengguna login",
             "detail": ", ".join(users[:20]) or "—", "data": {"users": users}}]


def c_disk(policy):
    events = []
    paths = ["C:\\"] if platform.system() == "Windows" else ["/"]
    for p in paths:
        try:
            u = shutil.disk_usage(p)
            pct = round(u.used / u.total * 100, 1)
            sev = "high" if pct >= 95 else "medium" if pct >= 90 else "info"
            events.append({"type": "disk", "severity": sev,
                           "title": f"Disk {p} terpakai {pct}%",
                           "detail": f"{u.used // (1024**3)} GB / {u.total // (1024**3)} GB",
                           "data": {"path": p, "percent": pct}})
        except Exception:
            pass
    return events


def c_firewall(policy):
    sysname = platform.system()
    on, detail = None, ""
    if sysname == "Windows":
        out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        states = [l.split()[-1].upper() for l in out.splitlines() if "State" in l]
        on = bool(states) and all(s == "ON" for s in states)
        detail = "; ".join(states) if states else "tidak terbaca"
    else:
        out = _run(["ufw", "status"])
        if out:
            on = "Status: active" in out
            detail = out.splitlines()[0] if out.strip() else ""
        else:
            out = _run(["firewall-cmd", "--state"])
            on = "running" in out
            detail = out.strip()
    if on is None:
        return [{"type": "firewall", "severity": "info",
                 "title": "Status firewall tidak terdeteksi", "detail": detail, "data": {}}]
    return [{"type": "firewall", "severity": "info" if on else "high",
             "title": "Firewall aktif" if on else "Firewall NONAKTIF",
             "detail": detail, "data": {"enabled": bool(on)}}]


def c_failed_logins(policy):
    if platform.system() == "Windows":
        return []
    count = 0
    for path in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()[-2000:]
                count = sum(1 for l in lines if "Failed password" in l)
            except Exception:
                pass
            break
    if count == 0:
        return []
    sev = "high" if count >= 50 else "medium" if count >= 10 else "low"
    return [{"type": "failed_logins", "severity": sev,
             "title": f"{count} percobaan login gagal (terbaru)",
             "detail": "Potensi brute-force SSH/login.", "data": {"count": count}}]


def c_software_inventory(policy):
    """Daftar software terpasang (Software Inventory) -> dasar Vulnerability Detection."""
    pkgs = []
    if platform.system() == "Windows":
        try:
            import winreg
            roots = [(winreg.HKEY_LOCAL_MACHINE,
                      r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                     (winreg.HKEY_LOCAL_MACHINE,
                      r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")]
            for hive, path in roots:
                try:
                    key = winreg.OpenKey(hive, path)
                except OSError:
                    continue
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                        name = winreg.QueryValueEx(sub, "DisplayName")[0]
                        try:
                            ver = winreg.QueryValueEx(sub, "DisplayVersion")[0]
                        except OSError:
                            ver = ""
                        pkgs.append({"name": name, "version": ver})
                    except OSError:
                        continue
        except Exception:
            pass
    else:
        out = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"]) or _run(["rpm", "-qa"])
        for line in out.splitlines():
            parts = line.split()
            if parts:
                pkgs.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else ""})
    seen, uniq = set(), []
    for p in pkgs:
        if p["name"] and p["name"] not in seen:
            seen.add(p["name"]); uniq.append(p)
    return [{"type": "software_inventory", "severity": "info",
             "title": f"{len(uniq)} paket software terpasang",
             "detail": ", ".join(p["name"] for p in uniq[:15]),
             "data": {"packages": uniq[:500], "count": len(uniq)}}]


def c_sca(policy):
    """Security Configuration Assessment ringan (hardening dasar)."""
    out = []
    if platform.system() == "Windows":
        g = _run(["net", "user", "guest"])
        line = next((l for l in g.splitlines() if "active" in l.lower()), "")
        active = "yes" in line.lower()
        out.append({"type": "sca", "severity": "high" if active else "info",
                    "event_type": "policy_check",
                    "title": "SCA: akun Guest " + ("AKTIF (berisiko)" if active else "nonaktif"),
                    "detail": "Akun Guest sebaiknya dinonaktifkan.",
                    "target": {"check": "guest_account"},
                    "data": {"status": "fail" if active else "pass"}})
    else:
        cfg = ""
        try:
            with open("/etc/ssh/sshd_config", encoding="utf-8", errors="replace") as f:
                cfg = f.read().lower()
        except Exception:
            pass
        if cfg:
            root_login = "permitrootlogin yes" in cfg
            out.append({"type": "sca", "severity": "high" if root_login else "info",
                        "event_type": "policy_check",
                        "title": "SCA: SSH PermitRootLogin "
                                 + ("yes (berisiko)" if root_login else "aman"),
                        "detail": "Nonaktifkan login root langsung via SSH.",
                        "target": {"check": "ssh_root_login"},
                        "data": {"status": "fail" if root_login else "pass"}})
    return out


def c_webaudit(policy):
    """PEMBEDA developer-first: audit project web (Laravel/Node) di webaudit_paths.
    Cek .env terekspos & APP_DEBUG=true."""
    out = []
    for root in policy.get("webaudit_paths", []) or []:
        env_path = os.path.join(root, ".env")
        if not os.path.isfile(env_path):
            continue
        try:
            with open(env_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            continue
        if "app_debug=true" in content.lower().replace(" ", ""):
            out.append({"type": "webaudit", "severity": "high",
                        "event_type": "app_debug_enabled",
                        "title": "Laravel APP_DEBUG=true terdeteksi",
                        "detail": f"{env_path}: APP_DEBUG aktif — bocorkan stack trace di produksi.",
                        "target": {"path": env_path}, "data": {"framework": "laravel"}})
        try:
            mode = os.stat(env_path).st_mode
            if platform.system() != "Windows" and (mode & 0o004):
                out.append({"type": "webaudit", "severity": "high",
                            "event_type": "file_modified", "title": ".env world-readable",
                            "detail": f"{env_path} dapat dibaca semua user (chmod 600).",
                            "target": {"path": env_path}, "data": {}})
        except Exception:
            pass
        out.append({"type": "webaudit", "severity": "info", "event_type": "config_found",
                    "title": "File .env ditemukan", "detail": env_path,
                    "target": {"path": env_path}, "data": {}})
    return out


REGISTRY = {
    "system": c_system, "listening_ports": c_listening_ports,
    "logged_users": c_logged_users, "disk": c_disk,
    "firewall": c_firewall, "failed_logins": c_failed_logins,
    "software_inventory": c_software_inventory, "sca": c_sca, "webaudit": c_webaudit,
}

NAMES = list(REGISTRY.keys()) + ["fim"]   # fim diproses di agent (butuh baseline)

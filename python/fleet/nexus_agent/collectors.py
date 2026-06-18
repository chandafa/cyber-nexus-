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
        # Event 4625 = logon gagal (RDP/SMB/lokal). Butuh izin baca Security log.
        out = _run(["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]",
                    "/c:200", "/rd:true", "/f:xml"], timeout=12)
        count = out.count("</Event>")
        if count == 0:
            return []
        sev = "high" if count >= 50 else "medium" if count >= 10 else "low"
        return [{"type": "failed_logins", "severity": sev,
                 "title": f"{count} login Windows gagal (Event 4625, terbaru)",
                 "detail": "Potensi brute-force RDP/SMB/lokal.", "data": {"count": count}}]
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


def _env_kv(content):
    kv = {}
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip().upper()] = v.strip().strip('"').strip("'")
    return kv


def c_webaudit(policy):
    """PEMBEDA developer-first: audit project web (Laravel/React/Next) di webaudit_paths.
    Cek konfigurasi tidak aman yang spesifik aplikasi — yang tidak dilihat EDR umum."""
    out = []

    def add(sev, etype, title, path, detail="", data=None):
        out.append({"type": "webaudit", "severity": sev, "event_type": etype,
                    "title": title, "detail": detail or title,
                    "target": {"path": path}, "data": data or {}})

    for root in policy.get("webaudit_paths", []) or []:
        if not os.path.isdir(root):
            continue
        env_path = os.path.join(root, ".env")

        # --- Laravel / .env ---
        if os.path.isfile(env_path):
            try:
                content = open(env_path, encoding="utf-8", errors="replace").read()
            except Exception:
                content = ""
            kv = _env_kv(content)
            add("info", "config_found", "File .env ditemukan", env_path)
            if kv.get("APP_DEBUG", "").lower() == "true":
                add("high", "app_debug_enabled", "Laravel APP_DEBUG=true di produksi", env_path,
                    "Bocorkan stack trace & config sensitif.", {"framework": "laravel"})
            if kv.get("APP_ENV", "").lower() in ("local", "development", "dev"):
                add("medium", "app_env_nonprod", f"APP_ENV={kv.get('APP_ENV')} (bukan production)",
                    env_path, "Set APP_ENV=production untuk deployment live.")
            if "APP_KEY" in kv and not kv.get("APP_KEY"):
                add("high", "app_key_missing", "APP_KEY kosong", env_path,
                    "Jalankan `php artisan key:generate`; enkripsi/session rentan.")
            if kv.get("DB_PASSWORD", "") in ("", "root", "password", "secret", "123456"):
                add("high", "weak_db_password", "DB_PASSWORD lemah/kosong", env_path,
                    "Gunakan password DB kuat & unik.")
            # Node/Next secret yang bocor ke client
            for k in kv:
                if k.startswith("NEXT_PUBLIC_") and any(s in k for s in ("SECRET", "KEY", "TOKEN", "PASSWORD")):
                    add("high", "public_secret_exposed", f"Secret terekspos ke client: {k}", env_path,
                        "Variabel NEXT_PUBLIC_* terbundel ke JS browser — jangan taruh rahasia.",
                        {"framework": "nextjs", "var": k})
            # perms .env (Unix)
            try:
                if platform.system() != "Windows" and (os.stat(env_path).st_mode & 0o004):
                    add("high", "env_world_readable", ".env world-readable", env_path,
                        "chmod 600 .env; saat ini dapat dibaca semua user.")
            except Exception:
                pass

        # --- .git terekspos di webroot ---
        for sub in ("public/.git", ".git"):
            gp = os.path.join(root, sub)
            if os.path.isdir(gp) and sub.startswith("public"):
                add("high", "git_exposed", "Direktori .git terekspos di webroot", gp,
                    "Source code & history bisa diunduh; pindahkan keluar dari public/.")

        # --- source map terbundel (kebocoran source) ---
        maps = 0
        for d in ("build", "dist", ".next", "public"):
            dd = os.path.join(root, d)
            if os.path.isdir(dd):
                for r, _x, names in os.walk(dd):
                    maps += sum(1 for n in names if n.endswith(".js.map"))
                    if maps > 200:
                        break
        if maps:
            add("medium", "sourcemap_exposed", f"{maps} source map (.js.map) terdeteksi",
                root, "Nonaktifkan source map produksi agar source tak terekspos.",
                {"count": maps})
    return out


# --------------------------------------------------------------------------- Log decoders (ala-Wazuh)
import re as _re

_SCANNER_UA = ("sqlmap", "nikto", "nmap", "dirbuster", "gobuster", "acunetix",
               "nessus", "masscan", "wpscan", "hydra")
_WEB_ATTACK = _re.compile(
    r"(union\s+select|select\s+.*\s+from|<script|onerror=|\.\./|/etc/passwd|"
    r"'\s*or\s*'1'\s*=\s*'1|;--|\bexec\b|base64_decode|/bin/sh)", _re.I)


def detect_logtype(path):
    p = os.path.basename(path).lower()
    if "laravel" in p or p.endswith(".log") and "storage" in path.lower():
        return "laravel"
    if "access" in p or "nginx" in p or "apache" in p:
        return "nginx"
    if "auth" in p or "secure" in p:
        return "auth"
    if "laravel" in path.lower():
        return "laravel"
    return "generic"


def _ev(sev, etype, title, data=None):
    return {"type": "log", "source": "logcollector", "severity": sev,
            "event_type": etype, "title": title[:200], "data": data or {}}


def decode_laravel(line):
    if _re.search(r"\.(EMERGENCY|CRITICAL)\b", line):
        return _ev("critical", "app_exception", "Laravel exception kritis: " + line.strip())
    if _re.search(r"\.(ERROR|ALERT)\b|production\.ERROR", line):
        return _ev("high", "app_exception", "Laravel ERROR di log: " + line.strip())
    return None


def decode_nginx(line):
    m = _re.search(r'"([A-Z]+)\s+(.*?)\s+HTTP/[\d.]+"\s+(\d{3})', line)
    if not m:
        m = _re.search(r'"([A-Z]+)\s+(\S+)"\s+(\d{3})', line)   # tanpa versi HTTP
        if not m:
            return None
    method, request, status = m.group(1), m.group(2), int(m.group(3))
    ua = (_re.findall(r'"([^"]*)"', line) or [""])[-1].lower()
    if any(s in (request.lower() + " " + ua) for s in _SCANNER_UA):
        return _ev("high", "scanner_detected",
                   f"Scanner terdeteksi di akses web: {method} {request[:80]}", {"status": status})
    if _WEB_ATTACK.search(request):
        return _ev("critical", "web_attack",
                   f"Pola serangan web di request: {method} {request[:80]}", {"status": status})
    if status == 419:
        return _ev("low", "csrf", f"CSRF token mismatch (419): {request[:80]}", {"status": 419})
    if status >= 500:
        return _ev("medium", "server_error", f"Server error {status}: {method} {request[:80]}",
                   {"status": status})
    return None


def decode_auth(line):
    if "Failed password" in line:
        return _ev("medium", "log_failed_login", "Login gagal (SSH/PAM): " + line.strip())
    if "authentication failure" in line.lower():
        return _ev("medium", "log_failed_login", "Authentication failure: " + line.strip())
    return None


def decode_generic(line):
    if _re.search(r"\b(CRITICAL|FATAL|EMERG)\b", line):
        return _ev("high", "log_error", "Log kritis: " + line.strip())
    if _re.search(r"\bERROR\b", line):
        return _ev("medium", "log_error", "Log error: " + line.strip())
    return None


_DECODERS = {"laravel": decode_laravel, "nginx": decode_nginx,
             "auth": decode_auth, "generic": decode_generic}


def decode_line(line, logtype):
    fn = _DECODERS.get(logtype, decode_generic)
    return fn(line)


_SUSPICIOUS_PROC = ("mimikatz", "ncat", "netcat", "xmrig", "cryptominer", "masscan",
                    "lazagne", "rubeus", "cobaltstrike", "metasploit", "meterpreter")


def c_processes(policy):
    """Inventori proses berjalan (Wazuh syscollector) + flag proses mencurigakan."""
    sysname = platform.system()
    procs = []
    if sysname == "Windows":
        out = _run(["tasklist", "/fo", "csv", "/nh"])
        for line in out.splitlines():
            cells = line.split('","')
            if cells:
                procs.append(cells[0].strip('"').strip())
    else:
        out = _run(["ps", "-eo", "comm"])
        procs = [l.strip() for l in out.splitlines()[1:] if l.strip()]
    procs = [p for p in procs if p]
    events = [{"type": "processes", "severity": "info", "event_type": "process_list",
               "title": f"{len(procs)} proses berjalan",
               "detail": ", ".join(sorted(set(procs))[:20]),
               "data": {"count": len(procs)}}]
    for p in sorted({x for x in procs if any(s in x.lower() for s in _SUSPICIOUS_PROC)}):
        events.append({"type": "processes", "severity": "high",
                       "event_type": "suspicious_process",
                       "title": f"Proses mencurigakan terdeteksi: {p}",
                       "target": {"process": p}, "data": {}})
    return events


def c_network(policy):
    """Inventori interface/alamat IP (Wazuh syscollector)."""
    if platform.system() == "Windows":
        out = _run(["ipconfig"])
        ips = set(_re.findall(r"IPv4.*?:\s*([\d.]+)", out))
    else:
        out = _run(["ip", "-o", "addr"]) or _run(["ifconfig"])
        ips = set(_re.findall(r"inet\s+(?:addr:)?([\d.]+)", out))
    ips.discard("127.0.0.1")
    return [{"type": "network", "severity": "info", "event_type": "network_inventory",
             "title": f"{len(ips)} alamat IP pada host",
             "detail": ", ".join(sorted(ips)) or "—", "data": {"ips": sorted(ips)}}]


REGISTRY = {
    "system": c_system, "listening_ports": c_listening_ports,
    "logged_users": c_logged_users, "disk": c_disk,
    "firewall": c_firewall, "failed_logins": c_failed_logins,
    "software_inventory": c_software_inventory, "sca": c_sca, "webaudit": c_webaudit,
    "processes": c_processes, "network": c_network,
}

# fim & logmonitor diproses di agent (butuh state: baseline/offset)
NAMES = list(REGISTRY.keys()) + ["fim", "logmonitor"]

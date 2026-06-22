# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_agent/agent.py
"""
Daemon endpoint Nexus Fleet: enroll, heartbeat, kumpulkan telemetri, kirim ke
manager dgn antrian store-and-forward, terapkan policy & perintah.
"""
import hashlib
import json
import os
import sqlite3
import time

from nexus_common import protocol as fc
from nexus_common.log import log
from nexus_agent import collectors

_RUN = True
_SEV_RANK = {s: i for i, s in enumerate(fc.SEVERITIES)}


# --------------------------------------------------------------------------- state
def _conn():
    c = sqlite3.connect(fc.agent_state_path(), timeout=10)
    c.row_factory = sqlite3.Row
    return c


def _init():
    c = _conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, payload TEXT
        );
        """
    )
    # Migrasi dari skema lama (kolom terpisah) -> simpan event utuh sebagai JSON,
    # agar field kaya (event_type/target/evidence/origin) tidak hilang saat dikirim.
    cols = {r[1] for r in c.execute("PRAGMA table_info(queue)").fetchall()}
    if "payload" not in cols:
        c.execute("DROP TABLE IF EXISTS queue")
        c.execute("CREATE TABLE queue (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "ts INTEGER, payload TEXT)")
    c.commit(); c.close()
    try:                                  # mitigasi at-rest: batasi izin file state agent
        os.chmod(fc.agent_state_path(), 0o600)
    except Exception:
        pass


def _get(key, default=None):
    c = _conn()
    row = c.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    c.close()
    return row["value"] if row else default


def _set(key, value):
    c = _conn()
    c.execute("INSERT INTO state(key,value) VALUES(?,?) "
              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    c.commit(); c.close()


def _policy():
    try:
        return json.loads(_get("policy") or "{}") or {}
    except Exception:
        return {}


def _enqueue(events):
    if not events:
        return
    c = _conn()
    for e in events:
        # Simpan event UTUH (semua field schema) sebagai JSON.
        c.execute("INSERT INTO queue(ts,payload) VALUES(?,?)",
                  (int(e.get("ts", fc.now())), json.dumps(e)))
    c.commit(); c.close()


def _queue_size():
    c = _conn()
    n = c.execute("SELECT COUNT(*) n FROM queue").fetchone()["n"]
    c.close()
    return n


# --------------------------------------------------------------------------- collect
def _effective_policy():
    """Gabungkan policy manager dgn `watch_paths` lokal agent (onboarding 1-perintah):
    arahkan FIM/web-audit/log ke project tanpa harus mengubah policy pusat."""
    pol = dict(_policy())
    try:
        watch = json.loads(_get("watch_paths", "[]") or "[]")
    except Exception:
        watch = []
    if not watch:
        return pol
    wp = list(pol.get("webaudit_paths", []))
    fp = list(pol.get("fim_paths", []))
    lp = list(pol.get("log_paths", []))
    cols = list(pol.get("collectors", collectors.NAMES))
    for w in watch:
        if os.path.isdir(w):
            wp.append(w)
            envf = os.path.join(w, ".env")
            if os.path.isfile(envf):
                fp.append(envf)
        elif w.endswith(".log") and os.path.isfile(w):
            lp.append(w)
        elif os.path.isfile(w):
            fp.append(w)
    pol["webaudit_paths"], pol["fim_paths"], pol["log_paths"] = wp, fp, lp
    for c in ("webaudit", "fim", "logmonitor"):
        if c not in cols:
            cols.append(c)
    pol["collectors"] = cols
    return pol


def collect_all():
    pol = _effective_policy()
    enabled = pol.get("collectors", collectors.NAMES)
    min_sev = _SEV_RANK.get(pol.get("min_report_severity", "info"), 0)
    out = []
    for name in enabled:
        try:
            if name == "fim":
                events = _fim_collect(pol)
            elif name == "logmonitor":
                events = _logmon_collect(pol)
            else:
                fn = collectors.REGISTRY.get(name)
                if not fn:
                    continue
                events = fn(pol)
            for e in events:
                if _SEV_RANK.get(e.get("severity", "info"), 0) >= min_sev:
                    e.setdefault("ts", fc.now())
                    e.setdefault("source", e.get("type", name))
                    e["origin"] = "real"      # item #4: telemetri agent SELALU real
                    out.append(e)
        except Exception as ex:
            log(f"[AGENT] collector {name} error: {ex}")
    return out


# --------------------------------------------------------------------------- FIM (item #1)
def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _fim_files(paths):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for n in names:
                    files.append(os.path.join(root, n))
                if len(files) > 2000:        # batasi beban
                    return files
    return files


def _fim_collect(pol):
    """File Integrity Monitoring: baseline checksum -> alert saat dibuat/diubah/dihapus."""
    paths = pol.get("fim_paths", []) or []
    if not paths:
        return []
    try:
        baseline = json.loads(_get("fim_baseline") or "{}")
    except Exception:
        baseline = {}
    had_baseline = bool(baseline)
    current, events = {}, []
    for f in _fim_files(paths):
        try:
            current[f] = _sha256(f)
        except Exception:
            continue
    for f, h in current.items():
        old = baseline.get(f)
        if old is None:
            if had_baseline:    # baru (hanya alert bila baseline sudah ada -> hindari noise run pertama)
                events.append({"type": "fim_new", "severity": "medium", "event_type": "file_created",
                               "title": f"File baru dipantau: {os.path.basename(f)}", "detail": f,
                               "target": {"path": f}, "evidence": {"new_hash": h}})
        elif old != h:
            events.append({"type": "fim_change", "severity": "high", "event_type": "file_modified",
                           "title": f"File diubah: {os.path.basename(f)}", "detail": f,
                           "target": {"path": f}, "evidence": {"old_hash": old, "new_hash": h}})
    for f, old in baseline.items():
        if f not in current:
            events.append({"type": "fim_deleted", "severity": "medium", "event_type": "file_deleted",
                           "title": f"File dihapus: {os.path.basename(f)}", "detail": f,
                           "target": {"path": f}, "evidence": {"old_hash": old}})
    _set("fim_baseline", json.dumps(current))
    return events


# --------------------------------------------------------------------------- Log Monitoring (ala-Wazuh)
def _logmon_collect(pol):
    """Pantau berkas log secara kontinu: baca HANYA baris baru (simpan offset),
    decode per tipe (laravel/nginx/auth/generic) -> event keamanan."""
    paths = pol.get("log_paths", []) or []
    if not paths:
        return []
    out = []
    for entry in paths:
        path = entry.get("path") if isinstance(entry, dict) else entry
        ltype = (entry.get("type") if isinstance(entry, dict) else "") or collectors.detect_logtype(path)
        if not path or not os.path.isfile(path):
            continue
        key = "logoff:" + path
        try:
            size = os.path.getsize(path)
            off = int(_get(key, "0") or 0)
            if off > size:            # file dirotasi/terpotong -> mulai dari awal
                off = 0
            with open(path, encoding="utf-8", errors="replace") as f:
                f.seek(off)
                lines = f.readlines(1_000_000)   # batasi beban per siklus
                new_off = f.tell()
            _set(key, str(new_off))
            for line in lines[:500]:
                line = line.rstrip("\n")
                if not line:
                    continue
                ev = collectors.decode_line(line, ltype)
                if ev:
                    ev["detail"] = line[:300]
                    ev["target"] = {"path": path}
                    out.append(ev)
        except Exception as ex:
            log(f"[AGENT] logmonitor {path} error: {ex}")
    return out


# --------------------------------------------------------------------------- networking
def _pin_path():
    return os.path.join(os.path.dirname(fc.agent_state_path()), "manager_cert.pem")


def _ensure_tls():
    """Muat sertifikat manager yang di-pin (TOFU) + sertifikat klien (mTLS) bila HTTPS.

    Fail-closed: bila belum ada pin, lakukan TOFU (ambil & simpan sertifikat manager
    pada kontak pertama) lalu verifikasi terhadapnya. TIDAK lagi default insecure —
    itu membuka MITM (pencurian agent_key saat enroll). Untuk uji, set NEXUS_TLS_INSECURE=1.
    """
    if _get("manager_scheme", "http") == "https":
        pin = _pin_path()
        if not os.path.isfile(pin):
            try:  # TOFU: pin sertifikat manager pada kontak pertama
                pem = fc.fetch_server_cert(_get("manager_host", fc.DEFAULT_MANAGER_HOST),
                                           _get("manager_port", fc.DEFAULT_MANAGER_PORT))
                os.makedirs(os.path.dirname(pin), exist_ok=True)
                with open(pin, "w", encoding="utf-8") as f:
                    f.write(pem)
            except Exception:
                pass  # gagal TOFU → tanpa pin, verifikasi default (fail-closed)
        insecure = os.environ.get("NEXUS_TLS_INSECURE") == "1"
        fc.set_client_tls(cafile=pin if os.path.isfile(pin) else "",
                          insecure=insecure,
                          clientcert=os.environ.get("NEXUS_CLIENT_CERT", ""),
                          clientkey=os.environ.get("NEXUS_CLIENT_KEY", ""))


def _murl(path):
    return fc.manager_url(_get("manager_host", fc.DEFAULT_MANAGER_HOST),
                          _get("manager_port", fc.DEFAULT_MANAGER_PORT), path,
                          scheme=_get("manager_scheme", "http"))


def enroll(manager_host, manager_port, enroll_key, name="", labels=None, tls=False, watch=None):
    _init()
    fp = fc.host_fingerprint()
    if isinstance(labels, str):
        labels = [x.strip() for x in labels.split(",") if x.strip()]
    if isinstance(watch, str):
        watch = [x.strip() for x in watch.split(",") if x.strip()]
    _set("watch_paths", json.dumps(watch or []))
    scheme = "https" if tls else "http"
    # TLS TOFU: ambil & pin sertifikat manager saat kontak pertama.
    if tls:
        try:
            with open(_pin_path(), "w", encoding="utf-8") as f:
                f.write(fc.fetch_server_cert(manager_host, manager_port))
            fc.set_client_tls(cafile=_pin_path(),
                              clientcert=os.environ.get("NEXUS_CLIENT_CERT", ""),
                              clientkey=os.environ.get("NEXUS_CLIENT_KEY", ""))
            log("[AGENT] Sertifikat manager di-pin (TLS TOFU)"
                + (" + sertifikat klien (mTLS)" if os.environ.get("NEXUS_CLIENT_CERT") else "") + ".")
        except Exception as e:
            return {"module": "fleet_agent", "ok": False, "error": f"gagal pin TLS cert: {e}"}
    body = {"name": name or fp["hostname"], "fingerprint": fp, "ip": fc.local_ip(),
            "labels": labels or []}
    # Sinkronkan jam dari server lebih dulu agar enroll tahan clock-skew.
    try:
        h = fc.get_admin(fc.manager_url(manager_host, manager_port, "/health", scheme=scheme), timeout=5)
        if h.get("time"):
            fc.set_clock_offset(int(h["time"]) - fc.now())
    except Exception:
        pass
    try:
        resp = fc.post_enroll(fc.manager_url(manager_host, manager_port, "/enroll", scheme=scheme),
                              body, enroll_key)
    except fc.HttpError as e:
        return {"module": "fleet_agent", "ok": False, "error": f"{e.status}: {e.body}"}
    except Exception as e:
        return {"module": "fleet_agent", "ok": False, "error": str(e)}
    _set("manager_host", manager_host)
    _set("manager_port", str(manager_port))
    _set("manager_scheme", scheme)
    _set("agent_id", resp["agent_id"])
    _set("agent_key", resp["agent_key"])
    _set("name", body["name"])
    _set("policy", json.dumps(resp.get("policy", {})))
    _set("policy_version", str(resp.get("policy_version", 1)))
    log(f"[AGENT] Terdaftar sebagai {resp['agent_id']} di {manager_host}:{manager_port}")
    return {"module": "fleet_agent", "ok": True, "agent_id": resp["agent_id"],
            "manager": f"{manager_host}:{manager_port}"}


def _flush_queue():
    aid, akey = _get("agent_id"), _get("agent_key")
    if not aid:
        return 0
    c = _conn()
    rows = c.execute("SELECT * FROM queue ORDER BY id ASC LIMIT 200").fetchall()
    c.close()
    if not rows:
        return 0
    events = []
    for r in rows:
        try:
            events.append(json.loads(r["payload"]))
        except Exception:
            continue
    try:
        fc.post_signed(_murl("/events"), {"events": events}, aid, akey)
    except Exception as e:
        log(f"[AGENT] Manager tak terjangkau, {len(events)} event tetap diantri ({e})")
        return 0
    ids = [r["id"] for r in rows]
    c = _conn()
    c.execute(f"DELETE FROM queue WHERE id IN ({','.join('?' * len(ids))})", ids)
    c.commit(); c.close()
    return len(ids)


def _remediation_plan(action, ip, proc):
    """Bangun daftar perintah (cmd) untuk aksi remediasi + deskripsi. (None, alasan) bila invalid."""
    import ipaddress
    import platform
    win = platform.system() == "Windows"
    if action == "block_ip":
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None, "IP tidak valid"
        cmd = (["netsh", "advfirewall", "firewall", "add", "rule", f"name=NexusBlock-{ip}",
                "dir=in", "action=block", f"remoteip={ip}"] if win
               else ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        return [cmd], f"blokir IP {ip} di firewall"
    if action == "enable_firewall":
        cmd = (["netsh", "advfirewall", "set", "allprofiles", "state", "on"] if win
               else ["ufw", "--force", "enable"])
        return [cmd], "aktifkan firewall host"
    if action == "kill_process":
        if not proc:
            return None, "nama proses kosong"
        cmd = ["taskkill", "/F", "/IM", proc] if win else ["pkill", "-f", proc]
        return [cmd], f"hentikan proses {proc}"
    if action == "disable_guest":
        cmd = ["net", "user", "guest", "/active:no"] if win else ["usermod", "-L", "guest"]
        return [cmd], "nonaktifkan akun Guest"
    if action == "harden":
        fw = (["netsh", "advfirewall", "set", "allprofiles", "state", "on"] if win
              else ["ufw", "--force", "enable"])
        guest = ["net", "user", "guest", "/active:no"] if win else ["usermod", "-L", "guest"]
        return [fw, guest], "hardening dasar (firewall + nonaktif Guest)"
    return None, "aksi tidak dikenal"


def _active_response(args):
    """Auto-remediation ("Amankan"). DEFAULT DRY-RUN demi keamanan/etika — eksekusi
    nyata hanya bila policy `active_response` aktif. Aksi: block_ip, enable_firewall,
    kill_process, disable_guest, harden."""
    import subprocess
    action = args.get("action", "")
    ip = args.get("ip", "") or args.get("target", "")
    proc = args.get("process", "")
    pol = _policy()
    cmds, detail = _remediation_plan(action, ip, proc)
    reason = None
    if cmds is None:
        reason = detail
    elif action == "block_ip":
        protected = set(pol.get("ar_protected_ips", ["127.0.0.1"])) | {"127.0.0.1", fc.local_ip()}
        if ip in protected:
            reason = f"IP {ip} dilindungi (anti tembak-kaki)"
    if reason:
        log(f"[AGENT] Active Response ditolak: {reason} (action={action}).")
        _enqueue([{"type": "response", "severity": "low", "event_type": "active_response",
                   "title": f"Active Response ditolak: {reason}",
                   "data": {"action": action, "executed": False, "reason": reason},
                   "origin": "real", "source": "response"}])
        return
    # Granular: butuh sakelar utama AND aksi ada di daftar yang diizinkan.
    glob = str(pol.get("active_response", "")).lower() in ("1", "true", "yes")
    enabled = glob and action in pol.get("ar_allowed_actions", [])
    executed = False
    if enabled:
        try:
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=15)
            executed = True
            log(f"[AGENT] Active Response DIJALANKAN: {detail}.")
        except Exception as e:
            log(f"[AGENT] Active Response gagal: {e}")
    else:
        log(f"[AGENT] (DRY-RUN) {detail} — aktifkan policy.active_response untuk eksekusi.")
    _enqueue([{"type": "response", "severity": "medium", "event_type": "active_response",
               "title": f"Active Response: {detail} ({'executed' if executed else 'dry-run'})",
               "detail": detail, "target": {"ip": ip, "process": proc},
               "data": {"action": action, "executed": executed},
               "origin": "real", "source": "response"}])


def _handle_commands(cmds):
    for cmd in cmds:
        name = cmd.get("command")
        if name == "collect_now":
            _enqueue(collect_all())
            log("[AGENT] Perintah collect_now dijalankan.")
        elif name == "respond":
            _active_response(cmd.get("args") or {})
        elif name == "ping":
            log("[AGENT] Perintah ping diterima dari manager.")
        elif name == "set_name":
            nm = (cmd.get("args") or {}).get("name")
            if nm:
                _set("name", nm)
                log(f"[AGENT] Nama agent diubah -> {nm}")


def _heartbeat():
    aid, akey = _get("agent_id"), _get("agent_key")
    try:
        resp = fc.post_signed(_murl("/heartbeat"), {"ip": fc.local_ip()}, aid, akey)
    except Exception as e:
        log(f"[AGENT] Heartbeat gagal (manager offline?): {e}")
        return
    st = resp.get("server_time")               # koreksi clock-skew dari server
    if st:
        fc.set_clock_offset(int(st) - fc.now())
    if resp.get("policy_version", 0) != int(_get("policy_version", "0") or 0):
        try:
            pol = fc.get_admin(_murl("/policy"))
            _set("policy", json.dumps(pol.get("policy", {})))
            _set("policy_version", str(pol.get("policy_version", 1)))
            log(f"[AGENT] Policy diperbarui -> versi {pol.get('policy_version')}")
        except Exception:
            pass
    _handle_commands(resp.get("commands", []))


def run_foreground(**kwargs):
    global _RUN
    _init()
    if not _get("agent_id"):
        log("[AGENT] Belum ter-enroll. Jalankan enrollment dulu.")
        return {"module": "fleet_agent", "status": "error", "error": "not_enrolled"}
    _RUN = True
    _ensure_tls()                          # muat pin TLS bila skema https
    log(f"[AGENT] Daemon mulai: {_get('agent_id')} -> "
        f"{_get('manager_scheme', 'http')}://{_get('manager_host')}:{_get('manager_port')}")
    last_hb = last_collect = 0
    _enqueue(collect_all())
    try:
        while _RUN:
            pol = _policy()
            hb_iv = int(pol.get("heartbeat_interval", fc.HEARTBEAT_INTERVAL))
            col_iv = int(pol.get("collect_interval", fc.COLLECT_INTERVAL))
            t = fc.now()
            if t - last_hb >= hb_iv:
                _heartbeat(); last_hb = t
            if t - last_collect >= col_iv:
                evts = collect_all(); _enqueue(evts)
                log(f"[AGENT] Telemetri terkumpul: {len(evts)} event (antrian={_queue_size()})")
                last_collect = t
            sent = _flush_queue()
            if sent:
                log(f"[AGENT] {sent} event terkirim ke manager.")
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    log("[AGENT] Daemon berhenti.")
    return {"module": "fleet_agent", "status": "stopped"}


def stop():
    global _RUN
    _RUN = False
    return {"module": "fleet_agent", "status": "stopped"}


def status():
    _init()
    return {"module": "fleet_agent", "enrolled": bool(_get("agent_id")),
            "agent_id": _get("agent_id", ""), "name": _get("name", ""),
            "manager_host": _get("manager_host", ""), "manager_port": _get("manager_port", ""),
            "policy_version": int(_get("policy_version", "0") or 0),
            "queue_size": _queue_size(), "collectors": collectors.NAMES}


def reset():
    import os
    try:
        if os.path.exists(fc.agent_state_path()):
            os.remove(fc.agent_state_path())
    except Exception as e:
        return {"module": "fleet_agent", "ok": False, "error": str(e)}
    return {"module": "fleet_agent", "ok": True}

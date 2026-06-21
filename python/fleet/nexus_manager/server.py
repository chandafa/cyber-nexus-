# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_manager/server.py
"""
Server pusat Nexus Fleet (analog: Wazuh manager + indexer ringan).

Endpoint API:
  POST /api/v1/enroll     -> daftar agent (enrollment key) -> agent_id + agent_key
  POST /api/v1/heartbeat  -> update last_seen, balas policy_version + perintah
  POST /api/v1/events     -> ingest telemetri (HMAC per-agent)
  GET  /api/v1/policy     -> policy aktif (publik, dipakai agent)
  POST /api/v1/policy     -> set policy (admin token)
  POST /api/v1/command    -> antri perintah ke agent (admin token)
  GET  /api/v1/agents|events|stats  -> data monitoring (admin token)
  GET  /api/v1/health     -> liveness

Selain itu menyajikan **nexus-dashboard** (UI web) di `/` bila berkasnya ada,
dan mengirim header CORS agar dashboard bisa juga dijalankan dari host lain.
"""
import json
import os
import socket
import sqlite3
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nexus_common import protocol as fc
from nexus_common import schema
from nexus_common import license as licensing
from nexus_common import cryptobox
from nexus_common.log import log
from nexus_manager import rules as ruleengine

_SERVER = None
_THREAD = None
_ENT = None


def _license_token() -> str:
    """
    Token lisensi aktif manager (urutan): config license_token (hot-reload) >
    env NEXUS_LICENSE > file lisensi desktop (~/.nexus/desktop_license.txt).

    Fallback ke lisensi desktop dilakukan eksplisit di sini supaya manager yang
    berjalan TETAP menghormati lisensi PRO/ENTERPRISE walau proses GUI menyetel
    NEXUS_LICENSE="" — satu key untuk GUI + Fleet di mesin yang sama.
    """
    t = (_get_cfg("license_token") or "").strip()
    if t:
        return t
    env = os.environ.get("NEXUS_LICENSE", "").strip()
    if env:
        return env
    if os.path.isfile(licensing._DESKTOP_LICENSE):
        return licensing._DESKTOP_LICENSE
    return ""


def ent() -> dict:
    """Hak pakai (entitlements) — dari config license_token (hot-reload) atau env. Cache per proses."""
    global _ENT
    if _ENT is None:
        _ENT = licensing.entitlements(token=_license_token())
    return _ENT


def reload_license() -> dict:
    global _ENT
    _ENT = licensing.entitlements(token=_license_token())
    return _ENT


def apply_license(token, actor="admin") -> dict:
    """Pasang lisensi pada manager yang SEDANG berjalan — tanpa restart (hot-reload)."""
    init_db()
    token = (token or "").strip()
    if token and os.path.isfile(token):
        try:
            token = open(token, encoding="utf-8").read().strip()
        except Exception as e:
            return {"ok": False, "error": f"gagal baca file lisensi: {e}"}
    res = licensing.entitlements(token=token)
    if token and not res["valid"]:
        return {"ok": False, "error": f"lisensi tidak valid: {res['reason']}"}
    _set_cfg("license_token", token)
    reload_license()
    _audit(actor, "license:apply", res.get("tier"))
    log(f"[MANAGER] Lisensi diterapkan (hot-reload) -> {res['tier'].upper()}.")
    return {"ok": True, **license_status()}


def license_status() -> dict:
    e = ent()
    return {"module": "fleet_manager", "valid": e["valid"], "tier": e["tier"],
            "licensee": e["licensee"], "max_agents": e["max_agents"],
            "features": sorted(e["features"]), "expires": e["expires"],
            "expires_iso": fc.iso(e["expires"]) if e["expires"] else "—",
            "reason": e["reason"]}

EVENT_CAP = 20000        # retensi: simpan maksimal N event terbaru
ALERT_CAP = 10000

_DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "nexus_dashboard")

DEFAULT_POLICY = {
    "heartbeat_interval": fc.HEARTBEAT_INTERVAL,
    "collect_interval": fc.COLLECT_INTERVAL,
    "collectors": ["system", "listening_ports", "logged_users", "disk",
                   "firewall", "failed_logins", "fim", "sca",
                   "software_inventory", "webaudit", "logmonitor",
                   "processes", "network"],
    "risky_ports": [21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017],
    # File Integrity Monitoring — path yang dipantau (hash baseline).
    "fim_paths": [],
    # Web/app audit — root project Laravel/Node yang dicek (.env, APP_DEBUG, dll).
    "webaudit_paths": [],
    # Log Monitoring — berkas log yang dipantau. Item: path atau {path,type}.
    # type: laravel|nginx|auth|generic (auto-deteksi bila kosong).
    "log_paths": [],
    # Active Response: false = DRY-RUN. Granular & aman by default:
    "active_response": False,                 # sakelar utama eksekusi nyata
    "ar_allowed_actions": [],                 # aksi yang BOLEH dieksekusi (kosong=tak ada)
    "ar_protected_ips": ["127.0.0.1"],        # IP yang TAK BOLEH diblokir (anti tembak-kaki)
    "min_report_severity": "info",
}


# --------------------------------------------------------------------------- DB
def _conn():
    c = sqlite3.connect(fc.manager_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    # WAL: izinkan banyak pembaca + 1 penulis (langkah kecil menuju HA; cluster
    # penuh perlu DB jaringan/Postgres — roadmap). busy_timeout cegah "db locked".
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    return c


def init_db():
    c = _conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY, agent_key TEXT NOT NULL, name TEXT,
            hostname TEXT, os TEXT, os_release TEXT, arch TEXT, ip TEXT,
            status TEXT DEFAULT 'pending', enrolled_at INTEGER,
            last_seen INTEGER DEFAULT 0, policy_version INTEGER DEFAULT 0,
            labels TEXT, meta TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, agent_id TEXT,
            tenant_id TEXT, ts INTEGER, source TEXT, type TEXT, category TEXT,
            event_type TEXT, severity TEXT, origin TEXT, title TEXT, detail TEXT,
            host TEXT, target TEXT, evidence TEXT, data TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY, ts INTEGER, agent_id TEXT, tenant_id TEXT,
            level INTEGER, severity TEXT, title TEXT, description TEXT,
            category TEXT, event_type TEXT, event_ref TEXT, rule_id TEXT,
            rule_name TEXT, mitre TEXT, recommendation TEXT, response TEXT,
            target TEXT, evidence TEXT, status TEXT DEFAULT 'open', origin TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, actor TEXT,
            action TEXT, detail TEXT
        );
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, command TEXT,
            args TEXT, status TEXT DEFAULT 'queued', created_at INTEGER, delivered_at INTEGER
        );
        """
    )
    # Siapkan tabel SecOps (XDR/SOAR/Threat-Intel) di koneksi yang SAMA agar skema
    # ter-bootstrap sekali & tak ada lock antar-koneksi saat ingest.
    try:
        from nexus_secops import correlate as _xdr, soar as _soar, threatintel as _ti
        from nexus_secops import ueba as _ueba, ai as _ai, edr as _edr, cloud as _cloud
        from nexus_secops import ndr as _ndr
        _xdr.ensure_tables(c)
        _soar.ensure_tables(c)
        _ti.ensure_tables(c)
        _ueba.ensure_tables(c)
        _ai.ensure_tables(c)
        _edr.ensure_tables(c)
        _cloud.ensure_tables(c)
        _ndr.ensure_tables(c)
    except Exception:
        pass
    c.commit()
    _migrate(c)
    c.close()
    try:                                  # mitigasi at-rest: batasi izin file DB
        os.chmod(fc.manager_db_path(), 0o600)
    except Exception:
        pass
    _ensure_config()


def _migrate(c):
    """Tambah kolom baru pada DB lama tanpa kehilangan data."""
    def cols(table):
        return {r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
    add = {
        "agents": {"labels": "TEXT"},
        "events": {"event_id": "TEXT", "tenant_id": "TEXT", "source": "TEXT",
                   "category": "TEXT", "event_type": "TEXT", "origin": "TEXT",
                   "host": "TEXT", "target": "TEXT", "evidence": "TEXT"},
    }
    for table, newcols in add.items():
        try:
            have = cols(table)
            for name, typ in newcols.items():
                if name not in have:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")
            c.commit()
        except Exception:
            pass


# Nilai rahasia di config dienkripsi at-rest bila NEXUS_MASTER_KEY diset (item #9).
_SECRET_KEYS = {"enroll_key", "admin_token", "license_token"}


def _get_cfg(key, default=None):
    c = _conn()
    row = c.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    c.close()
    if not row:
        return default
    val = row["value"]
    return cryptobox.decrypt(val) if key in _SECRET_KEYS else val


def _set_cfg(key, value):
    stored = cryptobox.encrypt(str(value)) if key in _SECRET_KEYS else str(value)
    c = _conn()
    c.execute("INSERT INTO config(key,value) VALUES(?,?) "
              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, stored))
    c.commit()
    c.close()


def _ensure_config():
    if _get_cfg("enroll_key") is None:
        _set_cfg("enroll_key", fc.gen_key())
    if _get_cfg("admin_token") is None:
        _set_cfg("admin_token", fc.gen_key())
    if _get_cfg("policy") is None:
        _set_cfg("policy", json.dumps(DEFAULT_POLICY))
        _set_cfg("policy_version", "1")
    if _get_cfg("rules") is None:
        _set_cfg("rules", json.dumps(ruleengine.DEFAULT_RULES))
    if _get_cfg("vuln_db") is None:
        from nexus_manager import vulndb
        _set_cfg("vuln_db", json.dumps(vulndb.DEFAULT_VULN_DB))
    if _get_cfg("accept_demo") is None:
        _set_cfg("accept_demo", "0")        # real findings only (item #4)
    if _get_cfg("tenant") is None:
        _set_cfg("tenant", "default")
    if _get_cfg("notify_webhook") is None:
        _set_cfg("notify_webhook", "")
        _set_cfg("notify_min_level", "12")  # default: alert high/critical -> webhook
    if _get_cfg("replay_window") is None:
        _set_cfg("replay_window", str(fc.REPLAY_WINDOW))  # toleransi clock-skew (detik)
    if _get_cfg("api_users") is None:
        _set_cfg("api_users", "{}")          # RBAC: {token: role(admin|viewer)}


def _api_users() -> dict:
    try:
        return json.loads(_get_cfg("api_users") or "{}") or {}
    except Exception:
        return {}


def _role_of_token(token) -> str:
    """admin (bootstrap admin_token atau user admin) / viewer / None."""
    if token and token == (_get_cfg("admin_token") or ""):
        return "admin"
    return _api_users().get(token)


def add_user(role="viewer", actor="admin") -> dict:
    if role not in ("admin", "viewer"):
        return {"ok": False, "error": "role harus admin|viewer"}
    users = _api_users()
    tok = fc.gen_key()
    users[tok] = role
    _set_cfg("api_users", json.dumps(users))
    _audit(actor, "user:add", role)
    return {"ok": True, "token": tok, "role": role}


def list_users() -> dict:
    users = _api_users()
    masked = [{"token_prefix": t[:8] + "…", "role": r} for t, r in users.items()]
    return {"ok": True, "users": masked, "count": len(masked)}


def _replay_window() -> int:
    try:
        return int(_get_cfg("replay_window") or fc.REPLAY_WINDOW)
    except Exception:
        return fc.REPLAY_WINDOW


def _audit(actor, action, detail=""):
    c = _conn()
    c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
              (fc.now(), actor, action, detail))
    c.commit(); c.close()


def get_rules() -> list:
    try:
        return json.loads(_get_cfg("rules") or "[]") or ruleengine.DEFAULT_RULES
    except Exception:
        return ruleengine.DEFAULT_RULES


def get_enroll_key() -> str:
    init_db(); return _get_cfg("enroll_key")


def get_admin_token() -> str:
    init_db(); return _get_cfg("admin_token")


def _policy() -> dict:
    try:
        return json.loads(_get_cfg("policy") or "{}") or DEFAULT_POLICY
    except Exception:
        return DEFAULT_POLICY


def _policy_version() -> int:
    try:
        return int(_get_cfg("policy_version") or "1")
    except Exception:
        return 1


# --------------------------------------------------------------------------- domain logic
def _enroll(body, raw, enroll_sig) -> tuple:
    if not fc.verify(_get_cfg("enroll_key"), raw, enroll_sig):
        return 401, {"error": "enrollment key tidak valid"}
    # Gerbang lisensi: batas jumlah agent sesuai tier (FREE = beberapa, PRO = seat,
    # ENTERPRISE = unlimited). Bila manager start sebelum lisensi diterapkan, ia
    # meng-cache tier FREE; muat ulang sekali di sini agar lisensi PRO yang baru
    # ditebus (desktop/env) langsung dihormati tanpa perlu restart manager.
    e = ent()
    if not e.get("valid"):
        e = reload_license()
    if e["max_agents"] is not None:
        c0 = _conn()
        n = c0.execute("SELECT COUNT(*) n FROM agents").fetchone()["n"]
        c0.close()
        if n >= e["max_agents"]:
            log(f"[MANAGER] Enrollment ditolak: batas tier {e['tier']} ({e['max_agents']} agent) tercapai.")
            return 403, {"error": f"Batas agent tier '{e['tier']}' tercapai "
                                  f"({e['max_agents']}). Upgrade lisensi untuk menambah agent.",
                         "tier": e["tier"], "max_agents": e["max_agents"]}
    fp = body.get("fingerprint", {})
    labels = body.get("labels", []) if isinstance(body.get("labels"), list) else []
    agent_id = fc.new_id("agt")
    agent_key = fc.gen_key()
    c = _conn()
    c.execute(
        "INSERT INTO agents(agent_id,agent_key,name,hostname,os,os_release,arch,ip,"
        "status,enrolled_at,last_seen,policy_version,labels,meta) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (agent_id, cryptobox.encrypt(agent_key),   # agent_key dienkripsi at-rest (item #9)
         body.get("name") or fp.get("hostname"), fp.get("hostname"),
         fp.get("os"), fp.get("os_release"), fp.get("arch"), body.get("ip", ""),
         "active", fc.now(), fc.now(), 0, json.dumps(labels), json.dumps(fp)))
    c.commit(); c.close()
    _audit("agent:" + agent_id, "enroll", f"{fp.get('hostname')} / {fp.get('os')}")
    log(f"[MANAGER] Agent terdaftar: {agent_id} ({fp.get('hostname')} / {fp.get('os')})")
    return 200, {"agent_id": agent_id, "agent_key": agent_key,
                 "policy": _policy(), "policy_version": _policy_version()}


def _auth_agent(agent_id, raw, sig):
    c = _conn()
    row = c.execute("SELECT agent_key FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    c.close()
    if not row:
        return None
    key = cryptobox.decrypt(row["agent_key"])      # dekripsi at-rest sebelum verifikasi
    return key if fc.verify(key, raw, sig) else None


def _heartbeat(agent_id, body) -> tuple:
    c = _conn()
    c.execute("UPDATE agents SET last_seen=?, status='active', ip=COALESCE(NULLIF(?,''),ip) "
              "WHERE agent_id=?", (fc.now(), body.get("ip", ""), agent_id))
    rows = c.execute("SELECT id,command,args FROM commands WHERE agent_id=? AND status='queued' "
                     "ORDER BY id ASC", (agent_id,)).fetchall()
    cmds = [{"id": r["id"], "command": r["command"], "args": json.loads(r["args"] or "{}")}
            for r in rows]
    if cmds:
        c.execute("UPDATE commands SET status='delivered', delivered_at=? "
                  "WHERE agent_id=? AND status='queued'", (fc.now(), agent_id))
    c.commit(); c.close()
    return 200, {"ok": True, "policy_version": _policy_version(), "commands": cmds,
                 "server_time": fc.now()}


def _host_for(agent_id) -> dict:
    c = _conn()
    r = c.execute("SELECT hostname,os,ip FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    c.close()
    return {"hostname": r["hostname"], "os": r["os"], "ip": r["ip"]} if r else {}


def _ingest_events(agent_id, body) -> tuple:
    evts = body.get("events", [])
    if not isinstance(evts, list):
        return 400, {"error": "events harus list"}
    accept_demo = (_get_cfg("accept_demo") or "0") == "1"
    tenant = _get_cfg("tenant") or "default"
    ruleset = get_rules()
    # Gerbang lisensi: tanpa fitur 'advanced_rules' (FREE), hanya rule tier 'free'
    # yang aktif (rule premium spt FIM .env, web-audit, dll. butuh lisensi).
    if not licensing.has(ent(), "advanced_rules"):
        ruleset = [r for r in ruleset if r.get("tier", "pro") == "free"]
    host = _host_for(agent_id)
    c = _conn()
    stored = skipped = n_alerts = 0
    for raw in evts[:500]:
        ev = schema.normalize_event(raw)
        # Item #4: real findings only — tolak demo kecuali sengaja diizinkan.
        if ev["origin"] == "demo" and not accept_demo:
            skipped += 1
            continue
        ev = schema.enrich_event(ev, agent_id=agent_id, tenant_id=tenant, host=host)
        _insert_event(c, ev, agent_id, tenant, host)
        stored += 1
        # Item #3: rule engine -> alert (dgn dedup utk kurangi alert fatigue)
        n_alerts += _run_rules(c, ev, ruleset, agent_id, tenant)
        # Vulnerability Detection: korelasi inventori software ↔ CVE (sisi manager)
        if ev["type"] == "software_inventory" and licensing.has(ent(), "advanced_rules"):
            ds, da = _correlate_vulns(c, ev, ruleset, agent_id, tenant, host)
            stored += ds
            n_alerts += da
        # Threat Intelligence: cocokkan observable event NYATA dgn IOC store -> alert.
        if licensing.has(ent(), "advanced_rules"):
            ds, da = _run_threatintel(c, ev, ruleset, agent_id, tenant, host)
            stored += ds
            n_alerts += da
        # EDR: snapshot proses NYATA (pid/ppid) -> pohon proses + deteksi garis keturunan.
        if ev.get("event_type") == "process_snapshot":
            ds, da = _run_edr(c, ev, ruleset, agent_id, tenant, host)
            stored += ds
            n_alerts += da
        # NDR: snapshot koneksi NYATA -> deteksi beaconing/scan/C2.
        if ev.get("event_type") == "network_snapshot":
            ds, da = _run_ndr(c, ev, ruleset, agent_id, tenant, host)
            stored += ds
            n_alerts += da
    c.execute("UPDATE agents SET last_seen=? WHERE agent_id=?", (fc.now(), agent_id))
    c.commit(); c.close()
    _prune()
    # XDR correlation (nexus_secops): bila ada alert baru, gabungkan sinyal lintas-
    # waktu menjadi insiden ber-kill-chain. Beroperasi atas tabel `alerts` NYATA
    # (demo sudah ditolak di atas) — bukan simulasi. Best-effort & non-fatal.
    incidents_xdr = soar_runs = 0
    if n_alerts:
        try:
            from nexus_secops import correlate as _xdr
            r = _xdr.correlate(lookback=21600, tenant=tenant)   # jendela 6 jam
            incidents_xdr = r.get("created", 0) + r.get("updated", 0)
            if r.get("fired"):
                log(f"[MANAGER] XDR: {r['created']} insiden baru, {r['updated']} diperbarui "
                    f"dari {r['scanned_alerts']} alert.")
            # AI triase otomatis insiden yang baru terbentuk/diperbarui (lokal, tanpa token).
            ids = [f["id"] for f in r.get("fired", [])]
            if ids:
                try:
                    from nexus_secops import ai as _ai
                    _ai.triage_incidents(ids, tenant=tenant)
                except Exception as e:
                    log(f"[MANAGER] AI triase dilewati: {e}")
        except Exception as e:
            log(f"[MANAGER] Korelasi XDR dilewati: {e}")
        # SOAR: jalankan playbook terhadap alert+insiden NYATA (aksi destruktif default
        # dry-run; lihat nexus_secops/soar.py). Idempoten via dedup. Best-effort.
        try:
            from nexus_secops import soar as _soar
            sr = _soar.process(lookback=21600, tenant=tenant)
            soar_runs = sr.get("fired", 0)
            if soar_runs:
                log(f"[MANAGER] SOAR: {soar_runs} playbook dijalankan "
                    f"({sr.get('executed', 0)} mengeksekusi aksi nyata).")
        except Exception as e:
            log(f"[MANAGER] SOAR dilewati: {e}")
    if stored:
        log(f"[MANAGER] {stored} event dari {agent_id} -> {n_alerts} alert"
            + (f" ({skipped} demo ditolak)" if skipped else ""))
    return 200, {"ok": True, "stored": stored, "alerts": n_alerts,
                 "skipped_demo": skipped, "xdr_incidents": incidents_xdr,
                 "soar_runs": soar_runs}


DEDUP_WINDOW = 3600   # detik: alert sama (rule+agent+target) tidak diulang dlm 1 jam


def _alert_duplicate(c, al) -> bool:
    """Cegah alert berulang identik (rule+agent+target) yang masih open/ack."""
    rule_id = al.get("rule", {}).get("id", "")
    target_json = json.dumps(al.get("target") or {})
    row = c.execute(
        "SELECT id FROM alerts WHERE rule_id=? AND agent_id=? AND status!='resolved' "
        "AND ts>=? AND target=? LIMIT 1",
        (rule_id, al["agent_id"], fc.now() - DEDUP_WINDOW, target_json)).fetchone()
    return row is not None


def _insert_event(c, ev, agent_id, tenant, host):
    c.execute(
        "INSERT INTO events(event_id,agent_id,tenant_id,ts,source,type,category,"
        "event_type,severity,origin,title,detail,host,target,evidence,data) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ev["event_id"], agent_id, tenant, ev["ts"], ev["source"], ev["type"],
         ev["category"], ev["event_type"], ev["severity"], ev["origin"],
         ev["title"], ev["detail"], json.dumps(host),
         json.dumps(ev["target"]), json.dumps(ev["evidence"]), json.dumps(ev["data"])))


def _run_rules(c, ev, ruleset, agent_id, tenant) -> int:
    n = 0
    for al in ruleengine.evaluate(ev, ruleset, agent_id, tenant):
        if _alert_duplicate(c, al):
            continue
        _insert_alert(c, al)
        _notify(al)
        n += 1
    return n


def _notify(al):
    """Kirim alert berat ke webhook (Slack/Discord/HTTP) — best-effort, non-fatal."""
    try:
        wh = _get_cfg("notify_webhook") or ""
        if not wh or al.get("level", 0) < int(_get_cfg("notify_min_level") or "12"):
            return
        text = (f"[NEXUS {al['severity'].upper()}/L{al['level']}] {al['title']} "
                f"· rule {al['rule'].get('id')} · agent {al['agent_id']}")
        payload = {"text": text, "content": text,   # Slack(text) & Discord(content)
                   "alert": {"id": al["id"], "level": al["level"], "severity": al["severity"],
                             "title": al["title"], "agent_id": al["agent_id"],
                             "rule": al["rule"].get("id"), "mitre": al["rule"].get("mitre")}}
        fc._request("POST", wh, fc.canonical(payload), {"Content-Type": "application/json"}, timeout=4)
    except Exception:
        pass


def set_notify(webhook, min_level=12, actor="admin") -> dict:
    init_db()
    _set_cfg("notify_webhook", webhook or "")
    try:
        _set_cfg("notify_min_level", str(int(min_level)))
    except Exception:
        pass
    _audit(actor, "notify:set", (webhook[:60] if webhook else "(disabled)"))
    return {"ok": True, "webhook_set": bool(webhook),
            "min_level": int(_get_cfg("notify_min_level") or "12")}


def _correlate_vulns(c, inv_ev, ruleset, agent_id, tenant, host):
    """Cocokkan paket di event software_inventory dgn vuln DB -> event+alert CVE."""
    from nexus_manager import vulndb
    pkgs = (inv_ev.get("data") or {}).get("packages", [])
    findings = vulndb.match(pkgs, get_vulndb())
    n_ev = n_al = 0
    for f in findings:
        vev = schema.normalize_event({
            "type": "vulnerability", "source": "vulndetect", "severity": f["severity"],
            "event_type": "cve_match",
            "title": f"{f['cve']}: {f['title']} — {f['package']} {f['installed']}",
            "detail": f"Terpasang {f['installed']} < perbaikan {f['fixed']} (CVSS {f.get('cvss')}).",
            "target": {"package": f["package"]},
            "evidence": {"cve": f["cve"], "installed": f["installed"], "fixed": f["fixed"],
                         "cvss": f.get("cvss")},
            "origin": "real"})
        vev = schema.enrich_event(vev, agent_id=agent_id, tenant_id=tenant, host=host)
        _insert_event(c, vev, agent_id, tenant, host)
        n_ev += 1
        n_al += _run_rules(c, vev, ruleset, agent_id, tenant)
    if findings:
        log(f"[MANAGER] Vuln detection: {len(findings)} CVE cocok dari inventori {agent_id}")
    return n_ev, n_al


def _run_threatintel(c, src_ev, ruleset, agent_id, tenant, host):
    """Cocokkan observable event NYATA dgn IOC store (nexus_secops.threatintel).
    Tiap kecocokan BARU -> event 'ioc_match' yang dijalankan lewat rule engine
    (rule NEXUS-TI-001) sehingga mengalir ke alert -> XDR -> SOAR. Non-fatal."""
    try:
        from nexus_secops import threatintel as ti
    except Exception as e:
        log(f"[MANAGER] Threat Intel dilewati: {e}")
        return 0, 0
    try:
        hits = ti.match_event(src_ev, tenant, conn=c)   # transaksi yang sama (anti-lock)
    except Exception as e:
        log(f"[MANAGER] Threat Intel match gagal: {e}")
        return 0, 0
    n_ev = n_al = 0
    for h in hits:
        if not h.get("new", True):
            continue
        is_ip = h["type"] == "ip"
        tev = schema.normalize_event({
            "type": "threat_intel", "source": "threatintel", "severity": h["severity"],
            "event_type": "ioc_match",
            "title": f"IOC cocok: {h['type']} {h['value']} ({h['threat']})",
            "detail": f"Observable {h['value']} cocok IOC dari sumber '{h['source']}' "
                      f"(confidence {h['confidence']}).",
            "target": {h["type"]: h["value"], "ip": h["value"] if is_ip else ""},
            "evidence": {"ioc_id": h["ioc_id"], "ioc_type": h["type"], "ioc_value": h["value"],
                         "threat": h["threat"], "source": h["source"],
                         "src_ip": h["value"] if is_ip else "",
                         "matched_event": src_ev.get("event_id", "")},
            "origin": "real"})
        tev = schema.enrich_event(tev, agent_id=agent_id, tenant_id=tenant, host=host)
        _insert_event(c, tev, agent_id, tenant, host)
        n_ev += 1
        n_al += _run_rules(c, tev, ruleset, agent_id, tenant)
    if n_ev:
        log(f"[MANAGER] Threat Intel: {n_ev} IOC cocok pada telemetri {agent_id}")
    return n_ev, n_al


def _run_edr(c, ev, ruleset, agent_id, tenant, host):
    """Proses snapshot proses NYATA (nexus_secops.edr): simpan inventori utk pohon
    proses, deteksi garis keturunan mencurigakan -> event suspicious_lineage ->
    rule NEXUS-EDR-001 -> alert -> XDR/SOAR/AI. Non-fatal."""
    procs = (ev.get("data") or {}).get("processes") or []
    if not procs:
        return 0, 0
    try:
        from nexus_secops import edr
        findings = edr.ingest_snapshot(agent_id, procs, tenant, conn=c)   # transaksi sama
    except Exception as e:
        log(f"[MANAGER] EDR dilewati: {e}")
        return 0, 0
    n_ev = n_al = 0
    for f in findings:
        lev = schema.normalize_event({
            "type": "process_tree", "source": "edr", "severity": f["severity"],
            "event_type": "suspicious_lineage",
            "title": f"Garis keturunan mencurigakan: {f['chain']} ({f['rule']})",
            "detail": f"{f['rule']}. Rantai {f['chain']}; cmd: {f['cmdline'][:160]}",
            "target": {"process": f["name"], "parent": f["parent_name"],
                       "pid": f["pid"], "ppid": f["ppid"]},
            "evidence": {"chain": f["chain"], "cmdline": f["cmdline"], "user": f["user"],
                         "mitre": f["mitre"], "pid": f["pid"], "ppid": f["ppid"]},
            "origin": "real"})
        lev = schema.enrich_event(lev, agent_id=agent_id, tenant_id=tenant, host=host)
        _insert_event(c, lev, agent_id, tenant, host)
        n_ev += 1
        n_al += _run_rules(c, lev, ruleset, agent_id, tenant)
    if n_ev:
        log(f"[MANAGER] EDR: {n_ev} garis keturunan mencurigakan pada {agent_id}")
    return n_ev, n_al


def _run_ndr(c, ev, ruleset, agent_id, tenant, host):
    """Proses snapshot koneksi NYATA (nexus_secops.ndr): simpan observasi flow +
    deteksi beaconing/scan/C2 -> event network_threat -> NEXUS-NDR-001 -> XDR/SOAR/AI."""
    flows = (ev.get("data") or {}).get("flows") or []
    if not flows:
        return 0, 0
    try:
        from nexus_secops import ndr
        findings = ndr.ingest_flows(agent_id, flows, tenant, conn=c)   # transaksi sama
    except Exception as e:
        log(f"[MANAGER] NDR dilewati: {e}")
        return 0, 0
    n_ev = n_al = 0
    for f in findings:
        nev = schema.normalize_event({
            "type": "network_threat", "source": "ndr", "severity": f["severity"],
            "event_type": "network_threat",
            "title": f"Ancaman jaringan ({f['kind']}): {f['detail']}",
            "detail": f["detail"],
            "target": {"ip": f["dst"], "dst": f["dst"], "dport": f.get("dport", 0),
                       "kind": f["kind"]},
            "evidence": {**f.get("evidence", {}), "src_ip": f["dst"], "mitre": f["mitre"],
                         "kind": f["kind"]},
            "origin": "real"})
        nev = schema.enrich_event(nev, agent_id=agent_id, tenant_id=tenant, host=host)
        _insert_event(c, nev, agent_id, tenant, host)
        n_ev += 1
        n_al += _run_rules(c, nev, ruleset, agent_id, tenant)
    if n_ev:
        log(f"[MANAGER] NDR: {n_ev} ancaman jaringan pada {agent_id}")
    return n_ev, n_al


def threatintel_scan(lookback=604800) -> dict:
    """Retro-hunt: pindai event NYATA `lookback` detik terakhir terhadap IOC store,
    buat alert utk kecocokan BARU (berguna setelah menambah feed). Lalu jalankan
    korelasi XDR + SOAR atas alert baru."""
    init_db()
    tenant = _get_cfg("tenant") or "default"
    ruleset = get_rules()
    c = _conn()
    rows = c.execute("SELECT * FROM events WHERE ts>=? AND type!='threat_intel' "
                     "ORDER BY id ASC", (fc.now() - int(lookback),)).fetchall()
    n_ev = n_al = scanned = 0
    for r in rows:
        ev = {"event_id": r["event_id"], "agent_id": r["agent_id"], "title": r["title"],
              "detail": r["detail"], "target": _safe_json(r["target"]),
              "evidence": _safe_json(r["evidence"]), "data": _safe_json(r["data"]),
              "host": _safe_json(r["host"]) if "host" in r.keys() else {}}
        de, da = _run_threatintel(c, ev, ruleset, r["agent_id"], tenant, ev["host"])
        n_ev += de; n_al += da; scanned += 1
    c.commit(); c.close()
    if n_al:
        try:
            from nexus_secops import correlate as _xdr
            _xdr.correlate(lookback=int(lookback), tenant=tenant)
            from nexus_secops import soar as _soar
            _soar.process(lookback=int(lookback), tenant=tenant)
        except Exception as e:
            log(f"[MANAGER] Pasca retro-hunt (XDR/SOAR) dilewati: {e}")
    return {"module": "fleet_manager", "ok": True, "scanned": scanned,
            "ti_events": n_ev, "ti_alerts": n_al}


def ueba_train(lookback=1209600) -> dict:
    """Latih baseline perilaku UEBA dari event NYATA `lookback` detik terakhir."""
    init_db()
    from nexus_secops import ueba
    return ueba.train(int(lookback), tenant=_get_cfg("tenant") or "default")


def ueba_scan(window=86400, emit=True) -> dict:
    """Skor anomali perilaku semua entitas. emit=True: anomali band 'high' diubah
    jadi event `behavior_anomaly` NYATA → rule NEXUS-UEBA-001 → alert → XDR/SOAR."""
    init_db()
    from nexus_secops import ueba
    tenant = _get_cfg("tenant") or "default"
    res = ueba.score(int(window), tenant=tenant)
    ruleset = get_rules()
    emitted = 0
    c = _conn()
    for ent in res.get("entities", []):
        if not emit or ent["band"] != "high":
            continue
        sev = ueba.band_to_severity(ent["band"])
        reasons = "; ".join(r["detail"] for r in ent["reasons"])
        bev = schema.normalize_event({
            "type": "behavior_anomaly", "source": "ueba", "severity": sev,
            "event_type": "behavior_anomaly",
            "title": f"Anomali perilaku: {ent['entity']} (skor {ent['score']})",
            "detail": f"Entitas {ent['entity']} menyimpang dari baseline — {reasons}.",
            "target": {"entity": ent["entity"]},
            "evidence": {"score": ent["score"], "band": ent["band"],
                         "reasons": ent["reasons"], "window_events": ent["window_events"]},
            "origin": "real"})
        host = _host_for(ent["entity"])
        bev = schema.enrich_event(bev, agent_id=ent["entity"], tenant_id=tenant, host=host)
        _insert_event(c, bev, ent["entity"], tenant, host)
        _run_rules(c, bev, ruleset, ent["entity"], tenant)
        emitted += 1
    c.commit(); c.close()
    if emitted:
        try:
            from nexus_secops import correlate as _xdr
            _xdr.correlate(lookback=max(int(window), 7200), tenant=tenant)
            from nexus_secops import soar as _soar
            _soar.process(lookback=max(int(window), 21600), tenant=tenant)
        except Exception as e:
            log(f"[MANAGER] Pasca UEBA (XDR/SOAR) dilewati: {e}")
        log(f"[MANAGER] UEBA: {emitted} anomali perilaku berisiko tinggi di-emit.")
    return {"module": "fleet_manager", "ok": True, "scored": res.get("scored", 0),
            "emitted": emitted, "entities": res.get("entities", [])}


def cloud_scan(resources=None, prowler=None, provider="aws", account="default") -> dict:
    """CSPM: nilai konfigurasi cloud (resources) ATAU impor keluaran Prowler, simpan
    temuan, lalu emit event `cloud_finding` NYATA → rule NEXUS-CLOUD-001 → alert →
    XDR/SOAR/AI. resources/prowler boleh string JSON atau objek."""
    init_db()
    from nexus_secops import cloud
    tenant = _get_cfg("tenant") or "default"
    if isinstance(resources, str):
        try:
            resources = json.loads(resources) if resources else None
        except Exception as e:
            return {"module": "fleet_manager", "ok": False, "error": f"resources JSON: {e}"}
    if prowler is not None:
        r = cloud.import_prowler(prowler, provider, account)
        if not r.get("ok"):
            return {"module": "fleet_manager", **r}
        findings = r["findings"]
    else:
        findings = cloud.evaluate(resources or [], provider, account)["findings"]
    ruleset = get_rules()
    c = _conn()
    cloud.store_findings(findings, tenant, conn=c)
    n_ev = n_al = 0
    for f in findings:
        cev = schema.normalize_event({
            "type": "cloud_posture", "source": "cspm", "severity": f["severity"],
            "event_type": "cloud_finding",
            "title": f"[{f.get('provider','')}/{f.get('account','')}] {f['title']} — {f['resource']}",
            "detail": f"{f['title']} ({f.get('compliance','')}). Remediasi: {f.get('remediation','')}",
            "target": {"resource": f["resource"], "resource_type": f.get("resource_type", "cloud"),
                       "provider": f.get("provider", ""), "account": f.get("account", "")},
            "evidence": {"check_id": f["check_id"], "compliance": f.get("compliance", ""),
                         "remediation": f.get("remediation", "")},
            "origin": "real"})
        cev = schema.enrich_event(cev, agent_id="cloud:" + f.get("account", "default"),
                                  tenant_id=tenant, host={})
        _insert_event(c, cev, "cloud:" + f.get("account", "default"), tenant, {})
        n_ev += 1
        n_al += _run_rules(c, cev, ruleset, "cloud:" + f.get("account", "default"), tenant)
    c.commit(); c.close()
    if n_al:
        try:
            from nexus_secops import correlate as _xdr
            _xdr.correlate(lookback=86400, tenant=tenant)
            from nexus_secops import soar as _soar
            _soar.process(lookback=86400, tenant=tenant)
        except Exception as e:
            log(f"[MANAGER] Pasca CSPM (XDR/SOAR) dilewati: {e}")
    log(f"[MANAGER] CSPM: {len(findings)} temuan, {n_al} alert dari konfigurasi cloud.")
    return {"module": "fleet_manager", "ok": True, "findings": len(findings),
            "alerts": n_al, "posture": cloud.posture(tenant)}


def cloud_findings(provider="", severity="", status="") -> dict:
    from nexus_secops import cloud
    return cloud.list_findings(provider, severity, status, 500, _get_cfg("tenant") or "default")


def cloud_posture() -> dict:
    from nexus_secops import cloud
    return cloud.posture(_get_cfg("tenant") or "default")


def ai_train() -> dict:
    init_db()
    from nexus_secops import ai
    return ai.train(_get_cfg("tenant") or "default")


def ai_triage_all(status="open") -> dict:
    init_db()
    from nexus_secops import ai
    return ai.triage_all(status, 200, _get_cfg("tenant") or "default")


def ai_triage(incident_id) -> dict:
    init_db()
    from nexus_secops import ai
    return ai.triage_incident(incident_id, _get_cfg("tenant") or "default")


def ai_list(priority="") -> dict:
    from nexus_secops import ai
    return ai.list_triage(200, priority, _get_cfg("tenant") or "default")


def ai_nl(text) -> dict:
    from nexus_secops import ai
    return ai.nl_query(text)


def ai_status() -> dict:
    from nexus_secops import ai
    return ai.model_status(_get_cfg("tenant") or "default")


def get_vulndb() -> list:
    from nexus_manager import vulndb
    try:
        return json.loads(_get_cfg("vuln_db") or "[]") or vulndb.DEFAULT_VULN_DB
    except Exception:
        return vulndb.DEFAULT_VULN_DB


def set_vulndb(db_json, actor="admin") -> dict:
    init_db()
    try:
        db = json.loads(db_json) if isinstance(db_json, str) else db_json
        assert isinstance(db, list)
    except Exception as e:
        return {"ok": False, "error": f"vuln_db harus JSON array: {e}"}
    _set_cfg("vuln_db", json.dumps(db))
    _audit(actor, "vulndb:set", f"{len(db)} entri")
    return {"ok": True, "count": len(db)}


def _insert_alert(c, al):
    rule = al.get("rule", {})
    c.execute(
        "INSERT INTO alerts(id,ts,agent_id,tenant_id,level,severity,title,description,"
        "category,event_type,event_ref,rule_id,rule_name,mitre,recommendation,response,"
        "target,evidence,status,origin) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (al["id"], al["ts"], al["agent_id"], al["tenant_id"], al["level"], al["severity"],
         al["title"], al["description"], al["category"], al["event_type"], al["event_ref"],
         rule.get("id", ""), rule.get("name", ""), json.dumps(rule.get("mitre", [])),
         rule.get("recommendation", ""), json.dumps(rule.get("response", [])),
         json.dumps(al["target"]), json.dumps(al["evidence"]), al["status"], al["origin"]))


def _prune():
    try:
        c = _conn()
        c.execute("DELETE FROM events WHERE id NOT IN "
                  "(SELECT id FROM events ORDER BY id DESC LIMIT ?)", (EVENT_CAP,))
        c.execute("DELETE FROM alerts WHERE id NOT IN "
                  "(SELECT id FROM alerts ORDER BY ts DESC LIMIT ?)", (ALERT_CAP,))
        c.commit(); c.close()
    except Exception:
        pass


# --------------------------------------------------------------------------- HTTP handler
_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token, X-Agent-Id, "
                                    "X-Signature, X-Enroll-Signature",
}

_STATIC = {".html": "text/html; charset=utf-8", ".js": "application/javascript",
           ".css": "text/css", ".svg": "image/svg+xml", ".ico": "image/x-icon"}

# Path API SecOps (semua butuh lisensi Pro/Enterprise — fitur 'secops').
_SECOPS_PREFIXES = ("/search", "/siem", "/xdr", "/ai", "/edr", "/ueba", "/ti",
                    "/cloud", "/ndr", "/soar")


def _is_secops_path(path):
    return any(path == p or path.startswith(p + "/") for p in _SECOPS_PREFIXES)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(payload)
        except Exception:
            pass

    def _send_file(self, path):
        ext = os.path.splitext(path)[1].lower()
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return self._send(404, {"error": "not found"})
        self.send_response(200)
        self.send_header("Content-Type", _STATIC.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _read(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def _role(self):
        return _role_of_token(self.headers.get("X-Admin-Token", ""))

    def _admin_ok(self):            # tulis: hanya admin
        return self._role() == "admin"

    def _can_read(self):            # baca: admin atau viewer (RBAC)
        return self._role() in ("admin", "viewer")

    def _path(self):
        p = self.path.split("?", 1)[0]
        prefix = f"/api/{fc.API_VERSION}"
        return p[len(prefix):] if p.startswith(prefix) else p

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        path = self._path()
        raw = self._read()
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return self._send(400, {"error": "JSON tidak valid"})
        # Anti-replay: tolak pesan agent yang stempel waktunya basi.
        if path in ("/enroll", "/agents/enroll", "/heartbeat", "/agents/heartbeat",
                    "/events", "/events/batch") and not fc.fresh(body, _replay_window()):
            return self._send(401, {"error": "pesan kedaluwarsa / replay ditolak"})
        if path in ("/enroll", "/agents/enroll"):
            return self._send(*_enroll(body, raw, self.headers.get("X-Enroll-Signature", "")))
        if path in ("/heartbeat", "/agents/heartbeat", "/events", "/events/batch"):
            aid = self.headers.get("X-Agent-Id", "")
            if not _auth_agent(aid, raw, self.headers.get("X-Signature", "")):
                return self._send(401, {"error": "tanda tangan agent tidak valid"})
            if path in ("/heartbeat", "/agents/heartbeat"):
                return self._send(*_heartbeat(aid, body))
            return self._send(*_ingest_events(aid, body))
        # --- admin only (tulis) ---
        if not self._admin_ok():
            role = self._role()
            # 403: terautentikasi (viewer) tapi tak berwenang · 401: tak terautentikasi
            return self._send(403 if role else 401,
                              {"error": "butuh peran admin" if role else "admin token diperlukan"})
        if path == "/policy":
            return self._send(*_set_policy_api(body))
        if path == "/command":
            return self._send(*_queue_command_api(body))
        if path == "/alerts/ack":
            r = ack_alert(body.get("id", ""), body.get("status", "ack"),
                          body.get("actor", "admin"))
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/response/actions":
            r = response_action(body.get("agent_id", ""), body.get("action", ""),
                                body.get("ip", ""), body.get("target", ""),
                                body.get("process", ""))
            return self._send(_status_for(r), r)
        if path == "/notify":
            r = set_notify(body.get("webhook", ""), body.get("min_level", 12))
            return self._send(200, r)
        if path == "/license/apply":
            r = apply_license(body.get("token", ""))
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/agents/remove":
            r = remove_agent(body.get("agent_id", ""), bool(body.get("purge", False)))
            return self._send(200 if r.get("ok") else 404, r)
        if path == "/users":
            r = add_user(body.get("role", "viewer"))
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/rules":
            r = set_rules(body.get("rules", []))
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/rules/sigma":
            r = import_sigma(body.get("sigma", body))
            return self._send(_status_for(r), r)
        if path == "/vulndb":
            r = set_vulndb(body.get("vuln_db", body))
            return self._send(200 if r.get("ok") else 400, r)
        # Gerbang lisensi SecOps (Pro/Enterprise) untuk seluruh aksi tulis SecOps.
        if _is_secops_path(path) and not licensing.has(ent(), "secops"):
            return self._send(403, {"error": "Fitur SecOps butuh lisensi Pro/Enterprise.",
                                    "feature": "secops"})
        if path == "/xdr/ack":
            from nexus_secops import correlate as xdr
            r = xdr.ack_incident(body.get("id", ""), body.get("status", "ack"))
            _audit("admin", "xdr:" + body.get("status", "ack"), body.get("id", ""))
            return self._send(200 if r.get("ok") else 404, r)
        if path == "/xdr/correlate":
            from nexus_secops import correlate as xdr
            r = xdr.correlate(int(body.get("lookback", 86400)),
                              tenant=_get_cfg("tenant") or "default")
            return self._send(200, r)
        if path == "/soar/playbook":
            from nexus_secops import soar
            r = soar.save_playbook(body.get("playbook", body),
                                   _get_cfg("tenant") or "default")
            _audit("admin", "soar:save", r.get("id", ""))
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/soar/playbook/enable":
            from nexus_secops import soar
            r = soar.set_enabled(body.get("id", ""), bool(body.get("enabled", True)))
            return self._send(200 if r.get("ok") else 404, r)
        if path == "/soar/playbook/mode":
            from nexus_secops import soar
            r = soar.set_mode(body.get("id", ""), body.get("mode", "dry_run"))
            _audit("admin", "soar:mode", f"{body.get('id', '')} -> {body.get('mode', '')}")
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/soar/playbook/delete":
            from nexus_secops import soar
            r = soar.delete_playbook(body.get("id", ""))
            return self._send(200 if r.get("ok") else 404, r)
        if path == "/soar/run":
            from nexus_secops import soar
            r = soar.run_now(body.get("id", ""), body.get("ref_id", ""),
                             _get_cfg("tenant") or "default")
            _audit("admin", "soar:run", f"{body.get('id', '')} / {body.get('ref_id', '')}")
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/ti/iocs":
            from nexus_secops import threatintel as ti
            r = ti.add_iocs(body.get("iocs", []), body.get("source", "manual"),
                            _get_cfg("tenant") or "default")
            _audit("admin", "ti:add", f"{r.get('added', 0)}+{r.get('updated', 0)}")
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/ti/import":
            from nexus_secops import threatintel as ti
            r = ti.import_feed(body.get("url", ""), body.get("fmt", "text"),
                               body.get("source"), body.get("threat", "feed"),
                               body.get("severity", "high"), int(body.get("col", 0)),
                               _get_cfg("tenant") or "default")
            _audit("admin", "ti:import", body.get("url", "")[:80])
            return self._send(200 if r.get("ok") else 400, r)
        if path == "/ti/delete":
            from nexus_secops import threatintel as ti
            r = ti.delete_ioc(body.get("id", ""))
            return self._send(200 if r.get("ok") else 404, r)
        if path == "/ti/scan":
            r = threatintel_scan(int(body.get("lookback", 604800)))
            return self._send(200, r)
        if path == "/ueba/train":
            r = ueba_train(int(body.get("lookback", 1209600)))
            _audit("admin", "ueba:train", str(r.get("trained", 0)))
            return self._send(200, r)
        if path == "/ueba/scan":
            r = ueba_scan(int(body.get("window", 86400)),
                          bool(body.get("emit", True)))
            return self._send(200, r)
        if path == "/ai/train":
            r = ai_train()
            _audit("admin", "ai:train", str(r.get("samples", 0)))
            return self._send(200, r)
        if path == "/ai/triage":
            iid = body.get("id", "")
            r = ai_triage(iid) if iid else ai_triage_all(body.get("status", "open"))
            return self._send(200, r)
        if path == "/cloud/scan":
            r = cloud_scan(body.get("resources"), body.get("prowler"),
                           body.get("provider", "aws"), body.get("account", "default"))
            return self._send(200 if r.get("ok") else 400, r)
        return self._send(404, {"error": "endpoint tidak dikenal"})

    def do_GET(self):
        full = self.path.split("?", 1)[0]
        # static dashboard — sajikan berkas apa pun di folder dashboard (html/js/css/svg/ico).
        # Aman dari path-traversal: nama dinormalisasi & wajib berada di dalam _DASHBOARD_DIR.
        if full == "/" or os.path.splitext(full)[1] in _STATIC:
            fname = "index.html" if full == "/" else full.lstrip("/")
            fpath = os.path.normpath(os.path.join(_DASHBOARD_DIR, fname))
            if (fpath == _DASHBOARD_DIR or fpath.startswith(_DASHBOARD_DIR + os.sep)) \
                    and os.path.isfile(fpath):
                return self._send_file(fpath)
        path = self._path()
        if path == "/health":
            return self._send(200, {"ok": True, "service": "nexus-manager",
                                    "version": fc.API_VERSION, "time": fc.now()})
        if path in ("/policy", "/policies"):
            return self._send(200, {"policy": _policy(), "policy_version": _policy_version()})
        if path == "/license":
            return self._send(200, license_status())
        if not self._can_read():          # RBAC: admin atau viewer boleh baca
            return self._send(401, {"error": "token admin/viewer diperlukan"})

        def _q(name, default):
            if "?" not in self.path:
                return default
            import urllib.parse as up
            q = up.parse_qs(self.path.split("?", 1)[1])
            return (q.get(name, [default]) or [default])[0]

        # --- Nexus SecOps: SIEM search + XDR incidents (lapisan analitik) ---
        # Gerbang lisensi: seluruh SecOps butuh fitur 'secops' (Pro/Enterprise).
        if _is_secops_path(path) and not licensing.has(ent(), "secops"):
            return self._send(403, {"error": "Fitur SecOps butuh lisensi Pro/Enterprise.",
                                    "feature": "secops"})
        if path == "/search":
            from nexus_secops import siem
            return self._send(200, siem.search(_q("index", "events"), _q("q", ""),
                                               int(_q("limit", "200")), _q("order", "desc")))
        if path == "/siem/stats":
            from nexus_secops import siem
            return self._send(200, siem.stats(_q("index", "events"), _q("q", ""),
                                              int(_q("buckets", "24")),
                                              _q("top_field", "event_type"),
                                              int(_q("top_n", "10"))))
        if path == "/xdr/incidents":
            from nexus_secops import correlate as xdr
            return self._send(200, xdr.list_incidents(_q("status", ""),
                                                      int(_q("limit", "200")),
                                                      _get_cfg("tenant") or "default"))
        if path == "/xdr/incident":
            from nexus_secops import correlate as xdr
            r = xdr.get_incident(_q("id", ""), _get_cfg("tenant") or "default")
            return self._send(200 if r.get("ok") else 404, r)
        if path == "/soar/playbooks":
            from nexus_secops import soar
            return self._send(200, soar.list_playbooks(_get_cfg("tenant") or "default"))
        if path == "/soar/runs":
            from nexus_secops import soar
            return self._send(200, soar.list_runs(int(_q("limit", "200")),
                                                  _get_cfg("tenant") or "default"))
        if path == "/ti/iocs":
            from nexus_secops import threatintel as ti
            return self._send(200, ti.list_iocs(_q("type", ""), _q("q", ""),
                                                int(_q("limit", "500")),
                                                _get_cfg("tenant") or "default"))
        if path == "/ti/matches":
            from nexus_secops import threatintel as ti
            return self._send(200, ti.list_matches(int(_q("limit", "200")),
                                                   _get_cfg("tenant") or "default"))
        if path == "/ti/stats":
            from nexus_secops import threatintel as ti
            return self._send(200, ti.stats(_get_cfg("tenant") or "default"))
        if path == "/ueba/baselines":
            from nexus_secops import ueba
            return self._send(200, ueba.list_baselines(_get_cfg("tenant") or "default"))
        if path == "/ueba/scores":
            from nexus_secops import ueba
            return self._send(200, ueba.list_scores(int(_q("limit", "200")), _q("band", ""),
                                                    _get_cfg("tenant") or "default"))
        if path == "/ueba/peers":
            from nexus_secops import ueba
            return self._send(200, ueba.peer_analysis(int(_q("window", "86400")),
                                                      _get_cfg("tenant") or "default"))
        if path == "/ai/triage":
            from nexus_secops import ai
            return self._send(200, ai.list_triage(int(_q("limit", "200")), _q("priority", ""),
                                                  _get_cfg("tenant") or "default"))
        if path == "/ai/incident":
            from nexus_secops import ai
            r = ai.triage_incident(_q("id", ""), _get_cfg("tenant") or "default", record=False)
            return self._send(200 if r.get("ok") else 404, r)
        if path == "/ai/model":
            return self._send(200, ai_status())
        if path == "/ai/nl":
            return self._send(200, ai_nl(_q("q", "")))
        if path == "/edr/hosts":
            from nexus_secops import edr
            return self._send(200, edr.hosts(_get_cfg("tenant") or "default"))
        if path == "/edr/tree":
            from nexus_secops import edr
            return self._send(200, edr.build_tree(_q("agent_id", ""),
                                                  _get_cfg("tenant") or "default"))
        if path == "/edr/processes":
            from nexus_secops import edr
            return self._send(200, edr.list_processes(_q("agent_id", ""), _q("q", ""),
                                                      _get_cfg("tenant") or "default"))
        if path == "/edr/ancestry":
            from nexus_secops import edr
            return self._send(200, edr.ancestry(_q("agent_id", ""), _q("pid", "0"),
                                                _get_cfg("tenant") or "default"))
        if path == "/cloud/findings":
            from nexus_secops import cloud
            return self._send(200, cloud.list_findings(_q("provider", ""), _q("severity", ""),
                                                       _q("status", ""), int(_q("limit", "500")),
                                                       _get_cfg("tenant") or "default"))
        if path == "/cloud/posture":
            return self._send(200, cloud_posture())
        if path == "/cloud/stats":
            from nexus_secops import cloud
            return self._send(200, cloud.stats(_get_cfg("tenant") or "default"))
        if path == "/ndr/flows":
            from nexus_secops import ndr
            return self._send(200, ndr.list_flows(_q("agent_id", ""), int(_q("limit", "500")),
                                                  _get_cfg("tenant") or "default"))
        if path == "/ndr/talkers":
            from nexus_secops import ndr
            return self._send(200, ndr.top_talkers(int(_q("window", "86400")),
                                                   _get_cfg("tenant") or "default"))
        if path == "/ndr/stats":
            from nexus_secops import ndr
            return self._send(200, ndr.stats(_get_cfg("tenant") or "default"))
        if path == "/agents":
            return self._send(200, {"agents": list_agents()["agents"]})
        if path == "/events":
            return self._send(200, {"events": list_events(int(_q("limit", "200")))["events"]})
        if path == "/alerts":
            return self._send(200, {"alerts": list_alerts(
                int(_q("limit", "200")), _q("status", ""), _q("severity", ""),
                int(_q("min_level", "0")))["alerts"]})
        if path == "/incidents":
            return self._send(200, incidents(_q("status", "open")))
        if path == "/users":
            if self._role() != "admin":
                return self._send(403, {"error": "hanya admin"})
            return self._send(200, list_users())
        if path == "/rules":
            return self._send(200, {"rules": get_rules()})
        if path == "/vulndb":
            return self._send(200, {"vuln_db": get_vulndb()})
        if path == "/audit":
            return self._send(200, list_audit(int(_q("limit", "200"))))
        if path == "/report":
            return self._send(200, report(_q("scope", "fleet")))
        if path == "/stats":
            return self._send(200, stats())
        return self._send(404, {"error": "endpoint tidak dikenal"})


def _status_for(r) -> int:
    """200 sukses · 403 bila terkunci lisensi (ada 'feature') · 400 lainnya."""
    if r.get("ok"):
        return 200
    return 403 if r.get("feature") else 400


def _set_policy_api(body):
    pol = body.get("policy")
    if not isinstance(pol, dict):
        return 400, {"error": "policy harus objek JSON"}
    set_policy(json.dumps(pol))
    return 200, {"ok": True, "policy_version": _policy_version()}


def _queue_command_api(body):
    r = queue_command(body.get("agent_id", ""), body.get("command", ""), body.get("args", {}))
    return (200, r) if r.get("ok") else (400, r)


# --------------------------------------------------------------------------- query helpers
def _is_online(last_seen):
    return last_seen and (fc.now() - last_seen) <= fc.OFFLINE_AFTER


def list_agents() -> dict:
    init_db()
    c = _conn()
    rows = c.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    c.close()
    agents = [{
        "agent_id": r["agent_id"], "name": r["name"], "hostname": r["hostname"],
        "os": r["os"], "os_release": r["os_release"], "arch": r["arch"], "ip": r["ip"],
        "status": "online" if _is_online(r["last_seen"]) else "offline",
        "enrolled_at": r["enrolled_at"], "last_seen": r["last_seen"],
        "last_seen_iso": fc.iso(r["last_seen"]), "policy_version": r["policy_version"],
        "labels": _safe_json(r["labels"]) if "labels" in r.keys() else [],
    } for r in rows]
    return {"module": "fleet_manager", "agents": agents}


def list_events(limit=200, agent_id="", severity="") -> dict:
    init_db()
    c = _conn()
    q = "SELECT * FROM events"
    cond, params = [], []
    if agent_id:
        cond.append("agent_id=?"); params.append(agent_id)
    if severity:
        cond.append("severity=?"); params.append(severity)
    if cond:
        q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    rows = c.execute(q, params).fetchall()
    c.close()
    events = [{
        "id": r["id"], "event_id": r["event_id"], "agent_id": r["agent_id"],
        "ts": r["ts"], "ts_iso": fc.iso(r["ts"]), "source": r["source"],
        "type": r["type"], "category": r["category"], "event_type": r["event_type"],
        "severity": r["severity"], "origin": r["origin"], "title": r["title"],
        "detail": r["detail"], "target": _safe_json(r["target"]),
        "evidence": _safe_json(r["evidence"]), "data": _safe_json(r["data"]),
    } for r in rows]
    return {"module": "fleet_manager", "events": events}


def remove_agent(agent_id, purge=False, actor="admin") -> dict:
    """Hapus pendaftaran agent (membebaskan seat lisensi). purge=True hapus juga event/alert-nya."""
    init_db()
    if not agent_id:
        return {"module": "fleet_manager", "ok": False, "error": "agent_id wajib"}
    c = _conn()
    n = c.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,)).rowcount
    c.execute("DELETE FROM commands WHERE agent_id=?", (agent_id,))
    if purge:
        c.execute("DELETE FROM events WHERE agent_id=?", (agent_id,))
        c.execute("DELETE FROM alerts WHERE agent_id=?", (agent_id,))
    c.commit(); c.close()
    if n:
        _audit(actor, "agent:remove", agent_id + (" (+purge)" if purge else ""))
        log(f"[MANAGER] Agent dihapus: {agent_id} — seat dibebaskan.")
    return {"module": "fleet_manager", "ok": n > 0, "removed": n}


def list_alerts(limit=200, status="", severity="", min_level=0) -> dict:
    init_db()
    c = _conn()
    q, cond, params = "SELECT * FROM alerts", [], []
    if status:
        cond.append("status=?"); params.append(status)
    if severity:
        cond.append("severity=?"); params.append(severity)
    if min_level:
        cond.append("level>=?"); params.append(int(min_level))
    if cond:
        q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY ts DESC LIMIT ?"
    params.append(int(limit))
    rows = c.execute(q, params).fetchall()
    c.close()
    alerts = [{
        "id": r["id"], "ts": r["ts"], "ts_iso": fc.iso(r["ts"]), "agent_id": r["agent_id"],
        "level": r["level"], "severity": r["severity"], "title": r["title"],
        "description": r["description"], "category": r["category"], "event_type": r["event_type"],
        "rule_id": r["rule_id"], "rule_name": r["rule_name"], "mitre": _safe_json(r["mitre"]),
        "recommendation": r["recommendation"], "response": _safe_json(r["response"]),
        "target": _safe_json(r["target"]), "evidence": _safe_json(r["evidence"]),
        "status": r["status"], "origin": r["origin"], "event_ref": r["event_ref"],
    } for r in rows]
    return {"module": "fleet_manager", "alerts": alerts}


def incidents(status="open") -> dict:
    """Kelompokkan alert (per agent+rule) jadi insiden -> kurangi alert fatigue (item #11)."""
    init_db()
    c = _conn()
    rows = c.execute(
        "SELECT agent_id, rule_id, rule_name, MAX(level) lvl, COUNT(*) cnt, "
        "MIN(ts) first_ts, MAX(ts) last_ts FROM alerts WHERE status=? "
        "GROUP BY agent_id, rule_id ORDER BY lvl DESC, cnt DESC", (status,)).fetchall()
    c.close()
    inc = [{"agent_id": r["agent_id"], "rule_id": r["rule_id"], "rule_name": r["rule_name"],
            "level": r["lvl"], "severity": schema.level_to_severity(r["lvl"] or 0),
            "count": r["cnt"], "first_iso": fc.iso(r["first_ts"]),
            "last_iso": fc.iso(r["last_ts"])} for r in rows]
    return {"module": "fleet_manager", "incidents": inc, "total": len(inc)}


def ack_alert(alert_id, status="ack", actor="admin") -> dict:
    init_db()
    if status not in ("open", "ack", "resolved"):
        return {"ok": False, "error": "status harus open|ack|resolved"}
    c = _conn()
    c.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
    c.commit(); c.close()
    _audit(actor, f"alert:{status}", alert_id)
    return {"ok": True, "id": alert_id, "status": status}


def import_sigma(sigma_json, actor="admin") -> dict:
    """Konversi rule Sigma (JSON) -> rule native & tambahkan ke ruleset."""
    from nexus_manager import sigma as sigmod
    init_db()
    if not licensing.has(ent(), "sigma"):
        return {"ok": False, "error": "Import Sigma butuh lisensi Pro/Enterprise.",
                "feature": "sigma"}
    try:
        data = json.loads(sigma_json) if isinstance(sigma_json, str) else sigma_json
    except Exception as e:
        return {"ok": False, "error": f"Sigma JSON tidak valid: {e}"}
    native = sigmod.convert_many(data)
    if not native:
        return {"ok": False, "error": "tidak ada rule Sigma yang valid"}
    rules = get_rules()
    ids = {r.get("id") for r in rules}
    added = [r for r in native if r["id"] not in ids]
    rules.extend(added)
    _set_cfg("rules", json.dumps(rules))
    _audit(actor, "rules:import_sigma", f"{len(added)} rule ditambah")
    return {"ok": True, "imported": len(added), "total_rules": len(rules)}


def response_action(agent_id, action, ip="", target="", process="", actor="admin") -> dict:
    """Auto-remediation ("Amankan"): antri perintah respon ke agent (dry-run default).
    Aksi: block_ip, enable_firewall, kill_process, disable_guest, harden."""
    if not licensing.has(ent(), "active_response"):
        return {"ok": False, "error": "Active Response butuh lisensi Pro/Enterprise.",
                "feature": "active_response"}
    r = queue_command(agent_id, "respond",
                      {"action": action, "ip": ip, "target": target, "process": process})
    if r.get("ok"):
        _audit(actor, "response:" + action, f"{agent_id} {ip or target}")
    return r


def set_rules(rules_json, actor="admin") -> dict:
    init_db()
    try:
        rules = json.loads(rules_json) if isinstance(rules_json, str) else rules_json
        assert isinstance(rules, list)
    except Exception as e:
        return {"ok": False, "error": f"rules harus JSON array: {e}"}
    _set_cfg("rules", json.dumps(rules))
    _audit(actor, "rules:set", f"{len(rules)} rules")
    return {"ok": True, "count": len(rules)}


def list_audit(limit=200) -> dict:
    init_db()
    c = _conn()
    rows = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    c.close()
    return {"audit": [{"ts": r["ts"], "ts_iso": fc.iso(r["ts"]), "actor": r["actor"],
                       "action": r["action"], "detail": r["detail"]} for r in rows]}


def _domain_for(rule_id: str) -> str:
    if rule_id.startswith("NEXUS-WEB"):
        return "web"
    if rule_id.startswith("NEXUS-NET"):
        return "network"
    return "server"


def posture(agent_id: str = "") -> dict:
    """Security posture score 0-100 (overall + per-domain) dari alert open.
    Mudah dipahami founder/manajer: makin tinggi makin aman."""
    init_db()
    c = _conn()
    q = "SELECT rule_id, level FROM alerts WHERE status!='resolved'"
    params = []
    if agent_id:
        q += " AND agent_id=?"; params.append(agent_id)
    rows = c.execute(q, params).fetchall()
    c.close()
    domains = {"network": 100.0, "server": 100.0, "web": 100.0}
    overall = 100.0
    for r in rows:
        # penalti progresif berdasarkan level (0-15)
        pen = (r["level"] or 0) * 1.5
        d = _domain_for(r["rule_id"] or "")
        domains[d] = max(0.0, domains[d] - pen)
        overall = max(0.0, overall - pen * 0.8)
    label = lambda s: ("baik" if s >= 80 else "perlu perhatian" if s >= 50 else "kritis")
    return {
        "overall": round(overall),
        "label": label(overall),
        "scores": {
            "network_security": round(domains["network"]),
            "server_hardening": round(domains["server"]),
            "website_security": round(domains["web"]),
        },
        "open_alerts": len(rows),
    }


def report(scope="fleet", limit=1000) -> dict:
    """Bangun report konsisten (schema nexus.report/v1) dari alert+event+agent."""
    init_db()
    alerts = list_alerts(limit)["alerts"]
    events = list_events(limit)["events"]
    agents = list_agents()["agents"]
    rep = schema.build_report(scope, alerts, events, agents)
    rep["posture"] = posture()
    return rep


def _safe_json(s):
    try:
        return json.loads(s) if s else {}
    except Exception:
        return {}


def get_policy() -> dict:
    init_db()
    return {"module": "fleet_manager", "policy": _policy(), "policy_version": _policy_version()}


def set_policy(policy_json) -> dict:
    init_db()
    try:
        pol = json.loads(policy_json) if isinstance(policy_json, str) else policy_json
    except Exception as e:
        return {"module": "fleet_manager", "ok": False, "error": f"JSON tidak valid: {e}"}
    _set_cfg("policy", json.dumps(pol))
    _set_cfg("policy_version", str(_policy_version() + 1))
    log(f"[MANAGER] Policy diperbarui -> versi {_policy_version()}")
    return {"module": "fleet_manager", "ok": True, "policy_version": _policy_version()}


def queue_command(agent_id, command, args=None) -> dict:
    init_db()
    if not agent_id or not command:
        return {"module": "fleet_manager", "ok": False, "error": "agent_id & command wajib"}
    c = _conn()
    c.execute("INSERT INTO commands(agent_id,command,args,status,created_at) VALUES(?,?,?,?,?)",
              (agent_id, command, json.dumps(args or {}), "queued", fc.now()))
    c.commit(); c.close()
    return {"module": "fleet_manager", "ok": True}


def stats() -> dict:
    init_db()
    c = _conn()
    total = c.execute("SELECT COUNT(*) n FROM agents").fetchone()["n"]
    rows = c.execute("SELECT last_seen FROM agents").fetchall()
    online = sum(1 for a in rows if _is_online(a["last_seen"]))
    ev_total = c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
    by_sev = {s: 0 for s in schema.SEVERITIES}
    for r in c.execute("SELECT severity, COUNT(*) n FROM events GROUP BY severity").fetchall():
        if r["severity"] in by_sev:
            by_sev[r["severity"]] = r["n"]
    al_total = c.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"]
    al_open = c.execute("SELECT COUNT(*) n FROM alerts WHERE status='open'").fetchone()["n"]
    al_by_sev = {s: 0 for s in schema.SEVERITIES}
    for r in c.execute("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity").fetchall():
        if r["severity"] in al_by_sev:
            al_by_sev[r["severity"]] = r["n"]
    risk = c.execute("SELECT COALESCE(SUM(level),0) s FROM alerts WHERE status!='resolved'").fetchone()["s"]
    c.close()
    return {"module": "fleet_manager", "agents_total": total, "agents_online": online,
            "agents_offline": total - online, "events_total": ev_total,
            "events_by_severity": by_sev, "alerts_total": al_total, "alerts_open": al_open,
            "alerts_by_severity": al_by_sev, "risk_score": risk, "posture": posture()}


def _probe_running(host, port):
    if _SERVER is not None:
        return True
    try:
        if fc.get_admin(fc.manager_url(host, port, "/health"), timeout=2).get("ok"):
            return True
    except Exception:
        pass
    # Deployment TLS: cek apakah ada yang mendengarkan di port (HTTPS).
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True
    except Exception:
        return False


def manager_status(host=fc.DEFAULT_MANAGER_HOST, port=fc.DEFAULT_MANAGER_PORT) -> dict:
    init_db()
    s = stats()
    e = ent()
    return {"module": "fleet_manager", "running": _probe_running(host, int(port)),
            "enroll_key": get_enroll_key(), "admin_token": get_admin_token(),
            "host": host, "port": int(port),
            "license": {"tier": e["tier"], "valid": e["valid"], "licensee": e["licensee"],
                        "max_agents": e["max_agents"], "features": sorted(e["features"])},
            **{k: v for k, v in s.items() if k != "module"}}


# --------------------------------------------------------------------------- lifecycle
_SCHEME = "http"


def _make_server(host, port):
    """Buat server; aktifkan TLS bila NEXUS_TLS_CERT/NEXUS_TLS_KEY diset."""
    global _SCHEME
    init_db()
    srv = ThreadingHTTPServer((host, port), _Handler)
    cert = os.environ.get("NEXUS_TLS_CERT", "")
    key = os.environ.get("NEXUS_TLS_KEY", "")
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            client_ca = os.environ.get("NEXUS_TLS_CLIENT_CA", "")
            if client_ca and os.path.isfile(client_ca):   # mTLS: wajib cert klien
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(client_ca)
                log("[MANAGER] mTLS aktif — agent wajib sertifikat klien tepercaya.")
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            _SCHEME = "https"
            log("[MANAGER] TLS aktif — transport terenkripsi (HTTPS).")
        except Exception as e:
            log(f"[MANAGER] Gagal aktifkan TLS ({e}) — lanjut HTTP.")
            _SCHEME = "http"
    else:
        _SCHEME = "http"
    return srv


def _banner(host, port):
    log(f"[MANAGER] Nexus Manager aktif di {_SCHEME}://{host}:{port}/api/{fc.API_VERSION}")
    log(f"[MANAGER] Dashboard      : {_SCHEME}://{host}:{port}/")
    log(f"[MANAGER] Enrollment key : {get_enroll_key()}")
    log(f"[MANAGER] Admin token    : {get_admin_token()}")
    e = ent()
    if e["valid"]:
        seats = "unlimited" if e["max_agents"] is None else e["max_agents"]
        log(f"[MANAGER] Lisensi        : {e['tier'].upper()} — {e['licensee']} "
            f"({seats} agent, exp {fc.iso(e['expires']) if e['expires'] else 'never'})")
    else:
        log(f"[MANAGER] Lisensi        : FREE (terbatas {licensing.FREE_MAX_AGENTS} agent, "
            f"fitur dasar). Pasang NEXUS_LICENSE untuk membuka Pro.")
    if cryptobox.enabled():
        log("[MANAGER] Enkripsi at-rest : AKTIF (NEXUS_MASTER_KEY).")
    log("[MANAGER] Bagikan host:port + enrollment key ke endpoint untuk mendaftarkan agent.")


def serve_blocking(host=fc.DEFAULT_MANAGER_HOST, port=fc.DEFAULT_MANAGER_PORT):
    """Jalankan server di thread utama (untuk service/standalone). Ctrl+C berhenti."""
    global _SERVER
    try:
        _SERVER = _make_server(host, int(port))
    except Exception as e:
        log(f"[MANAGER] Gagal bind {host}:{port}: {e}")
        return {"status": "error", "error": str(e)}
    _banner(host, int(port))
    try:
        _SERVER.serve_forever()
    except KeyboardInterrupt:
        log("\n[MANAGER] Dihentikan.")
    finally:
        stop()
    return {"status": "stopped"}


def _start_server(host, port):
    """Jalankan server di thread latar (untuk desktop foreground daemon)."""
    global _SERVER, _THREAD
    init_db()
    if _SERVER:
        log("[MANAGER] Server sudah berjalan")
        return True
    try:
        _SERVER = _make_server(host, port)
    except Exception as e:
        log(f"[MANAGER] Gagal bind {host}:{port}: {e}")
        return False
    _THREAD = threading.Thread(target=_SERVER.serve_forever, daemon=True)
    _THREAD.start()
    _banner(host, port)
    _ai_autostart()
    return True


def _ai_autostart():
    """AI LOKAL hidup begitu manager dijalankan: latih dari data yang ada lalu
    triase insiden terbuka. Tanpa API/token. Non-fatal."""
    try:
        from nexus_secops import ai
        r = ai.autostart(_get_cfg("tenant") or "default")
        if r.get("ok"):
            log(f"[MANAGER] Nexus AI aktif (lokal) — model {'terlatih' if r.get('trained') else 'mengumpulkan data'}"
                f" ({r.get('samples', 0)} sampel), {r.get('triaged', 0)} insiden ditriase.")
    except Exception as e:
        log(f"[MANAGER] Nexus AI autostart dilewati: {e}")


def run(host=fc.DEFAULT_MANAGER_HOST, port=str(fc.DEFAULT_MANAGER_PORT), **kwargs) -> dict:
    if not _start_server(host, int(port)):
        return {"module": "fleet_manager", "status": "error", "error": f"bind_failed:{port}"}
    return {"module": "fleet_manager", "status": "running", "host": host, "port": int(port),
            "enroll_key": get_enroll_key(), "admin_token": get_admin_token()}


def run_foreground(host=fc.DEFAULT_MANAGER_HOST, port=str(fc.DEFAULT_MANAGER_PORT), **kwargs) -> dict:
    if not _start_server(host, int(port)):
        return {"module": "fleet_manager", "status": "error", "error": f"bind_failed:{port}"}
    import time as _t
    try:
        while True:
            _t.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        stop()
    return {"module": "fleet_manager", "status": "stopped"}


def stop() -> dict:
    global _SERVER, _THREAD
    if _SERVER:
        try:
            _SERVER.shutdown(); _SERVER.server_close()
        except Exception:
            pass
    _SERVER = None
    _THREAD = None
    return {"module": "fleet_manager", "status": "stopped"}

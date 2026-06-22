# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/soar.py
"""
SOAR — Security Orchestration, Automation & Response untuk Nexus.

Memberi insiden/alert "tangan" untuk merespons otomatis (gaya Palo Alto Cortex
XSOAR / Google SecOps SOAR): sebuah *playbook* = pemicu (trigger) + langkah
(steps) berurutan, dengan riwayat eksekusi (audit).

NYATA, bukan simulasi — langkah yang menyentuh endpoint memanggil jalur active-
response Fleet yang SUNGGUHAN (`nexus_manager.server.response_action` → perintah
ke agent: block_ip / enable_firewall / kill_process / disable_guest / harden).
Notify mengirim webhook nyata. Status insiden benar-benar berubah di DB.

GERBANG KEAMANAN BERLAPIS (anti tembak-kaki):
  1. mode playbook: 'dry_run' (default utk aksi destruktif) hanya mencatat apa
     yang AKAN dilakukan; 'active' benar-benar mengeksekusi.
  2. lisensi: aksi endpoint butuh fitur 'active_response' (Pro/Enterprise).
  3. policy agent: agent hanya mengeksekusi bila policy.active_response aktif &
     aksi ada di ar_allowed_actions, dan TAK PERNAH memblokir ar_protected_ips.
Jadi playbook "otomatis" tetap aman: tak ada yang destruktif berjalan sampai
admin sengaja membuka ketiga gerbang.
"""
import json
import sqlite3
import uuid

from nexus_common import protocol as fc
from nexus_common import schema

# Aksi endpoint yang BENAR-BENAR didukung agent (lihat nexus_agent/agent.py).
# SOAR menolak aksi di luar daftar ini agar tak menjanjikan yang tak bisa dieksekusi.
AGENT_ACTIONS = {"block_ip", "enable_firewall", "kill_process", "disable_guest", "harden"}
# Aksi non-endpoint (selalu aman, langsung di manager).
MANAGER_ACTIONS = {"notify", "set_incident_status", "ack_alert", "tag"}
DESTRUCTIVE = {"block_ip", "kill_process", "disable_guest"}   # default dry_run


# --------------------------------------------------------------------------- DB
def _conn():
    c = sqlite3.connect(fc.manager_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    return c


def ensure_tables(c):
    """Buat tabel SOAR pada koneksi `c` (tanpa commit)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS soar_playbooks (
            id TEXT PRIMARY KEY, name TEXT, enabled INTEGER DEFAULT 1,
            mode TEXT DEFAULT 'dry_run', spec TEXT, tenant_id TEXT DEFAULT 'default'
        );
        CREATE TABLE IF NOT EXISTS soar_runs (
            id TEXT PRIMARY KEY, ts INTEGER, playbook_id TEXT, playbook_name TEXT,
            trigger TEXT, entity TEXT, ref_id TEXT, mode TEXT, status TEXT,
            steps TEXT, tenant_id TEXT DEFAULT 'default'
        );
        CREATE INDEX IF NOT EXISTS idx_soar_runs_ts ON soar_runs(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_soar_runs_dedup
            ON soar_runs(playbook_id, entity, ts DESC);
        """
    )


def init_db(seed=True):
    c = _conn()
    ensure_tables(c)
    c.commit()
    have = c.execute("SELECT COUNT(*) n FROM soar_playbooks").fetchone()["n"]
    c.close()
    if seed and not have:
        for pb in DEFAULT_PLAYBOOKS:
            save_playbook(pb)


# --------------------------------------------------------------------------- playbook CRUD
def _pb_row(r):
    spec = _j(r["spec"], {})
    spec.update({"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]),
                 "mode": r["mode"]})
    return spec


def list_playbooks(tenant="default"):
    init_db()
    c = _conn()
    rows = c.execute("SELECT * FROM soar_playbooks WHERE COALESCE(tenant_id,'default')=? "
                     "ORDER BY id", (tenant,)).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "playbooks": [_pb_row(r) for r in rows]}


def get_playbook(pb_id):
    init_db()
    c = _conn()
    r = c.execute("SELECT * FROM soar_playbooks WHERE id=?", (pb_id,)).fetchone()
    c.close()
    return {"ok": True, "playbook": _pb_row(r)} if r else {"ok": False, "error": "playbook tak ditemukan"}


def save_playbook(spec, tenant="default"):
    """Buat/perbarui playbook. Validasi aksi langkah agar nyata & dapat dieksekusi."""
    init_db(seed=False)
    if not isinstance(spec, dict):
        return {"ok": False, "error": "spec harus objek"}
    pb_id = spec.get("id") or ("pb_" + uuid.uuid4().hex[:10])
    name = spec.get("name") or pb_id
    enabled = 1 if spec.get("enabled", True) else 0
    mode = spec.get("mode", "dry_run")
    if mode not in ("dry_run", "active"):
        return {"ok": False, "error": "mode harus dry_run|active"}
    steps = spec.get("steps", [])
    if not isinstance(steps, list) or not steps:
        return {"ok": False, "error": "steps harus daftar tak kosong"}
    for st in steps:
        act = (st or {}).get("action")
        if act not in AGENT_ACTIONS | MANAGER_ACTIONS:
            return {"ok": False, "error": f"aksi tak dikenal/tak didukung: '{act}'"}
    clean = {"trigger": spec.get("trigger", {}), "steps": steps,
             "dedup_window": int(spec.get("dedup_window", 3600))}
    c = _conn()
    c.execute(
        "INSERT INTO soar_playbooks(id,name,enabled,mode,spec,tenant_id) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name, enabled=excluded.enabled, "
        "mode=excluded.mode, spec=excluded.spec",
        (pb_id, name, enabled, mode, json.dumps(clean), tenant))
    c.commit(); c.close()
    return {"ok": True, "id": pb_id, "name": name, "mode": mode, "enabled": bool(enabled)}


def delete_playbook(pb_id):
    init_db(seed=False)
    c = _conn()
    n = c.execute("DELETE FROM soar_playbooks WHERE id=?", (pb_id,)).rowcount
    c.commit(); c.close()
    return {"ok": n > 0, "removed": n}


def set_enabled(pb_id, enabled):
    init_db(seed=False)
    c = _conn()
    n = c.execute("UPDATE soar_playbooks SET enabled=? WHERE id=?",
                  (1 if enabled else 0, pb_id)).rowcount
    c.commit(); c.close()
    return {"ok": n > 0, "id": pb_id, "enabled": bool(enabled)}


def set_mode(pb_id, mode):
    if mode not in ("dry_run", "active"):
        return {"ok": False, "error": "mode harus dry_run|active"}
    init_db(seed=False)
    c = _conn()
    n = c.execute("UPDATE soar_playbooks SET mode=? WHERE id=?", (mode, pb_id)).rowcount
    c.commit(); c.close()
    return {"ok": n > 0, "id": pb_id, "mode": mode}


# --------------------------------------------------------------------------- trigger matching
def _as_list(v):
    return v if isinstance(v, list) else [v]


def _match(obj, cond):
    """Cocokkan alert ATAU incident terhadap kondisi trigger (toleran field hilang)."""
    for key, want in (cond or {}).items():
        if key == "severity_gte":
            if schema.severity_to_level(obj.get("severity")) < schema.severity_to_level(want):
                return False
        elif key == "level_gte":
            if int(obj.get("level", 0)) < int(want):
                return False
        elif key in ("rule_id", "event_type", "category", "status"):
            if str(obj.get(key, "")).lower() not in [str(x).lower() for x in _as_list(want)]:
                return False
        elif key == "entity":
            ent = obj.get("entity") or obj.get("agent_id", "")
            if str(ent).lower() not in [str(x).lower() for x in _as_list(want)]:
                return False
        elif key == "mitre":
            mitre = obj.get("mitre") or []
            if not any(m in mitre for m in _as_list(want)):
                return False
        elif key == "title_contains":
            if str(want).lower() not in str(obj.get("title", "")).lower():
                return False
        else:
            return False
    return True


# --------------------------------------------------------------------------- context extraction
def _dig(obj, keys):
    for src in (obj.get("target") or {}, obj.get("evidence") or {}):
        if isinstance(src, dict):
            for k in keys:
                if src.get(k):
                    return str(src[k])
    return ""


def _context_from_alert(al):
    return {"agent_id": al.get("agent_id", ""),
            "ip": _dig(al, ("src_ip", "ip", "source_ip", "remote_ip")),
            "process": _dig(al, ("process", "name", "proc")),
            "entity": al.get("agent_id", ""), "trigger": "alert",
            "ref_id": al.get("id", ""), "obj": al}


def _context_from_incident(inc):
    """Ambil IP/proses dari salah satu alert kontributor insiden (data nyata)."""
    ip = proc = ""
    ids = inc.get("alert_ids") or []
    if ids:
        c = _conn()
        ph = ",".join("?" * len(ids))
        rows = c.execute(f"SELECT target, evidence FROM alerts WHERE id IN ({ph})", ids).fetchall()
        c.close()
        for r in rows:
            al = {"target": _j(r["target"], {}), "evidence": _j(r["evidence"], {})}
            ip = ip or _dig(al, ("src_ip", "ip", "source_ip", "remote_ip"))
            proc = proc or _dig(al, ("process", "name", "proc"))
    return {"agent_id": inc.get("entity", "") if inc.get("entity_type", "agent_id") == "agent_id" else "",
            "ip": ip, "process": proc, "entity": inc.get("entity", ""),
            "trigger": "incident", "ref_id": inc.get("id", ""), "obj": inc}


# --------------------------------------------------------------------------- step executor
def _send_webhook(text):
    from nexus_manager import server as mgr
    wh = (mgr._get_cfg("notify_webhook") or "").strip()
    if not wh:
        return False, "tak ada webhook terkonfigurasi"
    try:
        payload = {"text": text, "content": text}
        fc._request("POST", wh, fc.canonical(payload),
                    {"Content-Type": "application/json"}, timeout=4)
        return True, "webhook terkirim"
    except Exception as e:
        return False, f"webhook gagal: {e}"


def _exec_step(step, ctx, mode):
    """Eksekusi satu langkah. Mengembalikan record hasil (untuk audit).
    status: executed | dry_run | gated | skipped | error."""
    action = (step or {}).get("action", "")
    params = (step or {}).get("params", {}) or {}
    base = {"action": action}

    if action == "notify":
        msg = params.get("message") or _default_msg(ctx)
        ok, detail = _send_webhook(msg)
        return {**base, "status": "executed" if ok else "skipped", "detail": detail}

    if action == "set_incident_status":
        if ctx["trigger"] != "incident":
            return {**base, "status": "skipped", "detail": "hanya untuk trigger insiden"}
        from nexus_secops import correlate as xdr
        r = xdr.ack_incident(ctx["ref_id"], params.get("status", "ack"))
        return {**base, "status": "executed" if r.get("ok") else "error",
                "detail": f"insiden -> {params.get('status', 'ack')}"}

    if action == "ack_alert":
        if ctx["trigger"] != "alert":
            return {**base, "status": "skipped", "detail": "hanya untuk trigger alert"}
        from nexus_manager import server as mgr
        r = mgr.ack_alert(ctx["ref_id"], params.get("status", "ack"))
        return {**base, "status": "executed" if r.get("ok") else "error",
                "detail": f"alert -> {params.get('status', 'ack')}"}

    if action == "tag":
        return {**base, "status": "executed", "detail": "tag: " + str(params.get("text", ""))}

    # --- aksi endpoint (nyata via Fleet active-response) ---
    if action in AGENT_ACTIONS:
        agent_id = ctx.get("agent_id", "")
        ip = params.get("ip") or ctx.get("ip", "")
        process = params.get("process") or ctx.get("process", "")
        target = params.get("target", "")
        if not agent_id:
            return {**base, "status": "skipped", "detail": "tak ada agent_id pada konteks"}
        if action == "block_ip" and not ip:
            return {**base, "status": "skipped", "detail": "tak ada IP penyerang pada bukti"}
        if action == "kill_process" and not process:
            return {**base, "status": "skipped", "detail": "tak ada nama proses pada bukti"}
        if mode != "active":
            return {**base, "status": "dry_run",
                    "detail": f"AKAN {action} (agent {agent_id}"
                              + (f", ip {ip}" if ip else "")
                              + (f", proc {process}" if process else "")
                              + ") — aktifkan mode 'active' untuk eksekusi"}
        from nexus_manager import server as mgr
        r = mgr.response_action(agent_id, action, ip, target, process)
        if r.get("ok"):
            return {**base, "status": "executed",
                    "detail": f"perintah {action} diantrikan ke agent {agent_id}"}
        if r.get("feature"):                       # terkunci lisensi
            return {**base, "status": "gated",
                    "detail": "butuh lisensi Pro/Enterprise (active_response)"}
        return {**base, "status": "error", "detail": r.get("error", "gagal")}

    return {**base, "status": "error", "detail": f"aksi tak dikenal: {action}"}


def _default_msg(ctx):
    o = ctx["obj"]
    return (f"[NEXUS SOAR] {ctx['trigger']} '{o.get('name') or o.get('title', '')}' "
            f"· entity {ctx['entity']} · severity {o.get('severity', '?')}")


# --------------------------------------------------------------------------- engine
def _recent_run(c, pb_id, entity, window):
    row = c.execute(
        "SELECT id FROM soar_runs WHERE playbook_id=? AND entity=? AND ts>=? LIMIT 1",
        (pb_id, entity, fc.now() - int(window))).fetchone()
    return row is not None


def _record_run(rec):
    c = _conn()
    c.execute(
        "INSERT INTO soar_runs(id,ts,playbook_id,playbook_name,trigger,entity,ref_id,"
        "mode,status,steps,tenant_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (rec["id"], rec["ts"], rec["playbook_id"], rec["playbook_name"], rec["trigger"],
         rec["entity"], rec["ref_id"], rec["mode"], rec["status"],
         json.dumps(rec["steps"]), rec.get("tenant_id", "default")))
    c.commit(); c.close()


def _run_playbook(pb, ctx, tenant):
    steps = [_exec_step(st, ctx, pb.get("mode", "dry_run")) for st in pb.get("steps", [])]
    status = ("executed" if any(s["status"] == "executed" for s in steps)
              else "dry_run" if any(s["status"] == "dry_run" for s in steps)
              else "gated" if any(s["status"] == "gated" for s in steps)
              else "skipped")
    rec = {"id": "run_" + uuid.uuid4().hex[:12], "ts": fc.now(),
           "playbook_id": pb["id"], "playbook_name": pb["name"], "trigger": ctx["trigger"],
           "entity": ctx["entity"], "ref_id": ctx["ref_id"], "mode": pb.get("mode", "dry_run"),
           "status": status, "steps": steps, "tenant_id": tenant}
    _record_run(rec)
    return rec


def _fetch_recent_alerts(lookback, tenant):
    c = _conn()
    rows = c.execute(
        "SELECT id, ts, agent_id, level, severity, title, category, event_type, rule_id, "
        "mitre, target, evidence, status FROM alerts WHERE ts>=? AND "
        "COALESCE(tenant_id,'default')=? ORDER BY ts ASC",
        (fc.now() - int(lookback), tenant)).fetchall()
    c.close()
    out = []
    for r in rows:
        d = dict(r)
        d["mitre"] = _j(r["mitre"], [])
        d["target"] = _j(r["target"], {})
        d["evidence"] = _j(r["evidence"], {})
        out.append(d)
    return out


def _fetch_recent_incidents(lookback, tenant):
    c = _conn()
    try:
        rows = c.execute(
            "SELECT id, rule_id, name, entity, entity_type, level, severity, status, "
            "last_ts, mitre, alert_ids FROM xdr_incidents WHERE last_ts>=? AND "
            "COALESCE(tenant_id,'default')=? ORDER BY last_ts ASC",
            (fc.now() - int(lookback), tenant)).fetchall()
    except sqlite3.Error:
        rows = []
    c.close()
    out = []
    for r in rows:
        d = dict(r)
        d["mitre"] = _j(r["mitre"], [])
        d["alert_ids"] = _j(r["alert_ids"], [])
        out.append(d)
    return out


def process(lookback=21600, tenant="default"):
    """Jalankan semua playbook aktif terhadap alert+insiden nyata `lookback` detik
    terakhir. Idempoten via dedup (playbook+entity dalam dedup_window) sehingga aman
    dipanggil tiap ingest. Mengembalikan ringkasan eksekusi."""
    init_db()
    pbs = [p for p in list_playbooks(tenant)["playbooks"] if p.get("enabled")]
    if not pbs:
        return {"ok": True, "module": "nexus_secops", "runs": [], "executed": 0}
    alerts = _fetch_recent_alerts(lookback, tenant)
    incidents = _fetch_recent_incidents(lookback, tenant)
    runs = []
    c = _conn()
    for pb in pbs:
        trig = pb.get("trigger", {})
        on = trig.get("on", "alert")
        cond = trig.get("conditions", {})
        window = int(pb.get("dedup_window", 3600))
        objs = incidents if on == "incident" else alerts
        for obj in objs:
            if not _match(obj, cond):
                continue
            ctx = _context_from_incident(obj) if on == "incident" else _context_from_alert(obj)
            if _recent_run(c, pb["id"], ctx["entity"], window):
                continue
            # `c` hanya membaca (SELECT autocommit) — _run_playbook/_record_run memakai
            # koneksi sendiri. Jangan tutup/buka-ulang `c` (dulu: bila _run_playbook
            # raise, iterasi berikut memakai koneksi tertutup). _recent_run tetap melihat
            # run baru karena _record_run commit di koneksi terpisah.
            runs.append(_run_playbook(pb, ctx, tenant))
    c.close()
    executed = sum(1 for r in runs if r["status"] == "executed")
    return {"ok": True, "module": "nexus_secops", "runs": runs,
            "fired": len(runs), "executed": executed}


def run_now(playbook_id, ref_id, tenant="default"):
    """Pemicu manual: jalankan satu playbook terhadap alert/insiden tertentu (analis
    menekan 'Run'). Mengabaikan dedup & enabled — eksekusi sesuai mode playbook."""
    init_db()
    g = get_playbook(playbook_id)
    if not g.get("ok"):
        return g
    pb = g["playbook"]
    on = pb.get("trigger", {}).get("on", "alert")
    if not ref_id:
        # Run manual ad-hoc TANPA ref (analis menekan 'Run' dari GUI/mobile/CLI tanpa
        # memilih alert/insiden). Jalankan playbook sesuai mode-nya (dry_run = aman);
        # aksi yang butuh ip/proses jadi no-op/gated, langkah notify tetap jalan.
        ctx = {"agent_id": "", "ip": "", "process": "", "entity": "manual",
               "trigger": "manual", "ref_id": "", "obj": {}}
    elif on == "incident":
        from nexus_secops import correlate as xdr
        r = xdr.get_incident(ref_id, tenant)
        if not r.get("ok"):
            return {"ok": False, "error": "insiden tak ditemukan"}
        inc = r["incident"]; inc["entity_type"] = inc.get("entity_type", "agent_id")
        ctx = _context_from_incident(inc)
    else:
        al = _one_alert(ref_id)
        if not al:
            return {"ok": False, "error": "alert tak ditemukan"}
        ctx = _context_from_alert(al)
    rec = _run_playbook(pb, ctx, tenant)
    return {"ok": True, "run": rec, "manual": not ref_id}


def _one_alert(alert_id):
    c = _conn()
    r = c.execute("SELECT id, ts, agent_id, level, severity, title, category, event_type, "
                  "rule_id, mitre, target, evidence, status FROM alerts WHERE id=?",
                  (alert_id,)).fetchone()
    c.close()
    if not r:
        return None
    d = dict(r)
    d["mitre"] = _j(r["mitre"], []); d["target"] = _j(r["target"], {})
    d["evidence"] = _j(r["evidence"], {})
    return d


def list_runs(limit=200, tenant="default"):
    init_db()
    c = _conn()
    rows = c.execute("SELECT * FROM soar_runs WHERE COALESCE(tenant_id,'default')=? "
                     "ORDER BY ts DESC LIMIT ?", (tenant, int(limit))).fetchall()
    c.close()
    runs = [{"id": r["id"], "ts": r["ts"], "ts_iso": fc.iso(r["ts"]),
             "playbook_id": r["playbook_id"], "playbook_name": r["playbook_name"],
             "trigger": r["trigger"], "entity": r["entity"], "ref_id": r["ref_id"],
             "mode": r["mode"], "status": r["status"], "steps": _j(r["steps"], [])}
            for r in rows]
    return {"ok": True, "module": "nexus_secops", "runs": runs, "total": len(runs)}


def _j(s, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except Exception:
        return default if default is not None else {}


# --------------------------------------------------------------------------- default playbooks
# Dipicu oleh sinyal/insiden NYATA yang diproduksi mesin deteksi & korelasi Nexus.
# Aksi destruktif default 'dry_run' — admin mengubah ke 'active' saat siap.
DEFAULT_PLAYBOOKS = [
    {
        "id": "PB-CRITICAL-NOTIFY", "name": "Beritahu tim saat alert kritis",
        "enabled": True, "mode": "active",          # notify aman → aktif default
        "trigger": {"on": "alert", "conditions": {"severity_gte": "critical"}},
        "dedup_window": 600,
        "steps": [{"action": "notify"}],
    },
    {
        "id": "PB-INTRUSION-RESPOND",
        "name": "Tanggap intrusi: blokir penyerang + hardening + akui insiden",
        "enabled": True, "mode": "dry_run",
        "trigger": {"on": "incident", "conditions": {"rule_id": "XDR-INTRUSION-001"}},
        "dedup_window": 3600,
        "steps": [
            {"action": "notify"},
            {"action": "block_ip"},
            {"action": "harden"},
            {"action": "set_incident_status", "params": {"status": "ack"}},
        ],
    },
    {
        "id": "PB-WEBATTACK-BLOCK", "name": "Blokir IP sumber serangan web",
        "enabled": True, "mode": "dry_run",
        "trigger": {"on": "alert", "conditions": {"event_type": "web_attack"}},
        "dedup_window": 1800,
        "steps": [{"action": "notify"}, {"action": "block_ip"}],
    },
    {
        "id": "PB-SUSPROC-KILL", "name": "Hentikan proses mencurigakan di endpoint",
        "enabled": True, "mode": "dry_run",
        "trigger": {"on": "alert", "conditions": {"rule_id": "NEXUS-PROC-001"}},
        "dedup_window": 1800,
        "steps": [{"action": "notify"}, {"action": "kill_process"}],
    },
    {
        "id": "PB-FIREWALL-ON", "name": "Aktifkan firewall saat terdeteksi nonaktif",
        "enabled": True, "mode": "dry_run",
        "trigger": {"on": "alert", "conditions": {"rule_id": "NEXUS-FW-001"}},
        "dedup_window": 3600,
        "steps": [{"action": "notify"}, {"action": "enable_firewall"}],
    },
    {
        "id": "PB-TI-BLOCK", "name": "Blokir IOC saat indikator ancaman cocok",
        "enabled": True, "mode": "dry_run",
        "trigger": {"on": "alert", "conditions": {"event_type": "ioc_match"}},
        "dedup_window": 1800,
        "steps": [{"action": "notify"}, {"action": "block_ip"}],
    },
    {
        "id": "PB-UEBA-NOTIFY", "name": "Beritahu analis saat anomali perilaku entitas",
        "enabled": True, "mode": "active",            # hanya notify → aman aktif
        "trigger": {"on": "alert", "conditions": {"event_type": "behavior_anomaly"}},
        "dedup_window": 3600,
        "steps": [{"action": "notify"}, {"action": "ack_alert", "params": {"status": "ack"}}],
    },
    {
        "id": "PB-CLOUD-NOTIFY", "name": "Beritahu tim cloud saat misconfig berisiko",
        "enabled": True, "mode": "active",            # notify aman; remediasi cloud manual/provider
        "trigger": {"on": "alert", "conditions": {"event_type": "cloud_finding",
                                                  "severity_gte": "high"}},
        "dedup_window": 7200,
        "steps": [{"action": "notify"}],
    },
    {
        "id": "PB-NDR-BLOCK", "name": "Blokir tujuan C2/beaconing saat ancaman jaringan",
        "enabled": True, "mode": "dry_run",
        "trigger": {"on": "alert", "conditions": {"event_type": "network_threat"}},
        "dedup_window": 1800,
        "steps": [{"action": "notify"}, {"action": "block_ip"}],
    },
]

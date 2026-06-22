# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/correlate.py
"""
XDR Correlation — gabungkan banyak alert menjadi SATU insiden ber-kill-chain.

Mesin rule manager (nexus_manager/rules.py) bersifat *per-event*: satu event →
satu alert. Itu bagus untuk deteksi, tapi analis tenggelam dalam alert lepas dan
tak melihat *rangkaian serangan*. Inilah yang dilakukan XDR (Microsoft Defender
XDR, Palo Alto Cortex XDR): mengkorelasikan sinyal lintas-waktu & lintas-sumber
menjadi insiden tunggal yang menceritakan kill-chain.

Korelasi di sini bekerja di atas tabel `alerts` yang sudah ada (tanpa
menduplikasi data), dikelompokkan per *entity* (default: agent_id), dalam sebuah
*jendela waktu*. Rule punya tahap (stages):
  • sequence  — tahap harus terjadi BERURUTAN (mis. brute-force → proses asing)
  • set       — tahap boleh urutan bebas (mis. port terekspos + brute-force)

Hasil disimpan di tabel `xdr_incidents` (di DB manager), de-dup per (rule, entity).
"""
import json
import sqlite3
import uuid

from nexus_common import protocol as fc
from nexus_common import schema


# --------------------------------------------------------------------------- DB
def _conn():
    return fc.connect()


def ensure_tables(c):
    """Buat tabel XDR pada koneksi `c` (tanpa commit)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS xdr_incidents (
            id TEXT PRIMARY KEY, rule_id TEXT, name TEXT, entity TEXT,
            entity_type TEXT, level INTEGER, severity TEXT,
            status TEXT DEFAULT 'open', first_ts INTEGER, last_ts INTEGER,
            count INTEGER, mitre TEXT, alert_ids TEXT, timeline TEXT,
            recommendation TEXT, tenant_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_status ON xdr_incidents(status);
        CREATE INDEX IF NOT EXISTS idx_xdr_last ON xdr_incidents(last_ts DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_xdr_key
            ON xdr_incidents(rule_id, entity, tenant_id);
        """
    )


def init_db():
    c = _conn()
    ensure_tables(c)
    c.commit(); c.close()


# --------------------------------------------------------------------------- stage matcher
def _as_list(v):
    return v if isinstance(v, list) else [v]


def _stage_match(alert, cond):
    """Apakah sebuah alert memenuhi satu tahap korelasi?"""
    for key, want in (cond or {}).items():
        if key in ("rule_id", "rule_id_in"):
            if str(alert.get("rule_id", "")) not in [str(x) for x in _as_list(want)]:
                return False
        elif key in ("category", "event_type", "severity", "agent_id", "status"):
            if str(alert.get(key, "")).lower() not in [str(x).lower() for x in _as_list(want)]:
                return False
        elif key == "level_gte":
            if int(alert.get("level", 0)) < int(want):
                return False
        elif key == "severity_gte":
            if schema.severity_to_level(alert.get("severity")) < schema.severity_to_level(want):
                return False
        elif key == "mitre":
            mitre = alert.get("mitre") or []
            if not any(m in mitre for m in _as_list(want)):
                return False
        elif key == "title_contains":
            if str(want).lower() not in str(alert.get("title", "")).lower():
                return False
        else:
            return False                    # kunci tahap tak dikenal → tak cocok (fail-safe)
    return True


def _entity_of(alert, group_by):
    if group_by == "agent_id":
        return alert.get("agent_id", "") or "unknown"
    # entity berbasis IP: cari di target/evidence (src_ip/ip)
    for src in (alert.get("target") or {}, alert.get("evidence") or {}):
        for k in ("src_ip", "ip", "source_ip", "remote_ip"):
            if isinstance(src, dict) and src.get(k):
                return str(src[k])
    return alert.get("agent_id", "") or "unknown"


# --------------------------------------------------------------------------- evaluation
def _evaluate_group(alerts_sorted, rule):
    """Cari rangkaian alert (terurut ts naik) yang memenuhi semua tahap rule dalam
    jendela waktu. Mengembalikan daftar alert kontributor (atau None bila tak cocok)."""
    stages = rule["stages"]
    window = int(rule.get("window", 1800))
    ordered = rule.get("mode", "sequence") == "sequence"
    n = len(alerts_sorted)
    # geser jendela [i..j] dengan ts[j]-ts[i] <= window.
    j = 0
    for i in range(n):
        if j < i:
            j = i
        while j < n and alerts_sorted[j]["ts"] - alerts_sorted[i]["ts"] <= window:
            j += 1
        win = alerts_sorted[i:j]            # alert dalam jendela mulai di i
        hit = _cover(win, stages, ordered)
        if hit:
            return hit
    return None


def _cover(win, stages, ordered):
    """Apakah jendela `win` menutupi semua tahap? Kembalikan alert kontributor."""
    if ordered:
        stage = 0
        chosen = []
        for al in win:                      # win sudah terurut ts naik
            if stage < len(stages) and _stage_match(al, stages[stage]):
                chosen.append(dict(al, _stage=stage))
                stage += 1
        return chosen if stage == len(stages) else None
    # set: setiap tahap butuh >=1 alert (urutan bebas)
    chosen = []
    for idx, st in enumerate(stages):
        match = next((al for al in win if _stage_match(al, st)), None)
        if not match:
            return None
        chosen.append(dict(match, _stage=idx))
    return chosen


# --------------------------------------------------------------------------- incident build/store
def _build_incident(rule, entity, entity_type, contributors, tenant):
    levels = [int(a.get("level", 0)) for a in contributors]
    level = max(int(rule.get("level", 0)), max(levels) if levels else 0)
    level = max(0, min(15, level))
    mitre = sorted({m for a in contributors for m in (a.get("mitre") or [])}
                   | set(rule.get("mitre", [])))
    timeline = [{
        "stage": a.get("_stage", 0), "ts": a["ts"], "ts_iso": fc.iso(a["ts"]),
        "alert_id": a.get("id", ""), "rule_id": a.get("rule_id", ""),
        "severity": a.get("severity", ""), "title": a.get("title", ""),
    } for a in sorted(contributors, key=lambda x: x["ts"])]
    ts_all = [a["ts"] for a in contributors]
    return {
        "id": "inc_" + uuid.uuid4().hex[:12],
        "rule_id": rule["id"], "name": rule["name"],
        "entity": entity, "entity_type": entity_type,
        "level": level, "severity": schema.level_to_severity(level),
        "status": "open", "first_ts": min(ts_all), "last_ts": max(ts_all),
        "count": len(contributors), "mitre": mitre,
        "alert_ids": [a.get("id", "") for a in contributors],
        "timeline": timeline,
        "recommendation": rule.get("recommendation", ""),
        "tenant_id": tenant,
    }


def _upsert(inc):
    """Sisipkan insiden baru atau perbarui yang ada (de-dup per rule+entity+tenant).
    Mempertahankan status & id lama agar acknowledgement analis tak hilang."""
    c = _conn()
    row = c.execute(
        "SELECT id, status, first_ts FROM xdr_incidents "
        "WHERE rule_id=? AND entity=? AND tenant_id=?",
        (inc["rule_id"], inc["entity"], inc["tenant_id"])).fetchone()
    created = row is None
    if row:
        inc["id"] = row["id"]
        inc["first_ts"] = min(inc["first_ts"], row["first_ts"] or inc["first_ts"])
        # insiden yang sudah resolved & muncul sinyal baru → buka kembali (reopen).
        inc["status"] = "open" if row["status"] == "resolved" else row["status"]
    c.execute(
        "INSERT INTO xdr_incidents(id,rule_id,name,entity,entity_type,level,severity,"
        "status,first_ts,last_ts,count,mitre,alert_ids,timeline,recommendation,tenant_id) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(rule_id,entity,tenant_id) DO UPDATE SET "
        "level=excluded.level, severity=excluded.severity, last_ts=excluded.last_ts, "
        "first_ts=excluded.first_ts, count=excluded.count, mitre=excluded.mitre, "
        "alert_ids=excluded.alert_ids, timeline=excluded.timeline, "
        "name=excluded.name, status=excluded.status",
        (inc["id"], inc["rule_id"], inc["name"], inc["entity"], inc["entity_type"],
         inc["level"], inc["severity"], inc["status"], inc["first_ts"], inc["last_ts"],
         inc["count"], json.dumps(inc["mitre"]), json.dumps(inc["alert_ids"]),
         json.dumps(inc["timeline"]), inc["recommendation"], inc["tenant_id"]))
    c.commit(); c.close()
    return created


def _fetch_alerts(lookback, tenant):
    c = _conn()
    rows = c.execute(
        "SELECT id, ts, agent_id, level, severity, title, category, event_type, "
        "rule_id, rule_name, mitre, target, evidence, status, tenant_id "
        "FROM alerts WHERE ts >= ? AND COALESCE(tenant_id,'default')=? ORDER BY ts ASC",
        (fc.now() - int(lookback), tenant)).fetchall()
    c.close()
    out = []
    for r in rows:
        d = dict(r)
        for col in ("mitre", "target", "evidence"):
            try:
                d[col] = json.loads(r[col]) if r[col] else ([] if col == "mitre" else {})
            except Exception:
                d[col] = [] if col == "mitre" else {}
        out.append(d)
    return out


# --------------------------------------------------------------------------- public API
def correlate(lookback=86400, rules=None, tenant="default"):
    """(Re)hitung insiden XDR dari alert `lookback` detik terakhir. Idempoten
    (de-dup per rule+entity), aman dipanggil tiap ingest maupun terjadwal."""
    init_db()
    rules = rules if rules is not None else DEFAULT_CORRELATIONS
    alerts = _fetch_alerts(lookback, tenant)
    created = updated = 0
    fired = []
    for rule in rules:
        group_by = rule.get("group_by", "agent_id")
        groups = {}
        for al in alerts:
            ent = _entity_of(al, group_by)
            groups.setdefault(ent, []).append(al)
        for ent, group in groups.items():
            group.sort(key=lambda x: x["ts"])
            contributors = _evaluate_group(group, rule)
            if not contributors:
                continue
            inc = _build_incident(rule, ent, group_by, contributors, tenant)
            was_new = _upsert(inc)
            created += 1 if was_new else 0
            updated += 0 if was_new else 1
            fired.append({"id": inc["id"], "rule_id": rule["id"], "name": rule["name"],
                          "entity": ent, "severity": inc["severity"], "level": inc["level"],
                          "new": was_new})
    return {"ok": True, "module": "nexus_secops", "created": created,
            "updated": updated, "fired": fired, "scanned_alerts": len(alerts)}


def list_incidents(status="", limit=200, tenant="default"):
    init_db()
    c = _conn()
    q = "SELECT * FROM xdr_incidents WHERE COALESCE(tenant_id,'default')=?"
    params = [tenant]
    if status:
        q += " AND status=?"; params.append(status)
    q += " ORDER BY level DESC, last_ts DESC LIMIT ?"
    params.append(int(limit))
    rows = c.execute(q, params).fetchall()
    c.close()
    incs = [{
        "id": r["id"], "rule_id": r["rule_id"], "name": r["name"], "entity": r["entity"],
        "entity_type": r["entity_type"], "level": r["level"], "severity": r["severity"],
        "status": r["status"], "first_ts": r["first_ts"], "last_ts": r["last_ts"],
        "first_iso": fc.iso(r["first_ts"]), "last_iso": fc.iso(r["last_ts"]),
        "count": r["count"], "mitre": _j(r["mitre"], []),
        "alert_ids": _j(r["alert_ids"], []),
    } for r in rows]
    return {"ok": True, "module": "nexus_secops", "incidents": incs, "total": len(incs)}


def get_incident(incident_id, tenant="default"):
    init_db()
    c = _conn()
    r = c.execute("SELECT * FROM xdr_incidents WHERE id=?", (incident_id,)).fetchone()
    c.close()
    if not r:
        return {"ok": False, "error": "insiden tak ditemukan"}
    return {"ok": True, "module": "nexus_secops", "incident": {
        "id": r["id"], "rule_id": r["rule_id"], "name": r["name"], "entity": r["entity"],
        "entity_type": r["entity_type"], "level": r["level"], "severity": r["severity"],
        "status": r["status"], "first_iso": fc.iso(r["first_ts"]),
        "last_iso": fc.iso(r["last_ts"]), "count": r["count"],
        "mitre": _j(r["mitre"], []), "alert_ids": _j(r["alert_ids"], []),
        "timeline": _j(r["timeline"], []), "recommendation": r["recommendation"],
    }}


def ack_incident(incident_id, status="ack"):
    init_db()
    if status not in ("open", "ack", "resolved"):
        return {"ok": False, "error": "status harus open|ack|resolved"}
    c = _conn()
    n = c.execute("UPDATE xdr_incidents SET status=? WHERE id=?",
                  (status, incident_id)).rowcount
    c.commit(); c.close()
    return {"ok": n > 0, "id": incident_id, "status": status}


def _j(s, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except Exception:
        return default if default is not None else {}


# --------------------------------------------------------------------------- default correlations
# Rangkaian serangan NYATA yang dibangun dari sinyal/rule yang SUDAH ada di Nexus
# (lihat nexus_manager/rules.py). Tiap tahap memetakan ke rule_id atau event_type
# yang benar-benar diproduksi mesin deteksi — jadi insiden ini akan muncul pada
# data sungguhan, bukan demo.
DEFAULT_CORRELATIONS = [
    {
        "id": "XDR-INTRUSION-001",
        "name": "Kemungkinan kompromi: brute-force diikuti eksekusi proses mencurigakan",
        "group_by": "agent_id", "mode": "sequence", "window": 1800, "level": 14,
        "mitre": ["T1110", "T1059"],
        "stages": [
            {"rule_id": ["NEXUS-AUTH-001", "NEXUS-AUTH-002", "NEXUS-LOG-005"]},
            {"rule_id": ["NEXUS-PROC-001"]},
        ],
        "recommendation": "Isolasi host, reset kredensial akun terdampak, audit "
                          "persistensi & jalur masuk (kill-chain pada timeline).",
    },
    {
        "id": "XDR-WEBCHAIN-001",
        "name": "Rantai serangan web: eksploitasi aplikasi → perubahan file sensitif",
        "group_by": "agent_id", "mode": "sequence", "window": 3600, "level": 14,
        "mitre": ["T1190", "T1505.003", "T1005"],
        "stages": [
            {"event_type": ["web_attack"]},
            {"category": ["file_integrity"]},
        ],
        "recommendation": "Periksa webshell/backdoor, rotasi secret di file yang "
                          "berubah, tambal kerentanan aplikasi, tinjau WAF.",
    },
    {
        "id": "XDR-RECON-EXPLOIT-001",
        "name": "Recon diikuti eksploitasi pada target yang sama",
        "group_by": "agent_id", "mode": "sequence", "window": 7200, "level": 12,
        "mitre": ["T1595", "T1190"],
        "stages": [
            {"event_type": ["scanner_detected"]},
            {"event_type": ["web_attack"]},
        ],
        "recommendation": "Blokir IP pemindai, perketat rate-limit, pastikan endpoint "
                          "sensitif tak terekspos, tinjau log akses penuh.",
    },
    {
        "id": "XDR-EXPOSED-ATTACK-001",
        "name": "Layanan terekspos sedang diserang (port berisiko + brute-force)",
        "group_by": "agent_id", "mode": "set", "window": 3600, "level": 13,
        "mitre": ["T1046", "T1110"],
        "stages": [
            {"rule_id": ["NEXUS-NET-001"]},
            {"rule_id": ["NEXUS-AUTH-001", "NEXUS-AUTH-002", "NEXUS-LOG-005"]},
        ],
        "recommendation": "Tutup/filter layanan terekspos (RDP/SMB/DB) ke VPN/allowlist, "
                          "aktifkan MFA & fail2ban pada layanan yang diserang.",
    },
    {
        "id": "XDR-NDR-001",
        "name": "C2 terkonfirmasi: ancaman jaringan + proses/IOC pada host sama",
        "group_by": "agent_id", "mode": "set", "window": 3600, "level": 14,
        "mitre": ["T1071", "T1571"],
        "stages": [
            {"rule_id": ["NEXUS-NDR-001"]},
            {"rule_id": ["NEXUS-PROC-001", "NEXUS-TI-001", "NEXUS-EDR-001"]},
        ],
        "recommendation": "Lalu lintas C2/beaconing BERSAMAAN dgn proses jahat di host — "
                          "kompromi aktif. Isolasi, blokir tujuan, IR penuh.",
    },
    {
        "id": "XDR-C2-001",
        "name": "Dugaan komunikasi C2: kontak IOC + proses mencurigakan",
        "group_by": "agent_id", "mode": "set", "window": 3600, "level": 14,
        "mitre": ["T1071", "T1059"],
        "stages": [
            {"rule_id": ["NEXUS-TI-001"]},
            {"rule_id": ["NEXUS-PROC-001"]},
        ],
        "recommendation": "Host kemungkinan terkompromi & berkomunikasi dgn infrastruktur "
                          "jahat. Isolasi, blokir IOC, lakukan IR & forensik memori.",
    },
    {
        "id": "XDR-UEBA-001",
        "name": "Entitas anomali + indikasi serangan (kemungkinan akun/host terkompromi)",
        "group_by": "agent_id", "mode": "set", "window": 7200, "level": 13,
        "mitre": ["T1078", "T1059"],
        "stages": [
            {"rule_id": ["NEXUS-UEBA-001"]},
            {"rule_id": ["NEXUS-PROC-001", "NEXUS-TI-001"]},
        ],
        "recommendation": "Perilaku menyimpang BERSAMAAN dgn proses jahat/kontak IOC — "
                          "prioritas tinggi. Isolasi, reset kredensial, lakukan IR.",
    },
    {
        "id": "XDR-VULN-EXPLOIT-001",
        "name": "Aset rentan menjadi target aktif (CVE berisiko + aktivitas serangan)",
        "group_by": "agent_id", "mode": "set", "window": 86400, "level": 14,
        "mitre": ["T1190", "T1203"],
        "stages": [
            {"rule_id": ["NEXUS-VULN-001"], "severity_gte": "high"},
            {"event_type": ["web_attack", "suspicious_process"]},
        ],
        "recommendation": "Prioritaskan patch CVE pada aset ini SEKARANG; bila sudah "
                          "dieksploitasi, lakukan IR penuh (isolasi, forensik, pemulihan).",
    },
]

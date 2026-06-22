# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/ueba.py
"""
UEBA — User & Entity Behavior Analytics untuk Nexus (gaya Securonix / Exabeam).

Membangun *baseline perilaku* tiap entitas (agent/host) dari riwayat event NYATA,
lalu memberi skor anomali pada jendela terbaru. Tidak ada data dikarang — semua
metrik dihitung dari tabel `events` manager.

Sinyal anomali yang dihitung (deterministik, dapat dijelaskan ke analis):
  • lonjakan volume      — aktivitas jauh di atas baseline harian entitas
  • aktivitas luar jam   — event di jam yang tak pernah aktif pada baseline
  • aktivitas tipe baru   — event_type yang belum pernah dilakukan entitas
  • eskalasi severity     — lonjakan event high/critical vs baseline
  • outlier peer-group    — entitas jauh menyimpang dari median rekan (MAD)

Anomali kuat (band 'high') di-emit sbg event `behavior_anomaly` (lewat manager)
→ rule NEXUS-UEBA-001 → alert → XDR/SOAR. Skor semua entitas disimpan utk
leaderboard risiko di dashboard.

Tabel: ueba_baselines (profil per entitas), ueba_scores (riwayat skor).
"""
import json
import math
import sqlite3
import time
import uuid

from nexus_common import protocol as fc
from nexus_common import schema

# Bobot kontribusi tiap sinyal ke skor risiko 0-100 (dijumlah lalu di-clamp).
W_VOLUME = 30
W_OFFHOURS = 20
W_NEWTYPE = 15           # per tipe baru, dibatasi
W_NEWTYPE_CAP = 30
W_SEVERITY = 25
W_PEER = 20

ACTIVE_HOUR_MIN = 0.5    # jam dianggap "aktif" bila >= 0.5 event/hari pada baseline


def _conn():
    return fc.connect()


def ensure_tables(c):
    """Buat tabel UEBA pada koneksi `c` (tanpa commit)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS ueba_baselines (
            entity TEXT, tenant_id TEXT DEFAULT 'default', hod_mean TEXT,
            known_types TEXT, active_hours TEXT, by_severity TEXT,
            total INTEGER, span_days REAL, trained_from INTEGER, trained_to INTEGER,
            updated_ts INTEGER, PRIMARY KEY(entity, tenant_id)
        );
        CREATE TABLE IF NOT EXISTS ueba_scores (
            id TEXT PRIMARY KEY, ts INTEGER, entity TEXT, tenant_id TEXT DEFAULT 'default',
            score INTEGER, band TEXT, reasons TEXT, window_from INTEGER, window_to INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_ueba_scores_ts ON ueba_scores(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_ueba_scores_entity ON ueba_scores(entity);
        """
    )


def init_db():
    c = _conn()
    ensure_tables(c)
    c.commit(); c.close()


def _hour_of_day(ts):
    return time.localtime(ts).tm_hour


def _fetch(since, until, tenant, conn=None):
    own = conn is None
    c = conn or _conn()
    rows = c.execute(
        "SELECT ts, agent_id, event_type, severity FROM events "
        "WHERE ts>=? AND ts<? AND COALESCE(tenant_id,'default')=? AND agent_id!=''",
        (int(since), int(until), tenant)).fetchall()
    if own:
        c.close()
    return rows


# --------------------------------------------------------------------------- training
def train(lookback=1209600, tenant="default", min_events=20):
    """Bangun baseline tiap entitas dari event `lookback` detik terakhir (default 14
    hari). Hanya entitas dengan >= min_events yang dibaseline (statistik bermakna)."""
    init_db()
    now = fc.now()
    since = now - int(lookback)
    rows = _fetch(since, now, tenant)
    per = {}
    for r in rows:
        e = r["agent_id"]
        d = per.setdefault(e, {"hod": [0] * 24, "types": {}, "sev": {}, "total": 0})
        d["hod"][_hour_of_day(r["ts"])] += 1
        d["types"][r["event_type"]] = d["types"].get(r["event_type"], 0) + 1
        d["sev"][r["severity"]] = d["sev"].get(r["severity"], 0) + 1
        d["total"] += 1
    span_days = max(1.0, (now - since) / 86400.0)
    c = _conn()
    trained = 0
    for e, d in per.items():
        if d["total"] < int(min_events):
            continue
        hod_mean = [round(x / span_days, 4) for x in d["hod"]]
        active_hours = [h for h in range(24) if hod_mean[h] >= ACTIVE_HOUR_MIN]
        c.execute(
            "INSERT INTO ueba_baselines(entity,tenant_id,hod_mean,known_types,active_hours,"
            "by_severity,total,span_days,trained_from,trained_to,updated_ts) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(entity,tenant_id) DO UPDATE SET hod_mean=excluded.hod_mean, "
            "known_types=excluded.known_types, active_hours=excluded.active_hours, "
            "by_severity=excluded.by_severity, total=excluded.total, "
            "span_days=excluded.span_days, trained_from=excluded.trained_from, "
            "trained_to=excluded.trained_to, updated_ts=excluded.updated_ts",
            (e, tenant, json.dumps(hod_mean), json.dumps(sorted(d["types"].keys())),
             json.dumps(active_hours), json.dumps(d["sev"]), d["total"], round(span_days, 2),
             since, now, now))
        trained += 1
    c.commit(); c.close()
    return {"ok": True, "module": "nexus_secops", "trained": trained,
            "entities_seen": len(per), "span_days": round(span_days, 1)}


def _get_baseline(c, entity, tenant):
    r = c.execute("SELECT * FROM ueba_baselines WHERE entity=? AND tenant_id=?",
                  (entity, tenant)).fetchone()
    if not r:
        return None
    return {"hod_mean": _j(r["hod_mean"], [0] * 24), "known_types": set(_j(r["known_types"], [])),
            "active_hours": set(_j(r["active_hours"], [])), "by_severity": _j(r["by_severity"], {}),
            "total": r["total"], "span_days": r["span_days"] or 1.0}


# --------------------------------------------------------------------------- scoring
def _score_one(entity, win_rows, base, peer):
    """Hitung skor anomali sebuah entitas (0-100) + alasan. win_rows = event jendela."""
    reasons = []
    score = 0
    total = len(win_rows)
    win_types = {}
    win_hc = 0
    offhour = 0
    for r in win_rows:
        et = r["event_type"]
        win_types[et] = win_types.get(et, 0) + 1
        if r["severity"] in ("high", "critical"):
            win_hc += 1
        if _hour_of_day(r["ts"]) not in base["active_hours"]:
            offhour += 1

    expected_day = sum(base["hod_mean"])             # ~event/hari baseline
    # 1) lonjakan volume
    if expected_day >= 1 and total > 3 * expected_day and total >= 10:
        reasons.append({"signal": "volume_spike", "weight": W_VOLUME,
                        "detail": f"{total} event vs baseline ~{round(expected_day)}/hari "
                                  f"({round(total / max(expected_day, 1), 1)}x)"})
        score += W_VOLUME

    # 2) aktivitas luar jam
    if offhour >= 5:
        reasons.append({"signal": "off_hours", "weight": W_OFFHOURS,
                        "detail": f"{offhour} event di jam yang tak pernah aktif pada baseline"})
        score += W_OFFHOURS

    # 3) tipe aktivitas baru
    new_types = [t for t in win_types if t not in base["known_types"]]
    if new_types:
        w = min(W_NEWTYPE * len(new_types), W_NEWTYPE_CAP)
        reasons.append({"signal": "new_activity", "weight": w,
                        "detail": "tipe aktivitas baru: " + ", ".join(sorted(new_types)[:5])})
        score += w

    # 4) eskalasi severity
    base_hc = sum(v for k, v in base["by_severity"].items() if k in ("high", "critical"))
    base_hc_day = base_hc / max(base["span_days"], 1.0)
    if win_hc >= 5 and (base_hc_day < 0.5 or win_hc > 3 * base_hc_day):
        reasons.append({"signal": "severity_escalation", "weight": W_SEVERITY,
                        "detail": f"{win_hc} event high/critical vs baseline "
                                  f"~{round(base_hc_day, 1)}/hari"})
        score += W_SEVERITY

    # 5) outlier peer-group (gagal login vs median rekan)
    if peer and entity in peer["outliers"]:
        reasons.append({"signal": "peer_outlier", "weight": W_PEER,
                        "detail": f"gagal-login jauh di atas median rekan "
                                  f"({peer['values'].get(entity, 0)} vs median {peer['median']})"})
        score += W_PEER

    score = max(0, min(100, score))
    band = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return score, band, reasons


def _peer_failed_logins(rows_by_entity):
    """Analisis peer-group: deteksi entitas yang gagal-login-nya outlier (median+MAD)."""
    vals = {}
    for e, rows in rows_by_entity.items():
        vals[e] = sum(1 for r in rows if r["event_type"] == "failed_login")
    nums = sorted(vals.values())
    if len(nums) < 3:
        return {"values": vals, "median": 0, "outliers": set()}
    med = _median(nums)
    mad = _median(sorted(abs(x - med) for x in nums)) or 1
    outliers = {e for e, v in vals.items() if v >= 5 and v > med + 3 * mad}
    return {"values": vals, "median": med, "mad": mad, "outliers": outliers}


def score(window=86400, tenant="default", record=True):
    """Skor anomali semua entitas berbaseline pada jendela terbaru. Mengembalikan
    daftar entitas + skor + alasan (deterministik, dari event NYATA)."""
    init_db()
    now = fc.now()
    since = now - int(window)
    rows = _fetch(since, now, tenant)
    by_entity = {}
    for r in rows:
        by_entity.setdefault(r["agent_id"], []).append(r)
    peer = _peer_failed_logins(by_entity)
    c = _conn()
    results = []
    for entity, win_rows in by_entity.items():
        base = _get_baseline(c, entity, tenant)
        if not base:
            continue                       # entitas tanpa baseline → butuh train dulu
        sc, band, reasons = _score_one(entity, win_rows, base, peer)
        if not reasons:
            continue                       # tak ada anomali → tak perlu dicatat
        rec = {"entity": entity, "score": sc, "band": band, "reasons": reasons,
               "window_events": len(win_rows)}
        results.append(rec)
        if record:
            c.execute(
                "INSERT INTO ueba_scores(id,ts,entity,tenant_id,score,band,reasons,"
                "window_from,window_to) VALUES(?,?,?,?,?,?,?,?,?)",
                ("ueba_" + uuid.uuid4().hex[:12], now, entity, tenant, sc, band,
                 json.dumps(reasons), since, now))
    c.commit(); c.close()
    results.sort(key=lambda x: x["score"], reverse=True)
    return {"ok": True, "module": "nexus_secops", "window": int(window),
            "scored": len(results), "entities": results}


# --------------------------------------------------------------------------- queries
def list_baselines(tenant="default"):
    init_db()
    c = _conn()
    rows = c.execute("SELECT * FROM ueba_baselines WHERE tenant_id=? ORDER BY total DESC",
                     (tenant,)).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "baselines": [{
        "entity": r["entity"], "total": r["total"], "span_days": r["span_days"],
        "known_types": _j(r["known_types"], []), "active_hours": _j(r["active_hours"], []),
        "trained_iso": fc.iso(r["updated_ts"]),
    } for r in rows]}


def list_scores(limit=200, band="", tenant="default"):
    init_db()
    c = _conn()
    q = "SELECT * FROM ueba_scores WHERE tenant_id=?"
    params = [tenant]
    if band:
        q += " AND band=?"; params.append(band)
    q += " ORDER BY ts DESC LIMIT ?"; params.append(int(limit))
    rows = c.execute(q, params).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "scores": [{
        "id": r["id"], "ts_iso": fc.iso(r["ts"]), "entity": r["entity"], "score": r["score"],
        "band": r["band"], "reasons": _j(r["reasons"], []),
    } for r in rows]}


def peer_analysis(window=86400, tenant="default"):
    """Analisis peer-group berdiri-sendiri (untuk dashboard)."""
    init_db()
    now = fc.now()
    rows = _fetch(now - int(window), now, tenant)
    by_entity = {}
    for r in rows:
        by_entity.setdefault(r["agent_id"], []).append(r)
    peer = _peer_failed_logins(by_entity)
    return {"ok": True, "module": "nexus_secops", "median": peer["median"],
            "outliers": sorted(peer["outliers"]),
            "values": dict(sorted(peer["values"].items(), key=lambda x: x[1], reverse=True))}


# --------------------------------------------------------------------------- util
def _median(nums):
    n = len(nums)
    if not n:
        return 0
    s = sorted(nums)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def band_to_severity(band):
    return {"high": "critical", "medium": "high", "low": "low"}.get(band, "low")


def _j(s, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except Exception:
        return default if default is not None else {}

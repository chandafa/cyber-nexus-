# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/ndr.py
"""
NDR — Network Detection & Response (gaya Security Onion/Zeek + IBM QRadar QFlow).

Menutup celah "analisis lalu-lintas jaringan": agent mengirim catatan KONEKSI
NYATA (dari `ss`/`netstat`), lalu engine ini mendeteksi ancaman berbasis jaringan
yang TAK terlihat dari satu koneksi saja:

  • Beaconing / C2  — koneksi berulang ke tujuan sama dengan interval teratur
                      (jitter rendah). Inilah cara malware "menelepon pulang".
                      (sama seperti RITA/Zeek: analisis periodisitas).
  • Port scan       — satu host menyentuh banyak port tujuan dalam jendela singkat.
  • Koneksi ke IOC  — tujuan cocok dengan database Threat Intel (C2 dikenal) →
                      memanfaatkan pilar threatintel (anti-redundan).
  • Eksfiltrasi      — volume keluar besar ke tujuan eksternal/jarang (bila byte ada).

NYATA, bukan demo: semua dihitung dari observasi koneksi sungguhan yang
terakumulasi dari waktu ke waktu. Temuan → event `network_threat` → rule
NEXUS-NDR-001 → alert → XDR/SOAR/AI.

Tabel: ndr_flows (observasi koneksi, retensi 24 jam).
"""
import json
import math
import re
import sqlite3
import uuid

from nexus_common import protocol as fc

# Ambang deteksi (deterministik, dapat dijelaskan).
BEACON_MIN = 4               # min observasi → cukup utk hitung periodisitas (≥3 delta)
BEACON_CV = 0.25             # koef. variasi delta < ini = teratur (beacon)
BEACON_MIN_INTERVAL = 5      # detik — beacon wajar 5 dtk .. 2 jam
BEACON_MAX_INTERVAL = 7200
SCAN_PORTS = 15              # port tujuan berbeda dari satu host dlm window → scan
EXFIL_BYTES = 50 * 1024 * 1024   # 50 MB keluar ke satu tujuan eksternal → eksfiltrasi
FLOW_RETENTION = 86400       # simpan observasi koneksi 24 jam

_PRIVATE = re.compile(r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|fe80:|fc|fd)")


def _conn():
    return fc.connect()


def ensure_tables(c):
    """Buat tabel NDR pada koneksi `c` (tanpa commit)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS ndr_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, tenant_id TEXT DEFAULT 'default',
            ts INTEGER, src TEXT, dst TEXT, dport INTEGER, proto TEXT, bytes INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_ndr_dst ON ndr_flows(agent_id, dst, dport, ts);
        CREATE INDEX IF NOT EXISTS idx_ndr_ts ON ndr_flows(ts);
        """
    )


def init_db():
    c = _conn()
    ensure_tables(c)
    c.commit(); c.close()


def _is_external(ip):
    return bool(ip) and not _PRIVATE.match(str(ip))


# --------------------------------------------------------------------------- ingest
def ingest_flows(agent_id, flows, tenant="default", conn=None):
    """Simpan observasi koneksi NYATA lalu jalankan deteksi atas riwayat terbaru.
    Pakai koneksi pemanggil bila diberikan (anti-lock saat ingest)."""
    own = conn is None
    c = conn or _conn()
    if own:
        ensure_tables(c)
    now = fc.now()
    rows = []
    for f in flows or []:
        dst = str(f.get("dst", "")).strip()
        if not dst:
            continue
        rows.append((agent_id, tenant, now, str(f.get("src", "")), dst,
                     _to_int(f.get("dport", 0)), str(f.get("proto", "tcp")),
                     _to_int(f.get("bytes", 0))))
    if rows:
        c.executemany("INSERT INTO ndr_flows(agent_id,tenant_id,ts,src,dst,dport,proto,bytes) "
                      "VALUES(?,?,?,?,?,?,?,?)", rows)
    c.execute("DELETE FROM ndr_flows WHERE ts < ?", (now - FLOW_RETENTION,))   # retensi
    findings = detect(agent_id, FLOW_RETENTION, tenant, conn=c)
    if own:
        c.commit(); c.close()
    return findings


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- detection
def detect(agent_id, window=86400, tenant="default", conn=None):
    """Deteksi ancaman jaringan atas observasi koneksi `window` detik terakhir."""
    own = conn is None
    c = conn or _conn()
    rows = c.execute("SELECT ts, src, dst, dport, proto, bytes FROM ndr_flows "
                     "WHERE agent_id=? AND tenant_id=? AND ts>=? ORDER BY ts ASC",
                     (agent_id, tenant, fc.now() - int(window))).fetchall()
    flows = [dict(r) for r in rows]
    findings = []
    findings += _beacons(flows)
    findings += _scans(flows)
    findings += _ioc_dst(flows, tenant, conn=c)   # pakai koneksi yg sama (anti-lock)
    findings += _exfil(flows)
    if own:
        c.close()                                  # tutup SETELAH _ioc_dst memakai c
    return findings


def _beacons(flows):
    """Deteksi beaconing: koneksi periodik (jitter rendah) ke tujuan eksternal sama."""
    groups = {}
    for f in flows:
        if _is_external(f["dst"]):
            groups.setdefault((f["dst"], f["dport"]), []).append(f["ts"])
    out = []
    for (dst, dport), ts_list in groups.items():
        ts_sorted = sorted(set(ts_list))
        if len(ts_sorted) < BEACON_MIN:
            continue
        deltas = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
        deltas = [d for d in deltas if d > 0]
        if len(deltas) < 3:
            continue
        mean = sum(deltas) / len(deltas)
        if not (BEACON_MIN_INTERVAL <= mean <= BEACON_MAX_INTERVAL):
            continue
        var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        cv = math.sqrt(var) / mean if mean else 1
        if cv <= BEACON_CV:
            out.append({"kind": "beaconing", "severity": "high", "dst": dst, "dport": dport,
                        "mitre": ["T1071", "T1571"],
                        "detail": f"Beaconing ke {dst}:{dport} tiap ~{round(mean)}s "
                                  f"({len(ts_sorted)}x, jitter {round(cv*100)}%)",
                        "evidence": {"interval_s": round(mean), "count": len(ts_sorted),
                                     "jitter": round(cv, 3), "dst": dst, "dport": dport}})
    return out


def _scans(flows):
    """Deteksi port scan: satu agent menyentuh banyak port tujuan berbeda."""
    by_dst = {}
    for f in flows:
        by_dst.setdefault(f["dst"], set()).add(f["dport"])
    out = []
    for dst, ports in by_dst.items():
        if len(ports) >= SCAN_PORTS:
            out.append({"kind": "port_scan", "severity": "medium", "dst": dst, "dport": 0,
                        "mitre": ["T1046"],
                        "detail": f"Port scan ke {dst}: {len(ports)} port berbeda",
                        "evidence": {"dst": dst, "distinct_ports": len(ports)}})
    return out


def _ioc_dst(flows, tenant, conn=None):
    """Cocokkan tujuan koneksi dgn Threat Intel (C2 dikenal) — memanfaatkan pilar TI.
    `conn` diteruskan ke ti.match_value agar TAK membuka koneksi kedua saat ingest."""
    try:
        from nexus_secops import threatintel as ti
    except Exception:
        return []
    out, seen = [], set()
    for f in flows:
        dst = f["dst"]
        if dst in seen or not _is_external(dst):
            continue
        seen.add(dst)
        hit = ti.match_value(dst, tenant, conn=conn)
        if hit:
            out.append({"kind": "c2_known", "severity": "critical", "dst": dst,
                        "dport": f["dport"], "mitre": ["T1071"],
                        "detail": f"Koneksi ke IOC dikenal {dst} ({hit['threat']})",
                        "evidence": {"dst": dst, "threat": hit["threat"],
                                     "ioc_source": hit["source"]}})
    return out


def _exfil(flows):
    """Deteksi eksfiltrasi: volume keluar besar ke satu tujuan eksternal (bila byte ada)."""
    by_dst = {}
    for f in flows:
        if _is_external(f["dst"]) and f.get("bytes"):
            by_dst[f["dst"]] = by_dst.get(f["dst"], 0) + f["bytes"]
    out = []
    for dst, total in by_dst.items():
        if total >= EXFIL_BYTES:
            out.append({"kind": "exfiltration", "severity": "high", "dst": dst, "dport": 0,
                        "mitre": ["T1041"],
                        "detail": f"Volume keluar besar ke {dst}: {round(total/1048576)} MB",
                        "evidence": {"dst": dst, "bytes": total}})
    return out


# --------------------------------------------------------------------------- queries
def list_flows(agent_id="", limit=500, tenant="default"):
    init_db()
    c = _conn()
    q = "SELECT * FROM ndr_flows WHERE tenant_id=?"
    params = [tenant]
    if agent_id:
        q += " AND agent_id=?"; params.append(agent_id)
    q += " ORDER BY ts DESC LIMIT ?"; params.append(int(limit))
    rows = c.execute(q, params).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "flows": [{
        "ts_iso": fc.iso(r["ts"]), "agent_id": r["agent_id"], "src": r["src"],
        "dst": r["dst"], "dport": r["dport"], "proto": r["proto"], "bytes": r["bytes"],
    } for r in rows]}


def top_talkers(window=86400, tenant="default", limit=15):
    """Tujuan eksternal teramai (gaya QFlow) — untuk dashboard."""
    init_db()
    c = _conn()
    rows = c.execute("SELECT dst, COUNT(*) n, SUM(bytes) b FROM ndr_flows WHERE tenant_id=? "
                     "AND ts>=? GROUP BY dst ORDER BY n DESC LIMIT ?",
                     (tenant, fc.now() - int(window), int(limit) * 3)).fetchall()
    c.close()
    talkers = [{"dst": r["dst"], "connections": r["n"], "bytes": r["b"] or 0,
                "external": _is_external(r["dst"])} for r in rows]
    talkers = [t for t in talkers if t["external"]][:int(limit)]
    return {"ok": True, "module": "nexus_secops", "talkers": talkers}


def stats(tenant="default"):
    init_db()
    c = _conn()
    total = c.execute("SELECT COUNT(*) n FROM ndr_flows WHERE tenant_id=?", (tenant,)).fetchone()["n"]
    ext = c.execute("SELECT COUNT(DISTINCT dst) n FROM ndr_flows WHERE tenant_id=?", (tenant,)).fetchone()["n"]
    c.close()
    return {"ok": True, "module": "nexus_secops", "observations": total, "distinct_dst": ext}

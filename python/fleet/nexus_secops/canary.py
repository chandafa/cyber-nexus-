# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/canary.py
"""
Nexus Canary — honeytokens / deception (fidelitas tinggi).

Sebar "umpan" yang tak punya alasan sah untuk disentuh: kredensial palsu, AWS key
palsu, file ber-marker, URL/DNS canary, .env palsu. Begitu salah satu DISENTUH —
muncul di log/telemetri, atau URL canary diakses — itu sinyal breach hampir tanpa
false-positive (siapa pun yang menyentuhnya sudah berada di tempat yang salah).

Deteksi (deterministik, tanpa AI — 100% fidelitas):
  • match_event(): pindai event NYATA yang masuk; bila marker canary muncul → picu.
  • trigger_marker(): dipanggil saat endpoint HTTP canary /c/<marker> diakses.

Setiap trigger → alert level tinggi (NEXUS-CANARY-001) yang mengalir ke pipeline
yang sudah ada (alert → XDR → SOAR → hub notifikasi).

Tabel: canary_tokens (token + artefak deploy + hitungan trigger).
Catatan kunci (footgun berulang): fungsi yang MENULIS saat ingest manager WAJIB
memakai koneksi pemanggil (conn=) agar tak deadlock terhadap transaksi ingest.
"""
import json
import secrets
import sqlite3

TYPES = ("credential", "aws_key", "url", "dns", "file", "env")


def ensure_tables(c):
    c.executescript("""
        CREATE TABLE IF NOT EXISTS canary_tokens (
            id TEXT PRIMARY KEY, type TEXT, label TEXT, marker TEXT,
            artifact TEXT, tenant_id TEXT, created INTEGER,
            triggered INTEGER DEFAULT 0, last_triggered INTEGER,
            last_source TEXT, enabled INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_canary_marker ON canary_tokens(marker);
    """)


def _now():
    import time
    return int(time.time())


def _marker() -> str:
    # marker unik & mudah dicari di log; awalan agar tak bentrok teks normal.
    return "nxc_" + secrets.token_hex(10)


def _b32(n):
    import base64
    return base64.b32encode(secrets.token_bytes(n)).decode().rstrip("=")


def _build_artifact(typ, marker, label, base_url):
    """Bangun artefak yang bisa di-deploy. Marker selalu tertanam agar terdeteksi
    saat dipakai/muncul di log; setiap token juga punya URL canary universal."""
    canary_url = f"{base_url.rstrip('/')}/c/{marker}" if base_url else f"/c/{marker}"
    if typ == "aws_key":
        # access key id memuat marker (huruf besar) → terdeteksi di CloudTrail/log.
        akid = "AKIA" + marker.replace("nxc_", "").upper()[:16].ljust(16, "X")
        return {"access_key_id": akid, "secret_access_key": _b32(30),
                "note": "Kredensial AWS UMPAN — jangan pernah dipakai sah.",
                "canary_url": canary_url, "detect_on": akid}
    if typ == "credential":
        user = f"svc_backup_{marker[4:12]}"
        return {"username": user, "password": _b32(12),
                "note": "Kredensial UMPAN. Login dgn user ini = breach.",
                "canary_url": canary_url, "detect_on": user}
    if typ == "dns":
        host = f"{marker.replace('_','-')}.canary.nexus.local"
        return {"hostname": host, "note": "DNS canary — query ke host ini = breach.",
                "canary_url": canary_url, "detect_on": host}
    if typ == "env":
        body = (f"# .env (UMPAN)\nAPP_KEY=base64:{_b32(24)}\n"
                f"DB_PASSWORD={_b32(12)}\nNEXUS_CANARY={marker}\n")
        return {"filename": ".env", "content": body,
                "note": "File .env UMPAN — letakkan di lokasi sensitif.",
                "canary_url": canary_url, "detect_on": marker}
    if typ == "file":
        return {"filename": f"{label or 'rahasia'}-{marker[4:10]}.txt",
                "content": f"KONFIDENSIAL\nID dokumen: {marker}\nakses: {canary_url}\n",
                "note": "Dokumen UMPAN ber-marker. Letakkan di share/file sensitif.",
                "canary_url": canary_url, "detect_on": marker}
    # url / default
    return {"canary_url": canary_url,
            "note": "Tanam URL ini sbg link/web-bug; akses ke URL = breach.",
            "detect_on": marker}


def mint(typ="url", label="", tenant="default", base_url="", conn=None) -> dict:
    if typ not in TYPES:
        return {"ok": False, "error": f"tipe canary tak dikenal: {typ}"}
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    marker = _marker()
    artifact = _build_artifact(typ, marker, label, base_url)
    tid = "cnr_" + secrets.token_hex(6)
    c.execute("INSERT INTO canary_tokens(id,type,label,marker,artifact,tenant_id,created,"
              "triggered,enabled) VALUES(?,?,?,?,?,?,?,0,1)",
              (tid, typ, label or typ, marker, json.dumps(artifact), tenant, _now()))
    if own:
        c.commit(); c.close()
    return {"ok": True, "id": tid, "type": typ, "label": label or typ,
            "marker": marker, "artifact": artifact}


def list_tokens(tenant="default", conn=None) -> dict:
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    rows = c.execute("SELECT id,type,label,marker,artifact,created,triggered,last_triggered,"
                     "last_source,enabled FROM canary_tokens WHERE tenant_id=? "
                     "ORDER BY created DESC", (tenant,)).fetchall()
    if own:
        c.close()
    return {"ok": True, "tokens": [{
        "id": r["id"], "type": r["type"], "label": r["label"], "marker": r["marker"],
        "created": r["created"], "triggered": r["triggered"],
        "last_triggered": r["last_triggered"], "last_source": r["last_source"],
        "enabled": bool(r["enabled"]),
        "canary_url": (json.loads(r["artifact"]) or {}).get("canary_url"),
    } for r in rows]}


def delete_token(tid, conn=None) -> dict:
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    cur = c.execute("DELETE FROM canary_tokens WHERE id=?", (tid,))
    if own:
        c.commit(); c.close()
    return {"ok": cur.rowcount > 0, "deleted": cur.rowcount}


def stats(tenant="default", conn=None) -> dict:
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    row = c.execute("SELECT COUNT(*) n, COALESCE(SUM(triggered),0) t, "
                    "SUM(CASE WHEN triggered>0 THEN 1 ELSE 0 END) tripped "
                    "FROM canary_tokens WHERE tenant_id=?", (tenant,)).fetchone()
    if own:
        c.close()
    return {"ok": True, "tokens": row["n"], "total_triggers": row["t"],
            "tripped_tokens": row["tripped"] or 0}


def _record_trigger(c, marker, source):
    """Tandai token terpicu (atomik). Mengembalikan baris token atau None."""
    row = c.execute("SELECT id,type,label,marker,tenant_id,enabled FROM canary_tokens "
                    "WHERE marker=?", (marker,)).fetchone()
    if not row or not row["enabled"]:
        return None
    c.execute("UPDATE canary_tokens SET triggered=triggered+1, last_triggered=?, "
              "last_source=? WHERE marker=?", (_now(), (source or "")[:200], marker))
    return row


def trigger_marker(marker, source="", conn=None):
    """Picu by marker persis (dipakai endpoint HTTP /c/<marker>). Mengembalikan
    info hit (utk dibungkus jadi alert oleh manager) atau None."""
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    row = _record_trigger(c, marker, source)
    if own:
        c.commit(); c.close()
    if not row:
        return None
    return {"marker": marker, "token_id": row["id"], "type": row["type"],
            "label": row["label"], "tenant": row["tenant_id"], "source": source}


def match_event(src_ev, tenant="default", conn=None) -> list:
    """Pindai SATU event NYATA: bila marker canary aktif muncul di teksnya → picu.
    Mengembalikan daftar hit BARU (untuk dijadikan alert oleh manager)."""
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    rows = c.execute("SELECT marker, artifact FROM canary_tokens "
                     "WHERE tenant_id=? AND enabled=1", (tenant,)).fetchall()
    if not rows:
        if own:
            c.close()
        return []
    text = json.dumps(src_ev, ensure_ascii=False, default=str)
    hits = []
    for r in rows:
        detect_on = (json.loads(r["artifact"]) or {}).get("detect_on") or r["marker"]
        # cocokkan marker ATAU nilai detect_on (mis. access_key/username/host umpan)
        if r["marker"] in text or (detect_on and detect_on in text):
            row = _record_trigger(c, r["marker"], f"event:{src_ev.get('event_id','')}")
            if row:
                hits.append({"marker": r["marker"], "token_id": row["id"],
                             "type": row["type"], "label": row["label"],
                             "tenant": tenant, "source": f"event:{src_ev.get('event_id','')}"})
    if own:
        c.commit(); c.close()
    return hits


def alert_from_hit(hit) -> dict:
    """Bentuk dict alert standar (sebelum id/ts/agent diisi manager)."""
    return {
        "level": 14, "severity": "critical", "category": "deception",
        "event_type": "canary_triggered",
        "title": f"Canary terpicu: {hit['label']} ({hit['type']})",
        "description": (f"Token canary '{hit['label']}' tipe {hit['type']} disentuh — "
                        f"indikasi breach fidelitas tinggi. Sumber: {hit.get('source','')}."),
        "rule": {"id": "NEXUS-CANARY-001", "name": "Canary token triggered",
                 "mitre": ["T1078", "T1530"],
                 "recommendation": "Isolasi sumber, rotasi kredensial nyata terkait, "
                                   "investigasi jalur akses.",
                 "response": ["notify"]},
        "target": {"marker": hit["marker"], "canary_type": hit["type"]},
        "evidence": {"marker": hit["marker"], "token_id": hit["token_id"],
                     "canary_type": hit["type"], "label": hit["label"],
                     "source": hit.get("source", "")},
    }


def _sa_conn():
    """Koneksi mandiri (di luar ingest). Memakai path DB manager yg sama."""
    from nexus_common import protocol as fc
    c = sqlite3.connect(fc.manager_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    return c

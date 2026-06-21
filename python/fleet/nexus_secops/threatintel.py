# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/threatintel.py
"""
Threat Intelligence untuk Nexus — database IOC + pencocokan ke telemetri NYATA.

Mengikuti praktik MISP / AlienVault OTX / abuse.ch: simpan *indicator of
compromise* (IP, domain, URL, hash) lalu cocokkan terhadap event/alert sungguhan
yang masuk. Saat cocok → buat alert `ioc_match` yang mengalir ke pipeline yang
sudah ada (rules → XDR correlate → SOAR). Jadi TI bukan pajangan; ia memperkaya
deteksi secara real-time + retro-hunt.

NYATA, bukan demo:
  • IOC store kosong secara default — operator mengisinya dari feed sungguhan.
  • import_feed() benar-benar mengunduh feed via HTTP (mis. abuse.ch Feodo/URLhaus,
    ekspor MISP/OTX) dan mem-parse-nya — stdlib `urllib`, tanpa dependensi.
  • match dilakukan atas observable yang DIEKSTRAK dari event asli (bukan dikarang).

Tabel: ti_iocs (indikator), ti_matches (audit kecocokan).
"""
import json
import re
import sqlite3
import urllib.request
import uuid

from nexus_common import protocol as fc

# --------------------------------------------------------------------------- pola observable
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>\\)]+", re.I)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")

IOC_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256")
SEVERITIES = ("info", "low", "medium", "high", "critical")
# IP privat/non-routable & host lokal — jangan pernah jadi IOC (anti false-positive).
_PRIVATE = re.compile(r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")


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
    """Buat tabel TI pada koneksi `c` (tanpa commit) — dipanggil manager init_db
    agar skema disiapkan dalam SATU koneksi (hindari lock antar-koneksi)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS ti_iocs (
            id TEXT PRIMARY KEY, type TEXT, value TEXT, threat TEXT,
            severity TEXT DEFAULT 'high', confidence INTEGER DEFAULT 75,
            source TEXT, tags TEXT, refs TEXT, enabled INTEGER DEFAULT 1,
            first_seen INTEGER, last_seen INTEGER, tenant_id TEXT DEFAULT 'default'
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_key ON ti_iocs(type, value, tenant_id);
        CREATE INDEX IF NOT EXISTS idx_ioc_value ON ti_iocs(value);
        CREATE TABLE IF NOT EXISTS ti_matches (
            id TEXT PRIMARY KEY, ts INTEGER, ioc_id TEXT, ioc_type TEXT, ioc_value TEXT,
            event_id TEXT, agent_id TEXT, threat TEXT, severity TEXT, source TEXT,
            observable TEXT, tenant_id TEXT DEFAULT 'default'
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_timatch_key ON ti_matches(ioc_id, event_id);
        CREATE INDEX IF NOT EXISTS idx_timatch_ts ON ti_matches(ts DESC);
        """
    )


def init_db():
    c = _conn()
    ensure_tables(c)
    c.commit(); c.close()


# --------------------------------------------------------------------------- type detection
def detect_type(value):
    v = (value or "").strip()
    if not v:
        return None
    if _URL.match(v):
        return "url"
    if re.fullmatch(_IPV4, v):
        return "ip"
    if re.fullmatch(_SHA256, v):
        return "sha256"
    if re.fullmatch(_SHA1, v):
        return "sha1"
    if re.fullmatch(_MD5, v):
        return "md5"
    if re.fullmatch(_DOMAIN, v):
        return "domain"
    return None


def _norm(value, typ):
    v = (value or "").strip().lower()
    if typ == "domain":
        v = v.rstrip(".")
    return v


# --------------------------------------------------------------------------- IOC CRUD
def add_iocs(iocs, source="manual", tenant="default"):
    """Tambah/perbarui daftar IOC. Tiap item: str (auto-deteksi) atau dict
    {value, type?, threat?, severity?, confidence?, tags?, refs?}. Mengembalikan
    jumlah ditambah/diperbarui/dilewati (tipe tak dikenal / IP privat)."""
    init_db()
    if isinstance(iocs, (str, dict)):
        iocs = [iocs]
    added = updated = skipped = 0
    c = _conn()
    now = fc.now()
    for item in iocs or []:
        d = {"value": item} if isinstance(item, str) else dict(item or {})
        raw = str(d.get("value", "")).strip()
        typ = (d.get("type") or detect_type(raw) or "").lower()
        if typ not in IOC_TYPES:
            skipped += 1
            continue
        val = _norm(raw, typ)
        if typ == "ip" and _PRIVATE.match(val):    # jangan jadikan IP lokal/privat IOC
            skipped += 1
            continue
        sev = (d.get("severity") or "high").lower()
        sev = sev if sev in SEVERITIES else "high"
        exists = c.execute("SELECT id FROM ti_iocs WHERE type=? AND value=? AND tenant_id=?",
                           (typ, val, tenant)).fetchone()
        if exists:
            c.execute("UPDATE ti_iocs SET last_seen=?, threat=COALESCE(NULLIF(?,''),threat), "
                      "severity=?, source=COALESCE(NULLIF(?,''),source), enabled=1 WHERE id=?",
                      (now, d.get("threat", ""), sev, d.get("source") or source, exists["id"]))
            updated += 1
        else:
            c.execute("INSERT INTO ti_iocs(id,type,value,threat,severity,confidence,source,"
                      "tags,refs,enabled,first_seen,last_seen,tenant_id) "
                      "VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?)",
                      ("ioc_" + uuid.uuid4().hex[:12], typ, val, d.get("threat", "unknown"),
                       sev, int(d.get("confidence", 75)), d.get("source") or source,
                       json.dumps(d.get("tags", [])), json.dumps(d.get("refs", [])),
                       now, now, tenant))
            added += 1
    c.commit(); c.close()
    return {"ok": True, "module": "nexus_secops", "added": added, "updated": updated,
            "skipped": skipped, "source": source}


def import_feed(url, fmt="text", source=None, threat="feed", severity="high",
                col=0, tenant="default", timeout=15):
    """Unduh feed IOC NYATA via HTTP & impor. fmt:
       text — satu indikator per baris (token ke-`col`, '#' = komentar; format
              abuse.ch/Feodo/URLhaus/spamhaus DROP).
       json — array string atau array objek {value,type,...} (ekspor MISP/OTX)."""
    init_db()
    source = source or url
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Nexus-TI/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 (URL operator-supplied)
            raw = resp.read().decode("utf-8", "replace")
    except Exception as e:
        return {"ok": False, "error": f"gagal unduh feed: {e}", "url": url}
    iocs = []
    if fmt == "json":
        try:
            data = json.loads(raw)
        except Exception as e:
            return {"ok": False, "error": f"feed JSON tak valid: {e}"}
        for it in (data if isinstance(data, list) else data.get("iocs", [])):
            if isinstance(it, str):
                iocs.append({"value": it, "threat": threat, "severity": severity})
            elif isinstance(it, dict):
                it.setdefault("threat", threat); it.setdefault("severity", severity)
                iocs.append(it)
    else:
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            parts = re.split(r"[,\t ]+", line)
            if col < len(parts):
                iocs.append({"value": parts[col], "threat": threat, "severity": severity})
    res = add_iocs(iocs, source=source, tenant=tenant)
    res["fetched"] = len(iocs)
    res["url"] = url
    return res


def list_iocs(type="", q="", limit=500, tenant="default"):
    init_db()
    c = _conn()
    sql = "SELECT * FROM ti_iocs WHERE COALESCE(tenant_id,'default')=?"
    params = [tenant]
    if type:
        sql += " AND type=?"; params.append(type)
    if q:
        sql += " AND (value LIKE ? OR threat LIKE ?)"; params += [f"%{q.lower()}%", f"%{q.lower()}%"]
    sql += " ORDER BY last_seen DESC LIMIT ?"; params.append(int(limit))
    rows = c.execute(sql, params).fetchall()
    c.close()
    iocs = [{"id": r["id"], "type": r["type"], "value": r["value"], "threat": r["threat"],
             "severity": r["severity"], "confidence": r["confidence"], "source": r["source"],
             "tags": _j(r["tags"], []), "enabled": bool(r["enabled"]),
             "first_iso": fc.iso(r["first_seen"]), "last_iso": fc.iso(r["last_seen"])}
            for r in rows]
    return {"ok": True, "module": "nexus_secops", "iocs": iocs, "total": len(iocs)}


def delete_ioc(ioc_id):
    init_db()
    c = _conn()
    n = c.execute("DELETE FROM ti_iocs WHERE id=?", (ioc_id,)).rowcount
    c.commit(); c.close()
    return {"ok": n > 0, "removed": n}


def clear_iocs(tenant="default"):
    init_db()
    c = _conn()
    n = c.execute("DELETE FROM ti_iocs WHERE COALESCE(tenant_id,'default')=?", (tenant,)).rowcount
    c.commit(); c.close()
    return {"ok": True, "removed": n}


def stats(tenant="default"):
    init_db()
    c = _conn()
    by_type = {t: 0 for t in IOC_TYPES}
    for r in c.execute("SELECT type, COUNT(*) n FROM ti_iocs WHERE COALESCE(tenant_id,'default')=? "
                       "GROUP BY type", (tenant,)).fetchall():
        if r["type"] in by_type:
            by_type[r["type"]] = r["n"]
    total = c.execute("SELECT COUNT(*) n FROM ti_iocs WHERE COALESCE(tenant_id,'default')=?",
                      (tenant,)).fetchone()["n"]
    matches = c.execute("SELECT COUNT(*) n FROM ti_matches WHERE COALESCE(tenant_id,'default')=?",
                        (tenant,)).fetchone()["n"]
    c.close()
    return {"ok": True, "module": "nexus_secops", "total_iocs": total, "by_type": by_type,
            "total_matches": matches}


# --------------------------------------------------------------------------- observable extraction
def extract_observables(event):
    """Ekstrak observable (IP/domain/URL/hash) dari field event NYATA."""
    blob = " ".join([
        str(event.get("title", "")), str(event.get("detail", "")),
        json.dumps(event.get("target", {})), json.dumps(event.get("evidence", {})),
        json.dumps(event.get("data", {})), json.dumps(event.get("host", {})),
    ])
    found = {}
    for m in _URL.findall(blob):
        found.setdefault(_norm(m, "url"), "url")
    for m in _SHA256.findall(blob):
        found.setdefault(m.lower(), "sha256")
    for m in _SHA1.findall(blob):
        found.setdefault(m.lower(), "sha1")
    for m in _MD5.findall(blob):
        found.setdefault(m.lower(), "md5")
    for m in _IPV4.findall(blob):
        if not _PRIVATE.match(m):
            found.setdefault(m, "ip")
    for m in _DOMAIN.findall(blob):
        found.setdefault(_norm(m, "domain"), "domain")
    # observable: {value: type}; satu value bisa muncul sbg domain & lainnya — cukup.
    return found


# --------------------------------------------------------------------------- matching
def match_value(value, tenant="default", conn=None):
    """Cek satu observable terhadap IOC store. Mengembalikan IOC bila cocok.

    `conn`: bila pemanggil menyediakan koneksi (mis. NDR saat ingest), pakai
    KONEKSI ITU — JANGAN buka koneksi/transaksi kedua (mencegah `database is
    locked` saat dipanggil di tengah transaksi ingest)."""
    typ = detect_type(value)
    if not typ:
        return None
    own = conn is None
    if own:
        init_db()
        c = _conn()
    else:
        c = conn
    r = c.execute("SELECT * FROM ti_iocs WHERE value=? AND enabled=1 AND "
                  "COALESCE(tenant_id,'default')=? LIMIT 1", (_norm(value, typ), tenant)).fetchone()
    if own:
        c.close()
    return dict(r) if r else None


def match_event(event, tenant="default", record=True, conn=None):
    """Cocokkan observable sebuah event terhadap IOC store. Mengembalikan daftar
    kecocokan (IOC + observable). Mencatat ke ti_matches (de-dup per ioc+event).

    `conn`: bila pemanggil menyediakan koneksi (mis. saat ingest), pakai KONEKSI
    ITU agar pencatatan ti_matches berada di transaksi yang sama — mencegah lock
    antar-koneksi (yang dulu membuat audit kecocokan diam-diam hilang)."""
    obs = extract_observables(event)
    if not obs:
        return []
    values = list(obs.keys())
    own = conn is None
    if own:
        init_db()
        c = _conn()
    else:
        c = conn
    ph = ",".join("?" * len(values))
    rows = c.execute(f"SELECT * FROM ti_iocs WHERE enabled=1 AND COALESCE(tenant_id,'default')=? "
                     f"AND value IN ({ph})", [tenant] + values).fetchall()
    hits = []
    for r in rows:
        hit = {"ioc_id": r["id"], "type": r["type"], "value": r["value"],
               "threat": r["threat"], "severity": r["severity"], "source": r["source"],
               "confidence": r["confidence"], "observable": r["value"], "new": True}
        hits.append(hit)
        if record:
            try:
                cur = c.execute(
                    "INSERT OR IGNORE INTO ti_matches(id,ts,ioc_id,ioc_type,ioc_value,"
                    "event_id,agent_id,threat,severity,source,observable,tenant_id) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    ("tim_" + uuid.uuid4().hex[:12], fc.now(), r["id"], r["type"],
                     r["value"], event.get("event_id", ""), event.get("agent_id", ""),
                     r["threat"], r["severity"], r["source"], r["value"], tenant))
                hit["new"] = cur.rowcount == 1     # False = kecocokan ini sudah pernah dicatat
            except sqlite3.Error:
                pass
    if own:
        c.commit(); c.close()
    return hits


def list_matches(limit=200, tenant="default"):
    init_db()
    c = _conn()
    rows = c.execute("SELECT * FROM ti_matches WHERE COALESCE(tenant_id,'default')=? "
                     "ORDER BY ts DESC LIMIT ?", (tenant, int(limit))).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "matches": [{
        "id": r["id"], "ts_iso": fc.iso(r["ts"]), "ioc_type": r["ioc_type"],
        "ioc_value": r["ioc_value"], "threat": r["threat"], "severity": r["severity"],
        "source": r["source"], "agent_id": r["agent_id"], "event_id": r["event_id"],
    } for r in rows]}


def _j(s, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except Exception:
        return default if default is not None else {}

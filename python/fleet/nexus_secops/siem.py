# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/siem.py
"""
SIEM / Log Analytics untuk Nexus — pencarian + agregasi atas store manager.

Bukan menyalin lima SIEM; kita ambil yang TERBAIK dari tiap kategori lalu
satukan jadi satu mesin (anti-redundan):
  • bahasa kueri ringkas      — gaya Splunk SPL / Elastic KQL (ekspresif tapi mudah)
  • agregasi & histogram      — gaya Kibana/Graylog (dashboard, timeline)
  • model "offense"/insiden   — gaya IBM QRadar (lihat nexus_secops.correlate)

NQL (Nexus Query Language) — token dipisah spasi, semuanya AND:
  severity:high                 field sama-dengan (string case-insensitive)
  severity>=high                perbandingan severity (urutan info<low<medium<high<critical)
  level>=12                     perbandingan numerik (alert)
  agent_id:agt_abc123           cocok persis
  event_type:failed_login,sca   IN (pisah koma → OR)
  title:*brute*                 wildcard contains (juga: ~brute)
  -origin:demo                  NEGASI (NOT)
  target.path:*.env             jalur JSON bertingkat (dicek presisi di Python)
  last:24h                      jendela waktu relatif (m/h/d) — ts >= now-Δ
  ssh OR "failed password"      kata bebas → cari di title+detail (frasa pakai kutip)

`search(index, query)` mengembalikan baris ala list_events/list_alerts manager.
`stats(index, query)` mengembalikan agregasi siap-dashboard.
`explain(query)` mem-parse tanpa mengeksekusi (untuk validasi UI).
"""
import json
import re
import sqlite3
import time

from nexus_common import protocol as fc
from nexus_common import schema

# Kolom yang BOLEH dikueri per index. Hanya nama di sini yang masuk SQL — semua
# nilai diparameterkan; ini mencegah injeksi (nama kolom di-allowlist, value bound).
_EVENT_COLS = {
    "event_id", "agent_id", "tenant_id", "ts", "source", "type", "category",
    "event_type", "severity", "origin", "title", "detail", "host", "target",
    "evidence", "data",
}
_ALERT_COLS = {
    "id", "ts", "agent_id", "tenant_id", "level", "severity", "title",
    "description", "category", "event_type", "event_ref", "rule_id",
    "rule_name", "mitre", "recommendation", "response", "target", "evidence",
    "status", "origin",
}
# Kolom yang menyimpan teks JSON → pencarian bertingkat (target.path) dievaluasi
# di Python setelah fetch; pencarian datar (target:*x*) pakai LIKE pada teks JSON.
_JSON_COLS = {"host", "target", "evidence", "data", "mitre", "response"}
_NUM_COLS = {"ts", "level"}
_TEXT_SEARCH = ("title", "detail")          # tujuan kata bebas

_INDEXES = {
    "events": (_EVENT_COLS, "events", "id"),
    "alerts": (_ALERT_COLS, "alerts", "ts"),
}

_REL = re.compile(r"^(\d+)\s*([smhdw])$", re.I)
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_SEV_RANK = {s: i for i, s in enumerate(schema.SEVERITIES)}   # info=0 .. critical=4


# --------------------------------------------------------------------------- DB
def _conn():
    c = sqlite3.connect(fc.manager_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    return c


# --------------------------------------------------------------------------- tokenizer
def _split_tokens(q):
    """Pisah berdasarkan spasi tetapi hormati frasa berkutip ganda."""
    out, buf, quoted = [], [], False
    for ch in q or "":
        if ch == '"':
            quoted = not quoted
            buf.append(ch)
        elif ch.isspace() and not quoted:
            if buf:
                out.append("".join(buf)); buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


_FIELD_RE = re.compile(r"^(-?)([A-Za-z_][\w.]*)\s*(>=|<=|>|<|:)\s*(.*)$", re.S)


def parse(query):
    """NQL → daftar predikat + error. Tidak menyentuh DB (murni)."""
    preds, errors, free = [], [], []
    for tok in _split_tokens(query or ""):
        if tok.upper() == "OR":
            # OR antar-kata-bebas didukung implisit (kata bebas selalu OR di title/detail);
            # sebagai operator antar-field eksplisit belum didukung — abaikan token.
            continue
        m = _FIELD_RE.match(tok)
        if not m:
            free.append(tok.strip('"'))
            continue
        neg, field, op, val = m.group(1) == "-", m.group(2), m.group(3), m.group(4).strip('"')
        low = field.lower()
        if low == "last":                      # jendela waktu relatif
            rm = _REL.match(val)
            if not rm:
                errors.append(f"last: butuh format angka+satuan (mis. 24h, 7d) — dapat '{val}'")
                continue
            delta = int(rm.group(1)) * _UNIT[rm.group(2).lower()]
            preds.append({"kind": "time", "since": int(time.time()) - delta})
            continue
        base = low.split(".")[0]
        nested = "." in low
        preds.append({
            "kind": "json" if (nested or base in _JSON_COLS) else "flat",
            "field": low, "base": base, "op": op, "val": val, "neg": neg,
            "nested": nested,
        })
    if free:
        preds.append({"kind": "text", "terms": free})
    return preds, errors


def explain(query):
    """Validasi kueri untuk UI: daftar predikat + error tanpa eksekusi."""
    preds, errors = parse(query)
    return {"ok": not errors, "predicates": preds, "errors": errors,
            "query": query or ""}


# --------------------------------------------------------------------------- SQL builder
def _sql_for_flat(p, cols, where, params):
    field, op, val = p["field"], p["op"], p["val"]
    if field not in cols:
        return f"kolom '{field}' tak dikenal untuk index ini"
    neg = p["neg"]
    if field == "severity" and op in (">=", "<=", ">", "<"):
        rank = _SEV_RANK.get((val or "").lower())
        if rank is None:
            return f"severity tak dikenal: '{val}'"
        # bandingkan via daftar severitas pada/atas-bawah ambang
        keep = [s for s, r in _SEV_RANK.items()
                if (r >= rank if op == ">=" else r <= rank if op == "<="
                    else r > rank if op == ">" else r < rank)]
        ph = ",".join("?" * len(keep))
        where.append(f"({'NOT ' if neg else ''}severity IN ({ph}))")
        params.extend(keep)
        return None
    if op in (">=", "<=", ">", "<"):
        try:
            num = float(val)
        except ValueError:
            return f"'{field}{op}' butuh angka — dapat '{val}'"
        where.append(f"({'NOT ' if neg else ''}{field} {op} ?)")
        params.append(num)
        return None
    # op ':' — equals / IN / wildcard contains
    if "," in val:                                   # IN (OR)
        items = [v for v in val.split(",") if v != ""]
        ph = ",".join("?" * len(items))
        where.append(f"({'NOT ' if neg else ''}LOWER({field}) IN ({ph}))")
        params.extend([v.lower() for v in items])
        return None
    if val.startswith("~") or "*" in val:            # contains
        needle = val.lstrip("~").replace("*", "")
        where.append(f"({'NOT ' if neg else ''}LOWER({field}) LIKE ?)")
        params.append(f"%{needle.lower()}%")
        return None
    where.append(f"({'NOT ' if neg else ''}LOWER({field})=?)")
    params.append((val or "").lower())
    return None


def _build_sql(preds, cols, table):
    """Bangun WHERE untuk predikat flat/text/time. Predikat json disisakan untuk Python."""
    where, params, errors, json_preds = [], [], [], []
    for p in preds:
        if p["kind"] == "time":
            where.append("ts >= ?"); params.append(p["since"]); continue
        if p["kind"] == "text":
            ors = []
            for term in p["terms"]:
                clause = " OR ".join(f"LOWER({c}) LIKE ?" for c in _TEXT_SEARCH)
                ors.append(f"({clause})")
                params.extend([f"%{term.lower()}%"] * len(_TEXT_SEARCH))
            if ors:
                where.append("(" + " OR ".join(ors) + ")")
            continue
        if p["kind"] == "json":
            if p["base"] not in cols:
                errors.append(f"kolom '{p['base']}' tak dikenal untuk index ini")
                continue
            if not p["nested"]:                      # cari datar pada teks JSON
                needle = p["val"].lstrip("~").replace("*", "")
                where.append(f"({'NOT ' if p['neg'] else ''}LOWER({p['base']}) LIKE ?)")
                params.append(f"%{needle.lower()}%")
            else:
                json_preds.append(p)                 # dicek presisi di Python
            continue
        err = _sql_for_flat(p, cols, where, params)
        if err:
            errors.append(err)
    sql = f"SELECT * FROM {table}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    return sql, params, errors, json_preds


# --------------------------------------------------------------------------- nested JSON match
def _nested_get(row, dotted):
    base = dotted.split(".")[0]
    raw = row[base] if base in row.keys() else None
    try:
        cur = json.loads(raw) if raw else {}
    except Exception:
        return None
    for part in dotted.split(".")[1:]:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _json_match(row, p):
    val = _nested_get(row, p["field"])
    want, op = p["val"], p["op"]
    res = False
    if val is None:
        res = False
    elif op in (">=", "<=", ">", "<"):
        try:
            a, b = float(val), float(want)
            res = (a >= b if op == ">=" else a <= b if op == "<="
                   else a > b if op == ">" else a < b)
        except (TypeError, ValueError):
            res = False
    else:
        sval = str(val).lower()
        if want.startswith("~") or "*" in want:
            res = want.lstrip("~").replace("*", "").lower() in sval
        elif "," in want:
            res = sval in [w.lower() for w in want.split(",")]
        else:
            res = sval == want.lower()
    return (not res) if p["neg"] else res


# --------------------------------------------------------------------------- public API
def _row_to_event(r):
    return {
        "id": r["id"], "event_id": r["event_id"], "agent_id": r["agent_id"],
        "ts": r["ts"], "ts_iso": fc.iso(r["ts"]), "source": r["source"],
        "type": r["type"], "category": r["category"], "event_type": r["event_type"],
        "severity": r["severity"], "origin": r["origin"], "title": r["title"],
        "detail": r["detail"], "target": _j(r["target"]), "evidence": _j(r["evidence"]),
        "data": _j(r["data"]),
    }


def _row_to_alert(r):
    return {
        "id": r["id"], "ts": r["ts"], "ts_iso": fc.iso(r["ts"]), "agent_id": r["agent_id"],
        "level": r["level"], "severity": r["severity"], "title": r["title"],
        "description": r["description"], "category": r["category"],
        "event_type": r["event_type"], "rule_id": r["rule_id"], "rule_name": r["rule_name"],
        "mitre": _j(r["mitre"]), "status": r["status"], "origin": r["origin"],
        "target": _j(r["target"]), "evidence": _j(r["evidence"]),
    }


def _j(s):
    try:
        return json.loads(s) if s else {}
    except Exception:
        return {}


def search(index="events", query="", limit=200, order="desc"):
    """Jalankan kueri NQL. index: events|alerts. Mengembalikan hasil + meta."""
    index = (index or "events").lower()
    if index not in _INDEXES:
        return {"ok": False, "error": f"index harus events|alerts — dapat '{index}'"}
    cols, table, order_col = _INDEXES[index]
    preds, errors = parse(query)
    if errors:
        return {"ok": False, "error": "; ".join(errors), "query": query}
    sql, params, sql_errors, json_preds = _build_sql(preds, cols, table)
    if sql_errors:
        return {"ok": False, "error": "; ".join(sql_errors), "query": query}
    direction = "ASC" if str(order).lower() == "asc" else "DESC"
    # Jika ada predikat JSON bertingkat, ambil lebih banyak lalu saring di Python.
    fetch = int(limit) * 8 if json_preds else int(limit)
    sql += f" ORDER BY {order_col} {direction} LIMIT ?"
    params.append(max(fetch, int(limit)))
    try:
        c = _conn()
        rows = c.execute(sql, params).fetchall()
        c.close()
    except sqlite3.Error as e:
        return {"ok": False, "error": f"kesalahan kueri: {e}", "query": query}
    if json_preds:
        rows = [r for r in rows if all(_json_match(r, p) for p in json_preds)]
    rows = rows[:int(limit)]
    to = _row_to_alert if index == "alerts" else _row_to_event
    results = [to(r) for r in rows]
    return {"ok": True, "module": "nexus_secops", "index": index, "query": query,
            "count": len(results), "results": results}


def stats(index="events", query="", buckets=24, top_field="event_type", top_n=10):
    """Agregasi siap-dashboard: total, per-severity, top nilai field, histogram waktu."""
    res = search(index, query, limit=5000)
    if not res.get("ok"):
        return res
    rows = res["results"]
    by_sev = {s: 0 for s in schema.SEVERITIES}
    top = {}
    times = []
    for r in rows:
        sev = (r.get("severity") or "info").lower()
        if sev in by_sev:
            by_sev[sev] += 1
        key = str(r.get(top_field, "") or "—")
        top[key] = top.get(key, 0) + 1
        if r.get("ts"):
            times.append(r["ts"])
    top_list = sorted(({"value": k, "count": v} for k, v in top.items()),
                      key=lambda x: x["count"], reverse=True)[:int(top_n)]
    # histogram: bagi rentang [min,max] jadi N bucket seragam.
    hist = []
    if times:
        lo, hi = min(times), max(times)
        span = max(1, hi - lo)
        width = max(1, span // max(1, int(buckets)))
        counts = {}
        for t in times:
            # clamp ke bucket terakhir agar event di tepi atas (akibat width dibulatkan
            # ke bawah) tak hilang dari histogram.
            b = min(int(buckets), (t - lo) // width)
            counts[b] = counts.get(b, 0) + 1
        for b in range(int(buckets) + 1):
            ts0 = lo + b * width
            if ts0 > hi:
                break
            hist.append({"ts": ts0, "ts_iso": fc.iso(ts0), "count": counts.get(b, 0)})
    return {"ok": True, "module": "nexus_secops", "index": index, "query": query,
            "total": len(rows), "by_severity": by_sev,
            "top": {"field": top_field, "values": top_list}, "timeline": hist}

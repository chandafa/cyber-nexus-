# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/human_element.py
"""
Layer 8 — Human Element: pelatihan & kesadaran keamanan (phishing awareness).

Modul NYATA, berbasis DB (bukan data hardcoded): kampanye drill, percobaan kuis,
dan log disimpan permanen di SQLite. Statistik dihitung dari data sungguhan —
mulai kosong dan terisi sesuai aktivitas Anda.

Catatan etika: modul ini TIDAK mengirim email phishing ke alamat nyata. Mengirim
phishing ke orang tanpa persetujuan/infra resmi = ilegal. "Peluncuran kampanye"
di sini adalah pencatatan drill/latihan internal; tingkat klik/lapor diisi dari
hasil drill yang sungguh tercatat (default: belum ada data).
"""
import sqlite3
import time
import uuid

from core.dbpath import db_path
from core.stream_handler import emit_line


def _conn():
    c = sqlite3.connect(db_path())
    c.row_factory = sqlite3.Row
    return c


def _init():
    c = _conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS he_campaigns (
            id TEXT PRIMARY KEY, name TEXT, template TEXT, target_group TEXT,
            schedule TEXT, status TEXT, click_rate INTEGER, report_rate INTEGER,
            sent INTEGER DEFAULT 0, created_at INTEGER, last_run TEXT
        );
        CREATE TABLE IF NOT EXISTS he_quiz_attempts (
            id TEXT PRIMARY KEY, score INTEGER, total INTEGER, passed INTEGER, created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS he_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, message TEXT
        );
        """
    )
    c.commit()
    c.close()


def _now_iso():
    return time.strftime("%Y-%m-%d %H:%M", time.localtime())


def _log(msg: str):
    c = _conn()
    c.execute("INSERT INTO he_logs(ts, message) VALUES(?,?)", (int(time.time()), msg))
    # retensi: simpan 200 log terbaru
    c.execute("DELETE FROM he_logs WHERE id NOT IN (SELECT id FROM he_logs ORDER BY id DESC LIMIT 200)")
    c.commit()
    c.close()


def list_campaigns() -> list:
    c = _conn()
    rows = [dict(r) for r in c.execute("SELECT * FROM he_campaigns ORDER BY created_at DESC").fetchall()]
    c.close()
    return rows


def create_campaign(name: str, target_group: str, schedule: str, template: str = "") -> dict:
    cid = str(uuid.uuid4())[:8]
    now_run = (schedule or "").lower().find("sekarang") >= 0 or (schedule or "").lower().find("now") >= 0
    status = "Selesai" if now_run else "Aktif"
    c = _conn()
    c.execute(
        "INSERT INTO he_campaigns(id,name,template,target_group,schedule,status,"
        "click_rate,report_rate,sent,created_at,last_run) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (cid, name, template, target_group, schedule, status,
         None, None, 0, int(time.time()), _now_iso() if now_run else None),
    )
    c.commit()
    c.close()
    _log(f"[DRILL] Kampanye dibuat: '{name}' -> grup '{target_group}' ({schedule}).")
    if now_run:
        _log(f"[DRILL] Drill '{name}' dijalankan & dicatat. Hasil klik/lapor: belum ada data nyata.")
    return {"id": cid, "name": name, "target_group": target_group, "schedule": schedule, "status": status}


def record_result(campaign_id: str, click_rate: int, report_rate: int, sent: int = 0) -> dict:
    """Catat hasil drill NYATA (mis. dari integrasi tracker email). Mengisi angka asli."""
    c = _conn()
    c.execute("UPDATE he_campaigns SET click_rate=?, report_rate=?, sent=?, status='Selesai', last_run=? WHERE id=?",
              (int(click_rate), int(report_rate), int(sent), _now_iso(), campaign_id))
    c.commit()
    c.close()
    _log(f"[DRILL] Hasil dicatat utk {campaign_id}: klik {click_rate}% · lapor {report_rate}% ({sent} terkirim).")
    return {"ok": True}


def delete_campaign(campaign_id: str) -> dict:
    c = _conn()
    n = c.execute("DELETE FROM he_campaigns WHERE id=?", (campaign_id,)).rowcount
    c.commit()
    c.close()
    if n:
        _log(f"[DRILL] Kampanye {campaign_id} dihapus.")
    return {"ok": bool(n)}


def record_quiz(score: int, total: int) -> dict:
    passed = 1 if total and (score / total) >= 0.7 else 0
    c = _conn()
    c.execute("INSERT INTO he_quiz_attempts(id,score,total,passed,created_at) VALUES(?,?,?,?,?)",
              (str(uuid.uuid4())[:8], int(score), int(total), passed, int(time.time())))
    c.commit()
    c.close()
    _log(f"[QUIZ] Percobaan kuis dicatat: {score}/{total} -> {'LULUS' if passed else 'belum lulus'}.")
    return {"ok": True, "passed": bool(passed)}


def _avg(vals):
    vals = [v for v in vals if v is not None]
    return round(sum(vals) / len(vals), 1) if vals else None


def stats() -> dict:
    c = _conn()
    camps = [dict(r) for r in c.execute("SELECT * FROM he_campaigns").fetchall()]
    quiz = [dict(r) for r in c.execute("SELECT * FROM he_quiz_attempts").fetchall()]
    c.close()
    total_camp = len(camps)
    avg_click = _avg([x["click_rate"] for x in camps])
    avg_report = _avg([x["report_rate"] for x in camps])
    quiz_total = len(quiz)
    quiz_pass = sum(1 for x in quiz if x["passed"])
    quiz_rate = round(quiz_pass / quiz_total * 100, 0) if quiz_total else None
    return {
        "campaigns_total": total_camp,
        "avg_click_rate": avg_click,           # None = belum ada data nyata
        "avg_report_rate": avg_report,
        "quiz_attempts": quiz_total,
        "quiz_pass_rate": quiz_rate,           # None = belum ada percobaan
    }


def logs(limit: int = 50) -> list:
    c = _conn()
    rows = [r["message"] and f'[{time.strftime("%H:%M:%S", time.localtime(r["ts"]))}] {r["message"]}'
            for r in c.execute("SELECT ts, message FROM he_logs ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()]
    c.close()
    return rows


def run(submode: str = "overview", **kwargs) -> dict:
    _init()
    cb = emit_line
    if submode == "create":
        cb("[OK] Mencatat kampanye drill (NYATA, tersimpan di DB).")
        camp = create_campaign(kwargs.get("name", "Untitled"), kwargs.get("target_group", ""),
                               kwargs.get("schedule", ""), kwargs.get("template", ""))
        return {"module": "human_element", "submode": "create", "campaign": camp,
                "campaigns": list_campaigns(), "stats": stats(), "logs": logs()}
    if submode == "delete":
        r = delete_campaign(kwargs.get("id", ""))
        return {"module": "human_element", "submode": "delete", **r,
                "campaigns": list_campaigns(), "stats": stats(), "logs": logs()}
    if submode == "record":
        r = record_result(kwargs.get("id", ""), int(kwargs.get("click_rate", 0)),
                          int(kwargs.get("report_rate", 0)), int(kwargs.get("sent", 0)))
        return {"module": "human_element", "submode": "record", **r,
                "campaigns": list_campaigns(), "stats": stats()}
    if submode == "quiz":
        r = record_quiz(int(kwargs.get("score", 0)), int(kwargs.get("total", 0)))
        return {"module": "human_element", "submode": "quiz", **r, "stats": stats(), "logs": logs()}
    if submode == "clear_logs":
        c = _conn(); c.execute("DELETE FROM he_logs"); c.commit(); c.close()
        return {"module": "human_element", "submode": "clear_logs", "logs": []}
    # overview (default): muat semua data nyata
    return {"module": "human_element", "submode": "overview",
            "campaigns": list_campaigns(), "stats": stats(), "logs": logs()}

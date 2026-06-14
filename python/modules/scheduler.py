# nexus/python/modules/scheduler.py
"""Modul Scheduler — SDD v2 §5.17. CRUD jadwal scan di DB + hitung next_run.
Catatan: eksekusi otomatis butuh service latar; modul ini menyediakan
manajemen jadwal + 'run now'. Validasi & next_run via APScheduler CronTrigger."""
import sqlite3
import uuid
from datetime import datetime

from core.dbpath import db_path
from core.stream_handler import emit_line

try:
    from apscheduler.triggers.cron import CronTrigger
    _HAS_APS = True
except Exception:
    _HAS_APS = False


def _next_run(cron_expr: str) -> str:
    if not _HAS_APS:
        return ''
    try:
        trig = CronTrigger.from_crontab(cron_expr)
        nxt = trig.get_next_fire_time(None, datetime.now())
        return nxt.isoformat(timespec='seconds') if nxt else ''
    except Exception:
        return ''


def _conn():
    return sqlite3.connect(db_path())


def add_schedule(target: str, module: str, mode: str, cron_expr: str) -> dict:
    nr = _next_run(cron_expr)
    jid = str(uuid.uuid4())
    conn = _conn()
    conn.execute('''INSERT INTO scheduled_scans (id, target, module, mode, cron_expr, enabled, next_run)
                    VALUES (?,?,?,?,?,1,?)''', (jid, target, module, mode, cron_expr, nr))
    conn.commit()
    conn.close()
    return {'id': jid, 'target': target, 'module': module, 'mode': mode,
            'cron_expr': cron_expr, 'enabled': 1, 'next_run': nr}


def list_schedules() -> list:
    conn = _conn()
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(
            'SELECT * FROM scheduled_scans ORDER BY next_run').fetchall()]
    except Exception:
        rows = []
    conn.close()
    return rows


def remove_schedule(job_id: str):
    conn = _conn()
    conn.execute('DELETE FROM scheduled_scans WHERE id=?', (job_id,))
    conn.commit()
    conn.close()


def toggle_schedule(job_id: str, enabled: bool):
    conn = _conn()
    conn.execute('UPDATE scheduled_scans SET enabled=? WHERE id=?', (1 if enabled else 0, job_id))
    conn.commit()
    conn.close()


def run(submode: str = 'list', target: str = '', module: str = 'port', mode: str = 'standard',
        cron_expr: str = '0 2 * * *', job_id: str = '', enabled: str = '1', **kwargs) -> dict:
    cb = emit_line
    if submode == 'add':
        sched = add_schedule(target, module, mode, cron_expr)
        cb(f'[OK] Jadwal dibuat: {module} {target} ({cron_expr}) next={sched["next_run"] or "?"}')
        return {'module': 'scheduler', 'submode': 'add', 'schedule': sched,
                'schedules': list_schedules(), 'aps_available': _HAS_APS}
    if submode == 'remove':
        remove_schedule(job_id)
        return {'module': 'scheduler', 'submode': 'remove', 'schedules': list_schedules()}
    if submode == 'toggle':
        toggle_schedule(job_id, enabled in ('1', 'true', 'True', True))
        return {'module': 'scheduler', 'submode': 'toggle', 'schedules': list_schedules()}
    return {'module': 'scheduler', 'submode': 'list', 'schedules': list_schedules(),
            'aps_available': _HAS_APS}

# nexus/python/modules/security_score.py
"""Modul Security Score Dashboard — SDD v2 §5.15."""
import sqlite3
from datetime import datetime
from typing import Dict

from core.dbpath import db_path
from core.stream_handler import emit_line


class SecurityScoreCalculator:
    WEIGHTS = {
        'network_exposure': 0.25,
        'vulnerability': 0.30,
        'ssl_tls': 0.15,
        'password_policy': 0.10,
        'hardening': 0.20,
    }

    def calculate(self, data: dict) -> Dict:
        s = {}
        s['network_exposure'] = max(0, 100 - data.get('unnecessary_open_ports', 0) * 5)
        v = data.get('vuln_counts', {})
        penalty = (v.get('critical', 0) * 20 + v.get('high', 0) * 10 +
                   v.get('medium', 0) * 4 + v.get('low', 0) * 1)
        s['vulnerability'] = max(0, 100 - penalty)
        s['ssl_tls'] = max(0, 100 - data.get('tls_critical_findings', 0) * 25)
        weak = data.get('weak_credentials_found', 0)
        s['password_policy'] = 100 if weak == 0 else max(0, 100 - weak * 30)
        s['hardening'] = data.get('lynis_index', 50)
        total = sum(s[k] * self.WEIGHTS[k] for k in s)
        return {'overall_score': round(total, 1), 'grade': self._grade(total), 'breakdown': s}

    def _grade(self, score: float) -> str:
        if score >= 90:
            return 'A'
        if score >= 75:
            return 'B'
        if score >= 60:
            return 'C'
        if score >= 40:
            return 'D'
        return 'F'


def _aggregate_from_db() -> dict:
    """Kumpulkan metrik dari hasil scan tersimpan untuk skor agregat."""
    data = {'unnecessary_open_ports': 0, 'vuln_counts': {}, 'tls_critical_findings': 0,
            'weak_credentials_found': 0, 'lynis_index': 50}
    try:
        conn = sqlite3.connect(db_path())
        cur = conn.cursor()
        # port exposure: total distinct open ports minus essential (22,80,443)
        cur.execute("SELECT DISTINCT port FROM port_results")
        ports = [r[0] for r in cur.fetchall()]
        essential = {22, 80, 443}
        data['unnecessary_open_ports'] = len([p for p in ports if p not in essential])
        # vuln counts
        for sev in ['critical', 'high', 'medium', 'low']:
            cur.execute("SELECT COUNT(*) FROM vuln_results WHERE severity=?", (sev,))
            data['vuln_counts'][sev] = cur.fetchone()[0]
        # tls critical
        try:
            cur.execute("SELECT COUNT(*) FROM tls_findings WHERE status='critical'")
            data['tls_critical_findings'] = cur.fetchone()[0]
        except Exception:
            pass
        conn.close()
    except Exception:
        pass
    return data


def run(submode: str = 'compute', **kwargs) -> dict:
    cb = emit_line
    data = _aggregate_from_db()
    cb(f'[*] Menghitung skor keamanan agregat dari data tersimpan...')
    for k, v in data.items():
        cb(f'    {k}: {v}')
    score = SecurityScoreCalculator().calculate(data)
    cb(f'[*] Skor keseluruhan: {score["overall_score"]} (Grade {score["grade"]})')
    # simpan ke history
    try:
        conn = sqlite3.connect(db_path())
        b = score['breakdown']
        conn.execute('''INSERT INTO security_scores
            (session_id, target, overall_score, grade, network_exposure_score,
             vulnerability_score, ssl_tls_score, password_policy_score, hardening_score, calculated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (None, 'aggregate', score['overall_score'], score['grade'],
             b['network_exposure'], b['vulnerability'], b['ssl_tls'],
             b['password_policy'], b['hardening'], datetime.now().isoformat(timespec='seconds')))
        conn.commit()
        conn.close()
    except Exception:
        pass
    return {'module': 'score', **score, 'inputs': data}


def history() -> dict:
    rows = []
    try:
        conn = sqlite3.connect(db_path())
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT overall_score, grade, calculated_at FROM security_scores ORDER BY calculated_at DESC LIMIT 30')
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    except Exception:
        pass
    return {'module': 'score_history', 'history': list(reversed(rows))}

# nexus/python/modules/scan_diff.py
"""Modul Scan Diff / Compare — SDD v2 §5.16. Bandingkan dua sesi scan."""
import sqlite3
from typing import List, Dict

from core.dbpath import db_path
from core.stream_handler import emit_line


class ScanDiff:
    def compare_ports(self, old: List[dict], new: List[dict]) -> Dict:
        o = {(p['port'], p.get('protocol')): p for p in old}
        n = {(p['port'], p.get('protocol')): p for p in new}
        opened = [n[k] for k in n if k not in o]
        closed = [o[k] for k in o if k not in n]
        changed = []
        for k in o:
            if k in n and o[k].get('version') != n[k].get('version'):
                changed.append({'port': k[0], 'protocol': k[1],
                                'old_version': o[k].get('version'),
                                'new_version': n[k].get('version')})
        return {'newly_opened': opened, 'newly_closed': closed, 'version_changes': changed}

    def compare_vulns(self, old: List[dict], new: List[dict]) -> Dict:
        oid = {v['vuln_id'] for v in old if v.get('vuln_id')}
        nid = {v['vuln_id'] for v in new if v.get('vuln_id')}
        return {'new_findings': [v for v in new if v.get('vuln_id') not in oid],
                'fixed_findings': [v for v in old if v.get('vuln_id') not in nid],
                'still_present_count': len(oid & nid)}


def _load(session_id: str) -> dict:
    out = {'ports': [], 'vulns': []}
    try:
        conn = sqlite3.connect(db_path())
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT port, protocol, service, version FROM port_results WHERE session_id=?',
                    (session_id,))
        out['ports'] = [dict(r) for r in cur.fetchall()]
        cur.execute('SELECT vuln_id, severity, title FROM vuln_results WHERE session_id=?',
                    (session_id,))
        out['vulns'] = [dict(r) for r in cur.fetchall()]
        conn.close()
    except Exception:
        pass
    return out


def run(old_session: str = '', new_session: str = '', **kwargs) -> dict:
    cb = emit_line
    diff = ScanDiff()
    if not old_session or not new_session:
        from core.subprocess_runner import demo_disabled
        if demo_disabled():
            cb('[REAL] Pilih dua sesi scan untuk dibandingkan. '
               'Mode eksekusi nyata: diff contoh tidak ditampilkan.')
            empty_p = {'newly_opened': [], 'newly_closed': [], 'version_changes': []}
            empty_v = {'new_findings': [], 'fixed_findings': [], 'still_present_count': 0}
            return {'module': 'diff', 'old_session': old_session,
                    'new_session': new_session, 'ports': empty_p, 'vulns': empty_v}
        cb('[DEMO] Sesi tidak lengkap — diff demo.')
        old_p = [{'port': 22, 'protocol': 'tcp', 'version': 'OpenSSH 8.2'},
                 {'port': 80, 'protocol': 'tcp', 'version': 'nginx 1.18'}]
        new_p = [{'port': 22, 'protocol': 'tcp', 'version': 'OpenSSH 8.9'},
                 {'port': 80, 'protocol': 'tcp', 'version': 'nginx 1.18'},
                 {'port': 3306, 'protocol': 'tcp', 'version': 'MySQL 8.0'}]
        old_v = [{'vuln_id': 'CVE-2021-1', 'severity': 'high', 'title': 'Old bug'}]
        new_v = [{'vuln_id': 'CVE-2023-9', 'severity': 'critical', 'title': 'New bug'}]
        ports = diff.compare_ports(old_p, new_p)
        vulns = diff.compare_vulns(old_v, new_v)
    else:
        a, b = _load(old_session), _load(new_session)
        ports = diff.compare_ports(a['ports'], b['ports'])
        vulns = diff.compare_vulns(a['vulns'], b['vulns'])
    cb(f"[*] Port baru: {len(ports['newly_opened'])}, tertutup: {len(ports['newly_closed'])}, "
       f"versi berubah: {len(ports['version_changes'])}")
    cb(f"[*] Vuln baru: {len(vulns['new_findings'])}, fixed: {len(vulns['fixed_findings'])}")
    return {'module': 'diff', 'old_session': old_session, 'new_session': new_session,
            'ports': ports, 'vulns': vulns}

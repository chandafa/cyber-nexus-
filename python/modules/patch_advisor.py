# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/patch_advisor.py
"""Modul Patch Advisory — SDD v2 §5.19.2.
Konsolidasi temuan vuln/container per komponen + rekomendasi update."""
import json
import sqlite3
from typing import List, Dict

from core.dbpath import db_path
from core.stream_handler import emit_line

_SEV = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}


class PatchAdvisor:
    def build_patch_list(self, findings: List[dict]) -> List[Dict]:
        grouped: Dict[str, dict] = {}
        for f in findings:
            key = f.get('package') or f.get('service') or 'unknown'
            g = grouped.setdefault(key, {
                'component': key,
                'current_version': f.get('installed_version') or f.get('version') or '-',
                'recommended_version': f.get('fixed_version', 'Cek dokumentasi vendor'),
                'issues': [], 'max_severity': 'low',
            })
            issue = f.get('vuln_id') or f.get('title')
            if issue and issue not in g['issues']:
                g['issues'].append(issue)
            if _SEV.get(f.get('severity', 'low'), 0) > _SEV.get(g['max_severity'], 0):
                g['max_severity'] = f.get('severity', 'low')
        return sorted(grouped.values(),
                      key=lambda x: -_SEV.get(x['max_severity'], 0))


def _load_findings() -> List[dict]:
    findings = []
    try:
        conn = sqlite3.connect(db_path())
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT vuln_id, severity, title FROM vuln_results')
        findings = [dict(r) for r in cur.fetchall()]
        conn.close()
    except Exception:
        pass
    return findings


def run(findings: str = '', **kwargs) -> dict:
    cb = emit_line
    data = []
    if findings:
        try:
            data = json.loads(findings)
        except Exception:
            data = []
    if not data:
        data = _load_findings()
    if not data:
        from core.subprocess_runner import demo_disabled
        if demo_disabled():
            cb('[REAL] Belum ada temuan tersimpan — jalankan vuln/container scan '
               'dulu. Mode eksekusi nyata: contoh palsu tidak ditampilkan.')
            return {'module': 'patch', 'advisories': [], 'total': 0}
        cb('[DEMO] Tidak ada temuan tersimpan — contoh patch advisory.')
        data = [
            {'package': 'openssl', 'installed_version': '1.1.1n', 'fixed_version': '1.1.1t',
             'severity': 'high', 'vuln_id': 'CVE-2023-0286'},
            {'package': 'log4j', 'version': '2.14.1', 'fixed_version': '2.17.1',
             'severity': 'critical', 'vuln_id': 'CVE-2021-44228'},
            {'service': 'nginx', 'version': '1.18.0', 'fixed_version': '1.24.0',
             'severity': 'medium', 'vuln_id': 'version-disclosure'},
        ]
    patches = PatchAdvisor().build_patch_list(data)
    for p in patches:
        cb(f'[{p["max_severity"].upper()}] {p["component"]}: {p["current_version"]} -> '
           f'{p["recommended_version"]} ({len(p["issues"])} isu)')
    return {'module': 'patch', 'advisories': patches, 'total': len(patches)}

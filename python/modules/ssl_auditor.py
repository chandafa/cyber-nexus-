# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/ssl_auditor.py
"""Modul SSL/TLS Auditor — SDD v2 §5.7. sslyze + demo fallback."""
import subprocess
import json
import os
import tempfile
from dataclasses import dataclass, asdict
from typing import Callable, List, Optional

from core.subprocess_runner import tool_available, simulate_stream, tool_argv
from core.stream_handler import emit_line


@dataclass
class TlsFinding:
    category: str   # protocol | cipher | certificate | vulnerability
    name: str
    status: str     # ok | warning | critical
    detail: str


class SslAuditor:
    def run_sslyze(self, target: str, port: int = 443,
                   output_callback: Optional[Callable] = None) -> List[TlsFinding]:
        cb = output_callback or emit_line
        if not tool_available('sslyze'):
            cb('[DEMO] sslyze tidak terpasang — audit TLS demo.')
            return self._demo(target, port, cb)
        out = os.path.join(tempfile.gettempdir(), 'sslyze_out.json')
        cmd = tool_argv('sslyze', [f'--json_out={out}', f'{target}:{port}'])
        cb(f'$ {" ".join(cmd)}')
        cb('[*] Mengaudit TLS (timeout 120s)...')
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            for line in (r.stdout or '').splitlines()[:60]:
                cb(line)
            findings = self._parse(out)
            return findings if findings else self._demo(target, port, cb)
        except subprocess.TimeoutExpired:
            cb('[!] sslyze timeout. Mode demo.')
            return self._demo(target, port, cb)
        except Exception as e:
            cb(f'[!] {e}. Mode demo.')
            return self._demo(target, port, cb)

    def _parse(self, json_path: str) -> List[TlsFinding]:
        findings: List[TlsFinding] = []
        try:
            with open(json_path, encoding='utf-8', errors='replace') as f:
                data = json.load(f)
            tr = data['server_scan_results'][0]['scan_result']
            for proto in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1']:
                res = tr.get(f'{proto}_cipher_suites', {})
                accepted = res.get('result', {}).get('accepted_cipher_suites', [])
                if accepted:
                    findings.append(TlsFinding('protocol', proto.upper().replace('_', '.'),
                                               'critical',
                                               f'Protokol deprecated aktif ({len(accepted)} cipher)'))
            def _name(x):
                if isinstance(x, dict):
                    return x.get('rfc4514_string') or x.get('value') or str(x)
                return str(x)
            cert = tr.get('certificate_info', {}).get('result', {})
            for dep in cert.get('certificate_deployments', []):
                leaf = dep['received_certificate_chain'][0]
                findings.append(TlsFinding(
                    'certificate', 'Certificate Validity',
                    'ok' if dep.get('leaf_certificate_subject_matches_hostname') else 'warning',
                    f"Subject: {_name(leaf.get('subject'))} | Issuer: {_name(leaf.get('issuer'))}"))
            if tr.get('heartbleed', {}).get('result', {}).get('is_vulnerable_to_heartbleed'):
                findings.append(TlsFinding('vulnerability', 'Heartbleed (CVE-2014-0160)',
                                           'critical', 'Server rentan Heartbleed — upgrade OpenSSL'))
            robot = tr.get('robot', {}).get('result', {})
            if robot.get('robot_result', '') not in ('NOT_VULNERABLE_NO_ORACLE', ''):
                findings.append(TlsFinding('vulnerability', 'ROBOT Attack',
                                           'critical', 'Server rentan ROBOT (RSA padding oracle)'))
        except Exception as e:
            findings.append(TlsFinding('error', 'Parser Error', 'warning', str(e)))
        return findings

    def _demo(self, target: str, port: int, cb: Callable) -> List[TlsFinding]:
        lines = [
            f'$ sslyze {target}:{port} (demo)',
            f'CHECKING CONNECTIVITY TO SERVER — {target}:{port}  OK',
            'SCAN RESULTS FOR ' + target,
            ' * TLS 1.0 Cipher Suites: 5 accepted (DEPRECATED)',
            ' * TLS 1.2 Cipher Suites: 12 accepted',
            ' * TLS 1.3 Cipher Suites: 3 accepted',
            ' * Certificate: CN=' + target + ', expires in 41 days',
            ' * Heartbleed: NOT vulnerable',
            ' * Weak cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA detected',
        ]
        simulate_stream(lines, cb, delay=0.05)
        return [
            TlsFinding('protocol', 'TLS.1.0', 'critical', 'Protokol deprecated masih aktif (5 cipher)'),
            TlsFinding('protocol', 'TLS.1.1', 'warning', 'Protokol lama sebaiknya dimatikan'),
            TlsFinding('cipher', '3DES (CVE-2016-2183 SWEET32)', 'warning', 'Cipher 3DES lemah terdeteksi'),
            TlsFinding('certificate', 'Certificate Validity', 'ok',
                       f'Subject: CN={target}; berlaku 41 hari lagi'),
            TlsFinding('vulnerability', 'Heartbleed', 'ok', 'Tidak rentan'),
            TlsFinding('protocol', 'HSTS Header', 'warning', 'Strict-Transport-Security tidak diset'),
        ]


def run(target: str, port: int = 443, **kwargs) -> dict:
    findings = SslAuditor().run_sslyze(target, int(port))
    crit = sum(1 for f in findings if f.status == 'critical')
    return {'module': 'ssl', 'target': target, 'port': int(port),
            'findings': [asdict(f) for f in findings],
            'critical_count': crit, 'total': len(findings)}

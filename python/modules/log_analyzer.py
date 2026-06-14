# nexus/python/modules/log_analyzer.py
"""
Modul Log Analyzer — SDD bagian 5.5.
Parse log sistem/web/firewall, deteksi pola anomali sesuai tabel SDD 5.5.3.
Demo fallback bila tidak ada file log nyata.
"""
import re
import os
from collections import defaultdict
from datetime import datetime
from typing import Callable, List, Optional

from core.subprocess_runner import simulate_stream
from core.stream_handler import emit_line

# Pola deteksi anomali (SDD 5.5.3).
PATTERNS = {
    'ssh_brute_force': {
        'regex': re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'),
        'severity': 'high', 'threshold': 10, 'window': 300,
        'label': 'SSH Brute Force',
    },
    'sql_injection': {
        'regex': re.compile(r"('\s*OR\s|UNION\s+SELECT|--|;\s*DROP)", re.IGNORECASE),
        'severity': 'critical', 'threshold': 1, 'window': 0,
        'label': 'SQL Injection',
    },
    'directory_traversal': {
        'regex': re.compile(r'(\.\./|\.\.\\){2,}'),
        'severity': 'high', 'threshold': 1, 'window': 0,
        'label': 'Directory Traversal',
    },
    'privilege_escalation': {
        'regex': re.compile(r'sudo:.*COMMAND='),
        'severity': 'medium', 'threshold': 1, 'window': 0,
        'label': 'Privilege Escalation',
    },
}

IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


class LogAnalyzer:
    def analyze(self, log_path: str, log_type: str = 'auto',
                output_callback: Optional[Callable] = None) -> List[dict]:
        cb = output_callback or emit_line
        if not log_path or not os.path.isfile(log_path):
            cb(f'[DEMO] File log "{log_path}" tidak ditemukan — analisis demo dijalankan.')
            return self._demo_analyze(cb)

        cb(f'[*] Menganalisis {log_path} (type={log_type})')
        anomalies: List[dict] = []
        brute_track = defaultdict(list)

        with open(log_path, 'r', errors='ignore') as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.rstrip('\n')
                for name, p in PATTERNS.items():
                    m = p['regex'].search(line)
                    if not m:
                        continue
                    ip_m = IP_RE.search(line)
                    src_ip = ip_m.group(1) if ip_m else ''
                    if name == 'ssh_brute_force' and src_ip:
                        brute_track[src_ip].append(lineno)
                        if len(brute_track[src_ip]) == p['threshold']:
                            anomalies.append(self._mk(name, p, src_ip, line))
                            cb(f'[!] {p["label"]} dari {src_ip} (>{p["threshold"]}x)')
                    elif name != 'ssh_brute_force':
                        anomalies.append(self._mk(name, p, src_ip, line))
                        cb(f'[!] {p["label"]}: {line[:80]}')
        cb(f'[*] Selesai. {len(anomalies)} anomali terdeteksi.')
        return anomalies

    def _mk(self, name, p, src_ip, line):
        return {
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'source_ip': src_ip, 'attack_type': p['label'],
            'severity': p['severity'], 'detail': name, 'raw_line': line[:300],
        }

    def _demo_analyze(self, cb) -> List[dict]:
        sample = [
            'Jan 14 10:22:01 srv sshd[2211]: Failed password for root from 203.0.113.9 port 51000 ssh2',
            'Jan 14 10:22:02 srv sshd[2212]: Failed password for root from 203.0.113.9 port 51002 ssh2',
            'Jan 14 10:22:03 srv sshd[2213]: Failed password for admin from 203.0.113.9 port 51004 ssh2',
            '192.168.1.50 - - "GET /products?id=1 OR 1=1 UNION SELECT user,pass FROM users HTTP/1.1" 200',
            '10.0.0.5 - - "GET /../../../../etc/passwd HTTP/1.1" 404',
            'Jan 14 10:25:11 srv sudo: bob : COMMAND=/usr/bin/cat /etc/shadow',
        ]
        cb('[*] Menganalisis log demo (6 baris sampel)...')
        simulate_stream(sample, cb, delay=0.05)
        anomalies = [
            {'timestamp': datetime.now().isoformat(timespec='seconds'),
             'source_ip': '203.0.113.9', 'attack_type': 'SSH Brute Force',
             'severity': 'high', 'detail': 'ssh_brute_force',
             'raw_line': 'Failed password for root from 203.0.113.9 (x3 in window)'},
            {'timestamp': datetime.now().isoformat(timespec='seconds'),
             'source_ip': '192.168.1.50', 'attack_type': 'SQL Injection',
             'severity': 'critical', 'detail': 'sql_injection',
             'raw_line': "GET /products?id=1 OR 1=1 UNION SELECT user,pass"},
            {'timestamp': datetime.now().isoformat(timespec='seconds'),
             'source_ip': '10.0.0.5', 'attack_type': 'Directory Traversal',
             'severity': 'high', 'detail': 'directory_traversal',
             'raw_line': 'GET /../../../../etc/passwd'},
            {'timestamp': datetime.now().isoformat(timespec='seconds'),
             'source_ip': '', 'attack_type': 'Privilege Escalation',
             'severity': 'medium', 'detail': 'privilege_escalation',
             'raw_line': 'sudo: bob : COMMAND=/usr/bin/cat /etc/shadow'},
        ]
        cb(f'[*] Selesai. {len(anomalies)} anomali terdeteksi (demo).')
        return anomalies


def run(log_path: str = '', log_type: str = 'auto', **kwargs) -> dict:
    analyzer = LogAnalyzer()
    anomalies = analyzer.analyze(log_path, log_type)
    by_sev = defaultdict(int)
    for a in anomalies:
        by_sev[a['severity']] += 1
    return {'module': 'log', 'log_path': log_path, 'anomalies': anomalies,
            'total': len(anomalies), 'by_severity': dict(by_sev)}

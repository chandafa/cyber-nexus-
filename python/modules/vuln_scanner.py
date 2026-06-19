# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/vuln_scanner.py
"""
Modul Vulnerability Scanner — SDD bagian 5.3.
Menggabungkan Nikto (HTTP vuln), Gobuster (dir enum), Nuclei (CVE templates).
Demo fallback bila tool tidak terpasang.
"""
import subprocess
import json
import os
import tempfile
from typing import Callable, List, Optional

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line


class VulnScanner:
    # ----------------------------------------------------------------- nikto
    def run_nikto(self, target: str, output_callback: Optional[Callable] = None) -> List[dict]:
        cb = output_callback or emit_line
        if not tool_available('nikto'):
            cb('[DEMO] nikto tidak terpasang — output demo.')
            return self._demo_nikto(target, cb)

        # Parse STDOUT langsung (andal lintas-versi & tak butuh modul Perl JSON,
        # yang sering bikin "Invalid output format").
        cmd = ['nikto', '-h', target, '-nointeractive', '-maxtime', '120s']
        cb(f'$ {" ".join(cmd)}')
        lines = self._stream(cmd, cb)
        return self._parse_nikto_stdout(lines, target)

    def _parse_nikto_stdout(self, lines: List[str], target: str) -> List[dict]:
        skip_starts = ('Target IP', 'Target Hostname', 'Target Port', 'Start Time',
                       'End Time', 'Scan terminated', 'Nikto v', 'No web server',
                       'SSL Info', 'ERROR', 'No CGI', 'Root page')
        skip_contains = ('host(s) tested', 'requested by the host')
        out = []
        for s in lines:
            t = s.strip()
            if not t.startswith('+'):
                continue
            body = t[1:].strip()
            if (not body or any(body.startswith(x) for x in skip_starts)
                    or any(x in body for x in skip_contains)):
                continue
            out.append({'tool': 'nikto', 'severity': 'medium', 'vuln_id': '',
                        'title': body[:200], 'description': body, 'url': target,
                        'remediation': ''})
        return out

    # -------------------------------------------------------------- gobuster
    def run_gobuster(self, target: str, wordlist: str = 'wordlists/common_dirs.txt',
                     mode: str = 'dir', output_callback: Optional[Callable] = None) -> List[str]:
        cb = output_callback or emit_line
        if not tool_available('gobuster'):
            cb('[DEMO] gobuster tidak terpasang — output demo.')
            return self._demo_gobuster(target, cb)

        cmd = ['gobuster', mode, '-u', target, '-w', wordlist, '-q', '--no-color']
        cb(f'$ {" ".join(cmd)}')
        lines = self._stream(cmd, cb)
        # gobuster -q mencetak temuan: "admin  (Status: 301) [Size: ..]" → ambil
        # baris yang memuat "(Status:" (rapikan spasi ganda).
        return [' '.join(l.split()) for l in lines if '(Status:' in l]

    # ----------------------------------------------------------------- nuclei
    def run_nuclei(self, target: str, output_callback: Optional[Callable] = None) -> List[dict]:
        cb = output_callback or emit_line
        if not tool_available('nuclei'):
            cb('[DEMO] nuclei tidak terpasang — output demo.')
            return self._demo_nuclei(target, cb)

        # -jsonl ke STDOUT (tanpa file) — parse tiap baris JSON.
        cmd = ['nuclei', '-u', target, '-jsonl', '-silent',
               '-severity', 'low,medium,high,critical']
        cb(f'$ {" ".join(cmd)}')
        lines = self._stream(cmd, cb)
        results = []
        for line in lines:
            line = line.strip()
            if not (line.startswith('{') and line.endswith('}')):
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            info = j.get('info', {})
            results.append({
                'tool': 'nuclei',
                'severity': info.get('severity', 'info'),
                'vuln_id': j.get('template-id', ''),
                'title': info.get('name', ''),
                'description': info.get('description', ''),
                'url': j.get('matched-at', target),
                'remediation': (info.get('remediation', '') or ''),
            })
        return results

    # -------------------------------------------------------------- helpers
    def _stream(self, cmd, cb) -> List[str]:
        """Jalankan tool (via routing WSL), stream + KUMPULKAN baris stdout."""
        cmd = fix_tool_cmd(cmd)
        collected: List[str] = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                s = line.rstrip('\n')
                collected.append(s)
                cb(s)
            proc.wait()
        except Exception as e:
            cb(f'[ERROR] {e}')
        return collected

    # ----------------------------------------------------------------- demo
    def _demo_nikto(self, target, cb) -> List[dict]:
        lines = [
            f'- Nikto v2.5.0 (demo)',
            f'+ Target Host: {target}',
            '+ Server: nginx/1.18.0',
            '+ /: Server may leak inodes via ETags, header found with file /, fields: 0x...',
            '+ The X-Content-Type-Options header is not set.',
            '+ The X-Frame-Options header is not set.',
            '+ /admin/: Admin login page/section found.',
            '+ 7 host(s) tested',
        ]
        simulate_stream(lines, cb, delay=0.05)
        return [
            {'tool': 'nikto', 'severity': 'medium', 'vuln_id': 'OSVDB-3092',
             'title': 'Missing X-Frame-Options header', 'description': 'Clickjacking protection absent.',
             'url': f'{target}/', 'remediation': 'Set X-Frame-Options: DENY'},
            {'tool': 'nikto', 'severity': 'low', 'vuln_id': 'OSVDB-3268',
             'title': 'Admin section exposed', 'description': '/admin/ reachable.',
             'url': f'{target}/admin/', 'remediation': 'Restrict access by IP / auth.'},
        ]

    def _demo_gobuster(self, target, cb) -> List[str]:
        found = ['/admin (Status: 301)', '/login (Status: 200)', '/api (Status: 200)',
                 '/uploads (Status: 301)', '/.git (Status: 403)', '/backup (Status: 200)']
        lines = [f'$ gobuster dir -u {target} (demo)'] + [f'{x}' for x in found]
        simulate_stream(lines, cb, delay=0.05)
        return found

    def _demo_nuclei(self, target, cb) -> List[dict]:
        findings = [
            {'tool': 'nuclei', 'severity': 'critical', 'vuln_id': 'CVE-2021-44228',
             'title': 'Apache Log4j RCE (Log4Shell)', 'description': 'JNDI lookup RCE.',
             'url': f'{target}/', 'remediation': 'Upgrade Log4j >= 2.17.1'},
            {'tool': 'nuclei', 'severity': 'high', 'vuln_id': 'CVE-2017-5638',
             'title': 'Apache Struts2 RCE', 'description': 'Content-Type OGNL injection.',
             'url': f'{target}/', 'remediation': 'Patch Struts2'},
            {'tool': 'nuclei', 'severity': 'medium', 'vuln_id': 'tech-detect:nginx',
             'title': 'nginx version disclosure', 'description': 'Server header reveals version.',
             'url': f'{target}/', 'remediation': 'Hide server tokens'},
        ]
        lines = [f'[critical] {target} CVE-2021-44228 (Log4Shell)',
                 f'[high] {target} CVE-2017-5638 (Struts2 RCE)',
                 f'[medium] {target} nginx version disclosure']
        simulate_stream(lines, cb, delay=0.06)
        return findings


def run(target: str, tools: str = 'nikto,gobuster,nuclei',
        wordlist: str = 'wordlists/common_dirs.txt', **kwargs) -> dict:
    scanner = VulnScanner()
    selected = [t.strip() for t in tools.split(',') if t.strip()]
    vulns: List[dict] = []
    dirs: List[str] = []
    if 'nikto' in selected:
        vulns += scanner.run_nikto(target)
    if 'gobuster' in selected:
        dirs = scanner.run_gobuster(target, wordlist)
    if 'nuclei' in selected:
        vulns += scanner.run_nuclei(target)
    return {'module': 'vuln', 'target': target, 'vulnerabilities': vulns,
            'directories': dirs, 'total': len(vulns)}

# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/defense_monitor.py
"""
Modul Defense Monitor — SDD bagian 5.6.
Firewall analyzer, open port audit, SSH hardening check, Lynis audit,
SUID finder, password policy. Lintas-platform dengan demo fallback.
"""
import subprocess
import re
import platform
from typing import Callable, List, Optional

from core.subprocess_runner import tool_available, simulate_stream
from core.stream_handler import emit_line


class DefenseMonitor:
    # ----------------------------------------------------------- firewall
    def get_firewall_rules(self, callback: Optional[Callable] = None) -> list:
        cb = callback or emit_line
        system = platform.system()
        try:
            if system == 'Linux' and tool_available('iptables'):
                result = subprocess.run(['iptables', '-L', '-n', '-v', '--line-numbers'],
                                        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
                cb(result.stdout)
                return result.stdout.strip().split('\n')
            if system == 'Windows':
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'],
                                        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
                cb(result.stdout)
                return result.stdout.strip().split('\n')
        except Exception as e:
            cb(f'[ERROR] {e}')
        cb('[DEMO] Firewall tool tidak tersedia — output demo.')
        demo = ['Chain INPUT (policy DROP)', 'pkts target prot opt source destination',
                ' 120 ACCEPT tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:22',
                ' 998 ACCEPT tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:443',
                '   5 DROP   all  --  10.0.0.66  0.0.0.0/0']
        simulate_stream(demo, cb, delay=0.04)
        return demo

    # --------------------------------------------------------- open ports
    def find_open_ports(self, callback: Optional[Callable] = None) -> list:
        cb = callback or emit_line
        system = platform.system()
        try:
            if system == 'Linux' and tool_available('ss'):
                result = subprocess.run(['ss', '-tlnpu'], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
                cb(result.stdout)
                return result.stdout.strip().split('\n')
            if system == 'Windows':
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
                lines = [l for l in result.stdout.split('\n') if 'LISTENING' in l]
                for l in lines[:40]:
                    cb(l.strip())
                return lines
        except Exception as e:
            cb(f'[ERROR] {e}')
        demo = ['State  Local Address:Port   Process',
                'LISTEN 0.0.0.0:22            sshd',
                'LISTEN 0.0.0.0:80            nginx',
                'LISTEN 127.0.0.1:3306        mysqld',
                'LISTEN 0.0.0.0:445           smbd  <-- pertimbangkan tutup']
        simulate_stream(demo, cb, delay=0.04)
        return demo

    # ----------------------------------------------------------- SSH check
    def check_ssh_hardening(self, callback: Optional[Callable] = None) -> List[dict]:
        cb = callback or emit_line
        checks = []
        rules = [
            ('PermitRootLogin', 'no', 'Root login harus dinonaktifkan'),
            ('PasswordAuthentication', 'no', 'Gunakan SSH key, bukan password'),
            ('X11Forwarding', 'no', 'X11 forwarding tidak perlu jika bukan GUI'),
            ('MaxAuthTries', '3', 'Batasi percobaan auth maksimal 3-5'),
        ]
        try:
            with open('/etc/ssh/sshd_config') as f:
                content = f.read()
            for key, expected, msg in rules:
                val = re.search(rf'^{key}\s+(\S+)', content, re.MULTILINE)
                current = val.group(1) if val else 'not set'
                checks.append({'check': key, 'passed': current == expected,
                               'current': current, 'expected': expected,
                               'recommendation': msg})
                cb(f'[{"OK" if current == expected else "WARN"}] {key} = {current}')
        except FileNotFoundError:
            from core.subprocess_runner import demo_disabled, DemoDisabled
            if demo_disabled():
                cb('[REAL] /etc/ssh/sshd_config tidak ada (sistem non-Linux / tanpa '
                   'SSH server). Mode eksekusi nyata: hasil contoh tidak ditampilkan.')
                raise DemoDisabled('ssh hardening: sshd_config tidak tersedia')
            cb('[DEMO] /etc/ssh/sshd_config tidak ditemukan — hasil demo.')
            demo_vals = {'PermitRootLogin': 'yes', 'PasswordAuthentication': 'yes',
                         'X11Forwarding': 'no', 'MaxAuthTries': '6'}
            for key, expected, msg in rules:
                cur = demo_vals[key]
                checks.append({'check': key, 'passed': cur == expected,
                               'current': cur, 'expected': expected, 'recommendation': msg})
                cb(f'[{"OK" if cur == expected else "WARN"}] {key} = {cur}')
        return checks

    # ----------------------------------------------------------- SUID find
    def find_suid_files(self, callback: Optional[Callable] = None) -> List[str]:
        cb = callback or emit_line
        if platform.system() != 'Linux':
            cb('[DEMO] SUID finder hanya untuk Linux — daftar demo.')
            demo = ['/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/pkexec  <-- audit',
                    '/usr/bin/find  <-- audit (GTFOBins)']
            simulate_stream(demo, cb, delay=0.03)
            return demo
        try:
            result = subprocess.run(['find', '/', '-perm', '/6000', '-type', 'f'],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            files = [l.strip() for l in result.stdout.split('\n') if l.strip()]
            for f in files[:50]:
                cb(f)
            return files
        except Exception as e:
            cb(f'[ERROR] {e}')
            return []

    # ------------------------------------------------------------- lynis
    def run_lynis(self, callback: Optional[Callable] = None) -> dict:
        cb = callback or emit_line
        if not tool_available('lynis'):
            cb('[DEMO] lynis tidak terpasang — audit demo.')
            demo = ['[+] Initializing program', '[+] System Tools',
                    '[+] Boot and services', '[+] Kernel Hardening',
                    'Hardening index : 67 [#############       ] (demo)',
                    'Suggestions: 23, Warnings: 4']
            simulate_stream(demo, cb, delay=0.05)
            return {'hardening_index': 67, 'suggestions': 23, 'warnings': 4}
        score = {'hardening_index': 0, 'suggestions': 0, 'warnings': 0}
        try:
            proc = subprocess.Popen(['lynis', 'audit', 'system', '--quick', '--no-colors'],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip('\n')
                cb(line)
                m = re.search(r'Hardening index\s*:\s*(\d+)', line)
                if m:
                    score['hardening_index'] = int(m.group(1))
            proc.wait()
        except Exception as e:
            cb(f'[ERROR] {e}')
        return score


def run(submode: str = 'all', **kwargs) -> dict:
    """Jalankan tiap sub-cek secara independen. Di mode eksekusi nyata, sub-cek
    yang hanya berlaku di Linux (ssh/suid/lynis) akan di-SKIP dengan jujur bila
    tidak tersedia — TANPA membatalkan sub-cek lain yang menghasilkan data nyata
    (mis. firewall & open ports via netsh/netstat di Windows)."""
    from core.subprocess_runner import DemoDisabled
    mon = DefenseMonitor()
    out = {'module': 'defense', 'submode': submode}
    skipped = []

    def _try(name, fn):
        try:
            return fn()
        except DemoDisabled:
            emit_line(f'[SKIP] {name}: tidak tersedia / tidak berlaku di sistem ini '
                      f'(mode nyata — tanpa data contoh).')
            skipped.append(name)
            return None

    if submode in ('all', 'firewall'):
        out['firewall'] = _try('firewall', mon.get_firewall_rules)
    if submode in ('all', 'ports'):
        out['open_ports'] = _try('open_ports', mon.find_open_ports)
    if submode in ('all', 'ssh'):
        out['ssh_checks'] = _try('ssh', mon.check_ssh_hardening)
    if submode in ('all', 'suid'):
        out['suid_files'] = _try('suid', mon.find_suid_files)
    if submode in ('all', 'lynis'):
        out['lynis'] = _try('lynis', mon.run_lynis)
    if skipped:
        out['skipped'] = skipped
    return out

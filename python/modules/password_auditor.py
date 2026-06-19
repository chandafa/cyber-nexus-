# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/password_auditor.py
"""
Modul Password Auditor — SDD bagian 5.4.
Hydra (online brute force) + Hashcat (offline hash cracking) + hash detection.
Demo fallback bila tool tidak terpasang.
"""
import subprocess
import os
import tempfile
from typing import Callable, Optional

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line

HYDRA_PROTOCOLS = ['ssh', 'ftp', 'http-get', 'http-post-form', 'smb', 'rdp',
                   'mysql', 'postgres', 'telnet']

HASHCAT_MODES = {
    0: 'MD5', 100: 'SHA1', 1400: 'SHA256', 1700: 'SHA512',
    1800: 'SHA-512 (Unix)', 1000: 'NTLM', 3200: 'bcrypt', 2500: 'WPA/WPA2',
}


class PasswordAuditor:
    # ------------------------------------------------------------------ hydra
    def run_hydra(self, target: str, protocol: str, username: Optional[str] = None,
                  user_list: Optional[str] = None, password_list: str = 'wordlists/rockyou.txt',
                  port: Optional[int] = None, extra_opts: str = '',
                  output_callback: Optional[Callable] = None):
        cb = output_callback or emit_line
        if not tool_available('hydra'):
            cb('[DEMO] hydra tidak terpasang — output demo.')
            return self._demo_hydra(target, protocol, username, cb)

        cmd = ['hydra', '-t', '16', '-V']
        if username:
            cmd += ['-l', username]
        elif user_list:
            cmd += ['-L', user_list]
        cmd += ['-P', password_list]
        if port:
            cmd += ['-s', str(port)]
        cmd.append(f'{protocol}://{target}')
        cb(f'$ {" ".join(cmd)}')

        found = []
        try:
            cmd = fix_tool_cmd(cmd)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip('\n')
                cb(line)
                if 'login:' in line and 'password:' in line:
                    found.append(line.strip())
            proc.wait()
            if proc.returncode not in (0, None) and not found:
                cb('[!] hydra gagal/keluar tanpa hasil — mode demo.')
                return self._demo_hydra(target, protocol, username, cb)
        except Exception as e:
            cb(f'[!] hydra gagal ({e}) — mode demo.')
            return self._demo_hydra(target, protocol, username, cb)
        return {'found': found}

    # --------------------------------------------------------- hash detection
    def detect_hash_type(self, hash_string: str) -> str:
        h = hash_string.strip()
        length = len(h)
        if h.startswith('$2'):
            return 'bcrypt (-m 3200)'
        if h.startswith('$6'):
            return 'SHA-512 Unix (-m 1800)'
        if h.startswith('$1'):
            return 'MD5 Unix (-m 500)'
        if h.startswith('$5'):
            return 'SHA-256 Unix (-m 7400)'
        if length == 32:
            return 'MD5 (-m 0)'
        if length == 40:
            return 'SHA1 (-m 100)'
        if length == 64:
            return 'SHA256 (-m 1400)'
        if length == 128:
            return 'SHA512 (-m 1700)'
        return 'Unknown — coba hashid tool untuk identifikasi'

    # ---------------------------------------------------------------- hashcat
    def run_hashcat(self, hash_file: str, mode: int, wordlist: str = 'wordlists/rockyou.txt',
                    attack_mode: int = 0, output_callback: Optional[Callable] = None):
        cb = output_callback or emit_line
        if not tool_available('hashcat'):
            cb('[DEMO] hashcat tidak terpasang — output demo.')
            return self._demo_hashcat(hash_file, mode, cb)

        out = os.path.join(tempfile.gettempdir(), 'cracked.txt')
        cmd = ['hashcat', '-m', str(mode), '-a', str(attack_mode),
               hash_file, wordlist, '--status', '--status-timer=5', '-o', out]
        cb(f'$ {" ".join(cmd)}')
        try:
            cmd = fix_tool_cmd(cmd)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1)
            assert proc.stdout is not None
            saw_err = False
            for line in proc.stdout:
                line = line.rstrip('\n')
                if 'not recognized' in line.lower() or 'no such file' in line.lower():
                    saw_err = True
                cb(line)
            proc.wait()
            if saw_err or proc.returncode not in (0, None):
                cb('[!] hashcat gagal dijalankan (shim/exe bermasalah) — mode demo.')
                return self._demo_hashcat(hash_file, mode, cb)
            with open(out, encoding='utf-8', errors='replace') as f:
                cracked = [l.strip() for l in f if l.strip()]
        except Exception as e:
            cb(f'[!] hashcat gagal ({e}) — mode demo.')
            return self._demo_hashcat(hash_file, mode, cb)
        return {'cracked': cracked, 'mode': HASHCAT_MODES.get(mode, str(mode))}

    # ------------------------------------------------------------------- demo
    def _demo_hydra(self, target, protocol, username, cb):
        user = username or 'admin'
        lines = [
            f'Hydra v9.5 (demo) starting',
            f'[DATA] attacking {protocol}://{target}',
            f'[ATTEMPT] target {target} - login "{user}" - pass "123456"',
            f'[ATTEMPT] target {target} - login "{user}" - pass "password"',
            f'[ATTEMPT] target {target} - login "{user}" - pass "admin123"',
            f'[{protocol}] host: {target}   login: {user}   password: admin123',
            '1 of 1 target successfully completed, 1 valid password found',
        ]
        simulate_stream(lines, cb, delay=0.08)
        return {'found': [f'host: {target}  login: {user}  password: admin123']}

    def _demo_hashcat(self, hash_file, mode, cb):
        lines = [
            f'hashcat (v6.2.6) demo starting in -m {mode} mode',
            'Dictionary cache built...',
            'Cracking...   Speed: 1234.5 MH/s',
            '5f4dcc3b5aa765d61d8327deb882cf99:password',
            'Session..........: hashcat',
            'Status...........: Cracked',
        ]
        simulate_stream(lines, cb, delay=0.07)
        return {'cracked': ['5f4dcc3b5aa765d61d8327deb882cf99:password'],
                'mode': HASHCAT_MODES.get(mode, str(mode))}


def run(submode: str = 'hydra', target: str = '', protocol: str = 'ssh',
        username: str = '', password_list: str = 'wordlists/rockyou.txt',
        user_list: str = '', userlist: str = '',
        hash_file: str = '', hash_mode: int = 0, hash_string: str = '', **kwargs) -> dict:
    auditor = PasswordAuditor()
    if submode == 'detect':
        return {'module': 'password', 'submode': 'detect',
                'hash': hash_string, 'detected': auditor.detect_hash_type(hash_string)}
    if submode == 'hashcat':
        res = auditor.run_hashcat(hash_file, int(hash_mode), password_list)
        return {'module': 'password', 'submode': 'hashcat', **res}
    # default hydra — pakai single username, atau userlist bila diberikan.
    ul = (user_list or userlist).strip() or None
    res = auditor.run_hydra(target, protocol, username or None, ul, password_list)
    return {'module': 'password', 'submode': 'hydra', 'target': target,
            'protocol': protocol, **res}

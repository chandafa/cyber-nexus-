# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/firewall_advisor.py
"""Modul Firewall Auto-Rule Suggestion — SDD v2 §5.19.1.
Mengusulkan rule firewall untuk menutup port tidak penting. Tidak menerapkan
perubahan tanpa konfirmasi eksplisit (dry-run default)."""
import platform
from typing import List, Dict, Optional, Callable

from core.stream_handler import emit_line

DEFAULT_ESSENTIAL = {22, 80, 443}


class FirewallAdvisor:
    def suggest_rules(self, open_ports: List[dict], essential: set = None) -> List[Dict]:
        essential = essential or DEFAULT_ESSENTIAL
        out = []
        for p in open_ports:
            port = int(p.get('port'))
            proto = p.get('protocol', 'tcp')
            if port in essential:
                continue
            out.append({
                'port': port, 'protocol': proto,
                'service': p.get('service', 'unknown'), 'action': 'block',
                'ufw_command': f'ufw deny {port}/{proto}',
                'iptables_command': f'iptables -A INPUT -p {proto} --dport {port} -j DROP',
                'netsh_command': f'netsh advfirewall firewall add rule name="Block {port}" '
                                 f'dir=in action=block protocol={proto.upper()} localport={port}',
                'reasoning': f'Port {port} ({p.get("service","unknown")}) bukan essential & terbuka',
            })
        return out

    def apply_rule(self, command: str, confirmed: bool = False) -> str:
        if not confirmed:
            return f'DRY RUN — perintah belum dijalankan: {command}'
        import subprocess
        try:
            r = subprocess.run(command.split(), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
            return (r.stdout + r.stderr).strip()
        except Exception as e:
            return f'ERROR: {e}'


def run(ports: str = '', essential: str = '22,80,443', **kwargs) -> dict:
    import json
    cb = emit_line
    try:
        port_list = json.loads(ports) if ports else []
    except Exception:
        port_list = []
    if not port_list:
        from core.subprocess_runner import demo_disabled
        if demo_disabled():
            pm = 'netsh' if platform.system() == 'Windows' else 'ufw'
            cb('[REAL] Tidak ada data port dari scan — jalankan port scan dulu. '
               'Mode eksekusi nyata: contoh palsu tidak ditampilkan.')
            return {'module': 'firewall', 'platform': platform.system(),
                    'preferred': pm, 'suggestions': [], 'total': 0}
        cb('[DEMO] Tidak ada data port — memakai contoh hasil port scan.')
        port_list = [{'port': 22, 'protocol': 'tcp', 'service': 'ssh'},
                     {'port': 23, 'protocol': 'tcp', 'service': 'telnet'},
                     {'port': 445, 'protocol': 'tcp', 'service': 'microsoft-ds'},
                     {'port': 3306, 'protocol': 'tcp', 'service': 'mysql'},
                     {'port': 3389, 'protocol': 'tcp', 'service': 'ms-wbt-server'}]
    ess = {int(x) for x in essential.split(',') if x.strip().isdigit()}
    suggestions = FirewallAdvisor().suggest_rules(port_list, ess)
    pm = 'netsh' if platform.system() == 'Windows' else 'ufw'
    for s in suggestions:
        cb(f'[SUGGEST] block {s["port"]}/{s["protocol"]} ({s["service"]})')
    return {'module': 'firewall', 'platform': platform.system(), 'preferred': pm,
            'suggestions': suggestions, 'total': len(suggestions)}

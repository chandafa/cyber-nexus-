# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/ids_monitor.py
"""Modul Lightweight IDS — SDD v2 §5.19.3. Suricata (pasif) + demo."""
import subprocess
import json
import os
import time
import tempfile
from typing import Callable, Optional

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line


class IdsMonitor:
    def __init__(self):
        self.process = None
        self._running = False

    def start(self, interface: str, duration: int = 20,
              output_callback: Optional[Callable] = None) -> list:
        cb = output_callback or emit_line
        if not tool_available('suricata'):
            cb('[DEMO] suricata tidak terpasang — IDS demo (alert simulasi).')
            return self._demo(cb)
        logdir = os.path.join(tempfile.gettempdir(), 'nexus_suricata')
        os.makedirs(logdir, exist_ok=True)
        cmd = ['suricata', '-i', interface, '-l', logdir, '--af-packet']
        cb(f'$ {" ".join(cmd)}')
        alerts = []
        try:
            cmd = fix_tool_cmd(cmd)
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            eve = os.path.join(logdir, 'eve.json')
            start = time.time()
            while time.time() - start < duration:
                if os.path.exists(eve):
                    with open(eve, encoding='utf-8', errors='replace') as f:
                        for line in f:
                            try:
                                ev = json.loads(line)
                                if ev.get('event_type') == 'alert':
                                    a = {'signature': ev['alert']['signature'],
                                         'severity': ev['alert'].get('severity', 3),
                                         'src_ip': ev.get('src_ip'), 'dest_ip': ev.get('dest_ip'),
                                         'timestamp': ev.get('timestamp')}
                                    alerts.append(a)
                                    cb(f'[ALERT] {a["signature"]} {a["src_ip"]} -> {a["dest_ip"]}')
                            except json.JSONDecodeError:
                                continue
                time.sleep(1)
            self.stop()
        except Exception as e:
            cb(f'[ERROR] {e} — beralih ke demo.')
            return self._demo(cb)
        return alerts if alerts else self._demo(cb)

    def stop(self):
        self._running = False
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def _demo(self, cb: Callable) -> list:
        demo = [
            {'signature': 'ET SCAN Nmap Scripting Engine User-Agent', 'severity': 2,
             'src_ip': '203.0.113.9', 'dest_ip': '192.168.1.10', 'timestamp': '2025-01-14T10:22:01'},
            {'signature': 'ET POLICY Outbound SSH Connection', 'severity': 3,
             'src_ip': '192.168.1.55', 'dest_ip': '198.51.100.4', 'timestamp': '2025-01-14T10:23:11'},
            {'signature': 'ET WEB_SERVER SQL Injection Attempt', 'severity': 1,
             'src_ip': '192.168.1.66', 'dest_ip': '192.168.1.10', 'timestamp': '2025-01-14T10:24:30'},
            {'signature': 'ET TROJAN Possible Cobalt Strike Beacon', 'severity': 1,
             'src_ip': '192.168.1.77', 'dest_ip': '203.0.113.200', 'timestamp': '2025-01-14T10:25:45'},
        ]
        lines = [f'[ALERT] (sev {a["severity"]}) {a["signature"]} {a["src_ip"]} -> {a["dest_ip"]}'
                 for a in demo]
        simulate_stream(['$ suricata -i <iface> (demo IDS)'] + lines, cb, delay=0.08)
        return demo


def run(interface: str = 'eth0', duration: int = 15, **kwargs) -> dict:
    alerts = IdsMonitor().start(interface, int(duration))
    high = sum(1 for a in alerts if a.get('severity', 3) <= 2)
    return {'module': 'ids', 'interface': interface, 'alerts': alerts,
            'high_severity': high, 'total': len(alerts)}

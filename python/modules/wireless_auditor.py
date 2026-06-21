# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/wireless_auditor.py
"""Modul Wireless Auditor — SDD v2 §5.11. aircrack-ng + demo.
Auto-hide di UI jika tool/adapter tidak ada."""
import subprocess
import csv
import os
import platform
import tempfile
from typing import Callable, List, Optional

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line


class WirelessAuditor:
    def detect_monitor_capable(self) -> List[str]:
        """Interface WiFi yang support monitor mode (Linux iwconfig)."""
        if platform.system() != 'Linux' or not tool_available('iwconfig'):
            return []
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
            return [line.split()[0] for line in result.stdout.split('\n')
                    if 'IEEE 802.11' in line]
        except Exception:
            return []

    def available(self) -> bool:
        return tool_available('aircrack-ng') and bool(self.detect_monitor_capable())

    def scan_networks(self, interface: str, duration: int = 15,
                      output_callback: Optional[Callable] = None) -> List[dict]:
        cb = output_callback or emit_line
        if not (tool_available('airodump-ng') and self.detect_monitor_capable()):
            cb('[DEMO] aircrack-ng/adapter monitor mode tidak tersedia — scan WiFi demo.')
            return self._demo(cb)
        try:
            subprocess.run(['airmon-ng', 'start', interface], capture_output=True)
            mon = f'{interface}mon'
            out = os.path.join(tempfile.gettempdir(), 'nexus_scan')
            cmd = ['airodump-ng', '--write', out, '--output-format', 'csv', mon]
            cb(f'$ {" ".join(cmd)}')
            cmd = fix_tool_cmd(cmd)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            try:
                proc.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                proc.terminate()
            return self._parse_csv(out + '-01.csv')
        except Exception as e:
            cb(f'[ERROR] {e}')
            return []

    def _parse_csv(self, path: str) -> List[dict]:
        nets = []
        if not os.path.exists(path):
            return nets
        with open(path, errors='ignore') as f:
            for row in csv.reader(f):
                if len(row) > 13 and row[0].strip() and ':' in row[0]:
                    enc = row[5].strip()
                    nets.append({'bssid': row[0].strip(), 'channel': row[3].strip(),
                                 'encryption': enc, 'cipher': row[6].strip(),
                                 'essid': row[13].strip(),
                                 'assessment': self.assess_encryption(enc)})
        return nets

    def assess_encryption(self, encryption: str) -> dict:
        e = encryption.upper()
        if 'WEP' in e:
            return {'rating': 'critical', 'note': 'WEP sangat lemah, dapat di-crack dalam menit'}
        if 'TKIP' in e:
            return {'rating': 'warning', 'note': 'WPA-TKIP deprecated, upgrade ke WPA2/3-AES'}
        if 'WPA3' in e:
            return {'rating': 'ok', 'note': 'WPA3 — standar terkini'}
        if 'WPA2' in e:
            return {'rating': 'ok', 'note': 'WPA2-AES — aman jika password kuat'}
        if 'WPA' in e:
            return {'rating': 'warning', 'note': 'WPA (lama), upgrade ke WPA2/3'}
        return {'rating': 'critical', 'note': 'Tanpa enkripsi (Open Network)'}

    def _demo(self, cb: Callable) -> List[dict]:
        demo = [
            ('AA:BB:CC:11:22:33', '6', 'WPA2', 'CCMP', 'HomeWiFi-5G'),
            ('AA:BB:CC:44:55:66', '11', 'WPA3', 'CCMP', 'Office-Secure'),
            ('AA:BB:CC:77:88:99', '1', 'WEP', 'WEP', 'OldRouter'),
            ('AA:BB:CC:AA:BB:CC', '3', 'OPN', '', 'FreeWiFi-Guest'),
            ('AA:BB:CC:DD:EE:FF', '9', 'WPA', 'TKIP', 'Legacy-AP'),
        ]
        lines = ['$ airodump-ng wlan0mon (demo)',
                 'BSSID              CH  ENC   CIPHER  ESSID']
        nets = []
        for bssid, ch, enc, cipher, essid in demo:
            lines.append(f'{bssid}  {ch:>2}  {enc:<5} {cipher:<6} {essid}')
            nets.append({'bssid': bssid, 'channel': ch, 'encryption': enc,
                         'cipher': cipher, 'essid': essid,
                         'assessment': self.assess_encryption(enc)})
        simulate_stream(lines, cb, delay=0.06)
        return nets


def run(interface: str = 'wlan0', duration: int = 12, **kwargs) -> dict:
    auditor = WirelessAuditor()
    nets = auditor.scan_networks(interface, int(duration))
    weak = sum(1 for n in nets if n['assessment']['rating'] == 'critical')
    return {'module': 'wireless', 'interface': interface, 'networks': nets,
            'weak_count': weak, 'total': len(nets)}

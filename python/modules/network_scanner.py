# nexus/python/modules/network_scanner.py
"""
Modul Network Scanner (tshark) — SDD bagian 5.1.
Live packet capture, filter protokol, deteksi interface, export pcap,
statistik real-time, dengan demo fallback bila tshark tidak terpasang.
"""
import subprocess
import threading
import queue
import random
from typing import Callable, Optional, List

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line


class NetworkScanner:
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.output_queue: "queue.Queue" = queue.Queue()
        self._running = False
        self.stats = {'packets': 0, 'bytes': 0, 'talkers': {}}

    # ------------------------------------------------------------- interfaces
    def get_interfaces(self) -> List[str]:
        """Daftar interface jaringan yang tersedia."""
        if not tool_available('tshark'):
            return [
                '1. \\Device\\NPF_{DEMO-ETH0} (Ethernet - demo)',
                '2. \\Device\\NPF_{DEMO-WLAN} (Wi-Fi - demo)',
                '3. \\Device\\NPF_Loopback (Adapter for loopback - demo)',
            ]
        try:
            result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
            lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
            # Dahulukan NIC nyata (NPF/\Device\) sebelum pseudo-interface (etwdump, dll).
            real = [l for l in lines if ('\\device\\' in l.lower() or 'npf' in l.lower())]
            pseudo = [l for l in lines if l not in real]
            ordered = real + pseudo
            return ordered or ['(tidak ada interface — Npcap mungkin belum terpasang)']
        except Exception:
            return ['(gagal mendeteksi interface)']

    # ---------------------------------------------------------------- capture
    def start_capture(
        self,
        interface: str,
        filter_expr: str = '',
        output_callback: Optional[Callable[[str], None]] = None,
        pcap_file: Optional[str] = None,
        packet_limit: int = 0,
    ):
        cb = output_callback or emit_line
        self.stats = {'packets': 0, 'bytes': 0, 'talkers': {}}

        if not tool_available('tshark'):
            cb('[DEMO] tshark tidak terpasang — capture demo dijalankan.')
            return self._demo_capture(cb, packet_limit or 40)

        # Pseudo-interface extcap (etwdump, sshdump, dll) bukan NIC nyata.
        pseudo = ('etwdump', 'sshdump', 'ciscodump', 'randpktdump', 'udpdump',
                  'wifidump', 'dpauxmon', 'sdjournal')
        if any(p in interface.lower() for p in pseudo):
            cb(f'[!] "{interface.strip()}" adalah pseudo-interface (bukan NIC nyata) '
               f'— beralih ke mode demo.')
            return self._demo_capture(cb, packet_limit or 40)

        # interface "1. \Device\..." -> ambil token pertama (angka/nama)
        iface = interface.split('.')[0].strip() if interface[:1].isdigit() else interface
        cmd = ['tshark', '-i', iface,
               '-T', 'fields',
               '-e', 'frame.number', '-e', 'frame.time_relative',
               '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ip.proto',
               '-e', '_ws.col.Protocol', '-e', 'frame.len',
               '-e', 'tcp.srcport', '-e', 'tcp.dstport',
               '-E', 'header=y', '-E', 'separator=|']
        if filter_expr:
            cmd += ['-f', filter_expr]
        if pcap_file:
            cmd += ['-w', pcap_file]
        if packet_limit:
            cmd += ['-c', str(packet_limit)]

        cb(f'$ {" ".join(cmd)}')
        cmd = fix_tool_cmd(cmd)
        self._running = True
        error_detected = False
        err_sigs = ("npf driver isn't running", 'npcap', 'extcap', 'error',
                    "doesn't exist", 'permission denied', "couldn't run", 'no such',
                    'you may have trouble', 'are you a member', 'failed to set',
                    'capture isn', 'no interfaces')
        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1
            )
            assert self.process.stdout is not None
            for line in self.process.stdout:
                if not self._running:
                    break
                line = line.rstrip('\n')
                low = line.lower()
                if any(s in low for s in err_sigs):
                    error_detected = True
                self._update_stats(line)
                cb(line)
            self.process.wait()
        except Exception as e:
            cb(f'[ERROR] {e}')
            error_detected = True

        # Gagal runtime (driver/izin/interface) atau tidak ada paket -> demo.
        if error_detected or self.stats['packets'] == 0:
            cb('[!] Capture nyata gagal / 0 paket (Npcap belum jalan, butuh admin, '
               'atau interface salah). Beralih ke mode demo agar modul tetap bisa dipakai.')
            return self._demo_capture(cb, packet_limit or 40)

    def _update_stats(self, line: str):
        parts = line.split('|')
        if len(parts) >= 7 and parts[0].strip().isdigit():
            self.stats['packets'] += 1
            try:
                self.stats['bytes'] += int(parts[6])
            except (ValueError, IndexError):
                pass
            src = parts[2].strip()
            if src:
                self.stats['talkers'][src] = self.stats['talkers'].get(src, 0) + 1

    def stop_capture(self):
        self._running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except Exception:
                self.process.kill()

    # ------------------------------------------------------------------- demo
    def _demo_capture(self, cb: Callable, count: int):
        self._running = True
        self.stats = {'packets': 0, 'bytes': 0, 'talkers': {}}  # reset agar bersih
        protos = ['TCP', 'UDP', 'HTTP', 'TLSv1.3', 'DNS', 'ARP', 'ICMP']
        hosts = ['192.168.1.10', '192.168.1.1', '192.168.1.55', '8.8.8.8',
                 '142.250.4.100', '93.184.216.34']
        header = ('frame.number|frame.time_relative|ip.src|ip.dst|ip.proto|'
                  '_ws.col.Protocol|frame.len|tcp.srcport|tcp.dstport')
        cb(header)
        lines = []
        t = 0.0
        rnd = random.Random(1337)
        for i in range(1, count + 1):
            t += rnd.uniform(0.001, 0.05)
            src = rnd.choice(hosts)
            dst = rnd.choice([h for h in hosts if h != src])
            proto = rnd.choice(protos)
            length = rnd.randint(54, 1480)
            sport = rnd.randint(1024, 65535)
            dport = rnd.choice([80, 443, 53, 22, 3389, 8080])
            row = f'{i}|{t:.6f}|{src}|{dst}|6|{proto}|{length}|{sport}|{dport}'
            lines.append(row)
            self._update_stats(row)
        simulate_stream(lines, cb, delay=0.06)
        cb(f'[DEMO] {count} paket ditangkap (simulasi).')

    def get_stats(self) -> dict:
        top = sorted(self.stats['talkers'].items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            'packets': self.stats['packets'],
            'bytes': self.stats['bytes'],
            'top_talkers': [{'ip': ip, 'count': c} for ip, c in top],
        }


def run(interface: str = '1', filter: str = '', pcap_file: str = '',
        packet_limit: int = 40, **kwargs) -> dict:
    scanner = NetworkScanner()
    scanner.start_capture(interface, filter, emit_line, pcap_file or None, int(packet_limit))
    stats = scanner.get_stats()
    return {'module': 'network', 'interface': interface, 'filter': filter, **stats}


def list_interfaces() -> dict:
    return {'interfaces': NetworkScanner().get_interfaces()}

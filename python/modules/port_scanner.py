# nexus/python/modules/port_scanner.py
"""
Modul Port Scanner (Nmap) — SDD bagian 5.2.
Mendukung mode scan quick/standard/os/full/vuln/stealth/udp, parsing XML,
dan demo fallback bila nmap tidak terpasang.
"""
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict, field
from typing import List, Callable, Optional
import tempfile
import os

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    version: str
    extra_info: str = ''


@dataclass
class ScanResult:
    target: str
    hostname: str
    status: str
    os_guess: str
    ports: List[PortResult] = field(default_factory=list)
    raw_xml: str = ''

    def to_dict(self):
        d = asdict(self)
        d['raw_xml'] = ''  # jangan kirim XML besar ke UI
        return d


class PortScanner:
    SCAN_MODES = {
        'quick':    ['-T4', '-F'],
        'standard': ['-sV', '-sC'],
        'os':       ['-O', '-sV'],
        'full':     ['-p-', '-sV', '-O', '--script=default'],
        'vuln':     ['-sV', '--script=vuln'],
        'stealth':  ['-sS', '-T2'],
        'udp':      ['-sU', '-p', '53,67,69,161,500,514'],
    }

    def scan(
        self,
        target: str,
        mode: str = 'standard',
        extra_args: Optional[list] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ScanResult:
        cb = progress_callback or emit_line

        if not tool_available('nmap'):
            cb('[DEMO] nmap tidak terpasang — menjalankan mode demo.')
            return self._demo_scan(target, mode, cb)

        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
            xml_path = f.name

        cmd = ['nmap', '--open'] + self.SCAN_MODES.get(mode, ['-sV'])
        if extra_args:
            cmd += extra_args
        cmd += ['-oX', xml_path, target]

        cb(f'$ {" ".join(cmd)}')
        cmd = fix_tool_cmd(cmd)
        error_detected = False
        err_sigs = ('requires root privileges', 'requires administrator', 'quitting',
                    'failed to', 'permission denied', 'dnet:', 'couldn\'t open',
                    'socket troubles', 'operation not permitted')
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                line = line.rstrip('\n')
                if any(s in line.lower() for s in err_sigs):
                    error_detected = True
                cb(line)
            process.wait()
            if error_detected:
                cb('[!] nmap gagal (butuh hak admin untuk mode ini, mis. -O/-sS). '
                   'Beralih ke mode demo.')
                result = self._demo_scan(target, mode, cb)
            else:
                result = self._parse_xml(xml_path, target)
        except Exception as e:
            cb(f'[ERROR] {e} — beralih ke mode demo.')
            result = self._demo_scan(target, mode, cb)
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass
        return result

    def _parse_xml(self, xml_path: str, target: str) -> ScanResult:
        try:
            with open(xml_path) as f:
                raw = f.read()
            tree = ET.parse(xml_path)
        except Exception:
            return ScanResult(target, '', 'down', 'Unknown')

        root = tree.getroot()
        host = root.find('host')
        if host is None:
            return ScanResult(target, '', 'down', 'Unknown', [], raw)

        hostname_el = host.find('.//hostname')
        hostname = hostname_el.get('name', '') if hostname_el is not None else ''
        status_el = host.find('status')
        status = status_el.get('state', 'unknown') if status_el is not None else 'unknown'
        os_el = host.find('.//osmatch')
        os_guess = os_el.get('name', 'Unknown') if os_el is not None else 'Unknown'

        ports = []
        for port_el in host.findall('.//port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            svc = port_el.find('service')
            ports.append(PortResult(
                port=int(port_el.get('portid')),
                protocol=port_el.get('protocol', 'tcp'),
                state='open',
                service=svc.get('name', '') if svc is not None else '',
                version=(f"{svc.get('product','')} {svc.get('version','')}".strip()
                         if svc is not None else ''),
                extra_info=svc.get('extrainfo', '') if svc is not None else '',
            ))
        return ScanResult(target, hostname, status, os_guess, ports, raw)

    # ---------------------------------------------------------------- demo
    def _demo_scan(self, target: str, mode: str, cb: Callable) -> ScanResult:
        demo_ports = [
            PortResult(22, 'tcp', 'open', 'ssh', 'OpenSSH 8.9p1 Ubuntu', 'protocol 2.0'),
            PortResult(80, 'tcp', 'open', 'http', 'nginx 1.18.0', ''),
            PortResult(443, 'tcp', 'open', 'https', 'nginx 1.18.0', 'TLSv1.3'),
            PortResult(3306, 'tcp', 'open', 'mysql', 'MySQL 8.0.34', ''),
            PortResult(8080, 'tcp', 'open', 'http-proxy', 'Apache Tomcat 9.0.71', ''),
        ]
        lines = [
            f'$ nmap --open {" ".join(self.SCAN_MODES.get(mode, ["-sV"]))} {target}',
            'Starting Nmap 7.94 ( https://nmap.org )',
            f'Nmap scan report for {target}',
            'Host is up (0.012s latency).',
            'Not shown: 995 closed tcp ports (reset)',
            'PORT     STATE SERVICE      VERSION',
        ]
        for p in demo_ports:
            lines.append(f'{p.port}/{p.protocol:<3} {p.state}  {p.service:<12} {p.version}')
        lines += [
            'OS details: Linux 5.15 - 6.2 (demo guess)',
            'Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds',
        ]
        simulate_stream(lines, cb, delay=0.05)
        return ScanResult(target, 'demo-host.local', 'up', 'Linux 5.15 (demo)', demo_ports, '')


def run(target: str, mode: str = 'standard', **kwargs) -> dict:
    """Entry point dipanggil runner.py. Kembalikan dict hasil."""
    scanner = PortScanner()
    result = scanner.scan(target, mode)
    return {
        'module': 'port',
        'target': target,
        'mode': mode,
        'hostname': result.hostname,
        'status': result.status,
        'os_guess': result.os_guess,
        'ports': [asdict(p) for p in result.ports],
    }

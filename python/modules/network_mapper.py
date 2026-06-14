# nexus/python/modules/network_mapper.py
"""
Modul Network Mapper — SDD modul #6.
Membangun topologi jaringan dari hasil host discovery nmap, menghasilkan
graph nodes/edges untuk divisualisasikan dengan Cytoscape.js di frontend.
Demo fallback bila nmap tidak terpasang.
"""
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
import random
from typing import Callable, Optional

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line


class NetworkMapper:
    def discover(self, target: str, output_callback: Optional[Callable] = None) -> dict:
        cb = output_callback or emit_line
        if not tool_available('nmap'):
            cb('[DEMO] nmap tidak terpasang — topologi demo dibuat.')
            return self._demo_topology(target, cb)

        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
            xml_path = f.name
        cmd = ['nmap', '-sn', '-oX', xml_path, target]  # ping sweep
        cb(f'$ {" ".join(cmd)}')
        try:
            cmd = fix_tool_cmd(cmd)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                cb(line.rstrip('\n'))
            proc.wait()
            graph = self._parse(xml_path, target)
        except Exception as e:
            cb(f'[ERROR] {e}')
            graph = {'nodes': [], 'edges': []}
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass
        return graph

    def _parse(self, xml_path: str, target: str) -> dict:
        nodes = [{'id': 'gateway', 'label': 'Gateway', 'type': 'router'}]
        edges = []
        try:
            tree = ET.parse(xml_path)
            for host in tree.getroot().findall('host'):
                if host.find('status') is None or host.find('status').get('state') != 'up':
                    continue
                addr_el = host.find("address[@addrtype='ipv4']")
                ip = addr_el.get('addr') if addr_el is not None else 'unknown'
                hn_el = host.find('.//hostname')
                label = hn_el.get('name') if hn_el is not None else ip
                nodes.append({'id': ip, 'label': label, 'type': 'host', 'ip': ip})
                edges.append({'source': 'gateway', 'target': ip})
        except Exception:
            pass
        return {'nodes': nodes, 'edges': edges, 'target': target}

    def _demo_topology(self, target: str, cb: Callable) -> dict:
        rnd = random.Random(99)
        base = '192.168.1.'
        nodes = [{'id': 'gateway', 'label': 'Gateway 192.168.1.1', 'type': 'router'}]
        edges = []
        roles = ['workstation', 'server', 'printer', 'iot', 'phone']
        lines = [f'$ nmap -sn {target} (demo)', 'Starting Nmap ping sweep...']
        for i in range(2, 12):
            ip = base + str(i + rnd.randint(0, 3))
            role = rnd.choice(roles)
            nodes.append({'id': ip, 'label': f'{ip}', 'type': 'host', 'ip': ip, 'role': role})
            edges.append({'source': 'gateway', 'target': ip})
            lines.append(f'Nmap scan report for {ip}  -> host up ({role})')
        lines.append(f'[DEMO] {len(nodes)-1} host ditemukan.')
        simulate_stream(lines, cb, delay=0.05)
        return {'nodes': nodes, 'edges': edges, 'target': target}


def run(target: str, **kwargs) -> dict:
    mapper = NetworkMapper()
    graph = mapper.discover(target)
    return {'module': 'mapper', 'target': target,
            'nodes': graph['nodes'], 'edges': graph['edges'],
            'host_count': len([n for n in graph['nodes'] if n.get('type') == 'host'])}

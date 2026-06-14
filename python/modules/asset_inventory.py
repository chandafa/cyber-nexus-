# nexus/python/modules/asset_inventory.py
"""Modul Asset Inventory — SDD v2 §5.14.
Mengagregasi host dari hasil Port/Network/Mapper scan ke tabel `assets`."""
import sqlite3
from datetime import datetime
from typing import List, Optional

from core.dbpath import db_path
from core.stream_handler import emit_line


class AssetInventory:
    def __init__(self, path: str = None):
        self.db_path = path or db_path()

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def upsert_asset(self, ip: str, mac: Optional[str], hostname: str,
                     os_guess: str, open_ports: List[int]):
        conn = self._conn()
        cur = conn.cursor()
        now = datetime.now().isoformat(timespec='seconds')
        cur.execute('SELECT id FROM assets WHERE ip_address = ? OR (mac_address IS NOT NULL AND mac_address = ?)',
                    (ip, mac))
        row = cur.fetchone()
        ports_str = ','.join(map(str, sorted(set(open_ports))))
        if row:
            cur.execute('''UPDATE assets SET last_seen=?, hostname=?, os_guess=?, open_ports=?
                           WHERE id=?''', (now, hostname, os_guess, ports_str, row[0]))
        else:
            cur.execute('''INSERT INTO assets
                (ip_address, mac_address, hostname, os_guess, open_ports, device_type,
                 first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)''',
                (ip, mac, hostname, os_guess, ports_str,
                 self._classify(open_ports, os_guess), now, now))
        conn.commit()
        conn.close()

    def _classify(self, ports: List[int], os_guess: str) -> str:
        ps = set(ports)
        og = (os_guess or '').lower()
        if 53 in ps or (80 in ps and 23 in ps):
            return 'router'
        if 'windows' in og and (3389 in ps or 445 in ps):
            return 'workstation (windows)'
        if 22 in ps and (80 in ps or 443 in ps):
            return 'server'
        if len(ps) <= 2 and (80 in ps or 8080 in ps):
            return 'iot device'
        return 'unknown'

    def rebuild_from_scans(self, cb=None) -> int:
        """Bangun ulang inventaris dari port_results yang tersimpan."""
        cb = cb or emit_line
        conn = self._conn()
        cur = conn.cursor()
        try:
            cur.execute('''SELECT target_ip, hostname, os_guess, port FROM port_results''')
            rows = cur.fetchall()
        except Exception as e:
            cb(f'[ERROR] {e}')
            conn.close()
            return 0
        conn.close()
        hosts = {}
        for ip, hostname, os_guess, port in rows:
            if not ip:
                continue
            h = hosts.setdefault(ip, {'hostname': hostname or '', 'os': os_guess or '', 'ports': set()})
            if port:
                h['ports'].add(int(port))
            if hostname:
                h['hostname'] = hostname
            if os_guess:
                h['os'] = os_guess
        for ip, h in hosts.items():
            self.upsert_asset(ip, None, h['hostname'], h['os'], sorted(h['ports']))
            cb(f'[*] Asset: {ip} ({len(h["ports"])} port) -> {self._classify(list(h["ports"]), h["os"])}')
        cb(f'[*] Inventaris diperbarui: {len(hosts)} host.')
        return len(hosts)

    def list_assets(self) -> List[dict]:
        conn = self._conn()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            cur.execute('SELECT * FROM assets ORDER BY last_seen DESC')
            rows = [dict(r) for r in cur.fetchall()]
        except Exception:
            rows = []
        conn.close()
        # tandai 'baru' (first_seen == last_seen)
        for r in rows:
            r['is_new'] = (r.get('first_seen') == r.get('last_seen'))
        return rows


def run(submode: str = 'list', **kwargs) -> dict:
    inv = AssetInventory()
    if submode == 'rebuild':
        count = inv.rebuild_from_scans()
        return {'module': 'asset', 'submode': 'rebuild', 'rebuilt': count,
                'assets': inv.list_assets()}
    return {'module': 'asset', 'submode': 'list', 'assets': inv.list_assets()}

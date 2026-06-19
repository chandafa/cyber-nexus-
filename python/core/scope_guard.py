# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/scope_guard.py
"""Scope Guard — SDD v2 §5.9.3. Validasi target sebelum modul attack/simulation."""
import sqlite3
import ipaddress

from .dbpath import db_path


class ScopeError(PermissionError):
    pass


class ScopeGuard:
    def __init__(self, path: str = None):
        self.db_path = path or db_path()

    def is_target_authorized(self, target: str) -> bool:
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('SELECT cidr_or_host FROM authorized_targets WHERE active = 1')
            rows = cur.fetchall()
            conn.close()
        except Exception:
            return False
        for (entry,) in rows:
            entry = (entry or '').strip()
            try:
                if '/' in entry:
                    if ipaddress.ip_address(target) in ipaddress.ip_network(entry, strict=False):
                        return True
                elif entry == target:
                    return True
            except ValueError:
                if entry == target:
                    return True
        return False

    def require_authorization(self, target: str):
        if not self.is_target_authorized(target):
            raise ScopeError(
                f"Target '{target}' belum ditandai authorized. Tambahkan ke "
                f"'Authorized Targets' di Attack Simulation sebelum menjalankan modul ini."
            )

    # ----------------------------------------------------- manajemen target
    def list_targets(self) -> list:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute(
                'SELECT * FROM authorized_targets ORDER BY added_at DESC').fetchall()]
            conn.close()
            return rows
        except Exception:
            return []

    def add_target(self, cidr_or_host: str, label: str = ''):
        from datetime import datetime
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            'INSERT OR IGNORE INTO authorized_targets (cidr_or_host, label, active, added_at) '
            'VALUES (?,?,1,?)', (cidr_or_host.strip(), label, datetime.now().isoformat(timespec='seconds')))
        conn.commit()
        conn.close()

    def remove_target(self, target_id: int):
        conn = sqlite3.connect(self.db_path)
        conn.execute('DELETE FROM authorized_targets WHERE id=?', (target_id,))
        conn.commit()
        conn.close()


def run(submode: str = 'list', cidr_or_host: str = '', label: str = '',
        target_id: str = '', **kwargs) -> dict:
    g = ScopeGuard()
    if submode == 'add' and cidr_or_host:
        g.add_target(cidr_or_host, label)
    elif submode == 'remove' and target_id:
        g.remove_target(int(target_id))
    return {'module': 'scope', 'targets': g.list_targets()}

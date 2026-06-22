#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji core.scope_guard — gerbang target SAH (security-critical) sebelum modul
attack/simulation berjalan.

Memverifikasi keputusan in-scope vs out-of-scope: host eksak, CIDR (IPv4/IPv6),
wildcard tak valid, target rusak, dan upaya bypass. DB SQLite terisolasi dengan
tabel authorized_targets dibuat sendiri (mirror schema Rust).
"""
import os
import sys
import sqlite3
import tempfile

# Windows: paksa stdout UTF-8 agar karakter non-ASCII (panah, dsb.) tak crash cp1252.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)

# DB terisolasi: scope_guard memakai NEXUS_DB_PATH lewat core.dbpath bila path
# tak diberikan; kita beri path eksplisit ke ScopeGuard agar 100% terisolasi.
_tmp = tempfile.mkdtemp(prefix="nexus_scope_test_")
DB = os.path.join(_tmp, "nexus.db")
os.environ["NEXUS_DB_PATH"] = DB

from core.scope_guard import ScopeGuard, ScopeError  # noqa: E402

FAILED = []

# Skema authorized_targets (mirror src-tauri/src/db/schema.rs).
_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorized_targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr_or_host TEXT NOT NULL UNIQUE,
    label        TEXT,
    active       INTEGER DEFAULT 1,
    added_at     TEXT NOT NULL
);
"""


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def _fresh_db(entries):
    """Buat DB baru berisi `entries`: list (cidr_or_host, active)."""
    if os.path.exists(DB):
        os.remove(DB)
    c = sqlite3.connect(DB)
    c.executescript(_SCHEMA)
    for host, active in entries:
        c.execute("INSERT INTO authorized_targets(cidr_or_host,label,active,added_at) "
                  "VALUES(?,?,?,?)", (host, "test", active, "2026-01-01T00:00:00"))
    c.commit()
    c.close()
    return ScopeGuard(path=DB)


def main():
    print("== Host eksak: in-scope vs out-of-scope ==")
    g = _fresh_db([("192.168.1.50", 1), ("example.com", 1)])
    check("host eksak authorized → True", g.is_target_authorized("192.168.1.50"))
    check("hostname eksak authorized → True", g.is_target_authorized("example.com"))
    check("host tak terdaftar → False", not g.is_target_authorized("192.168.1.51"))
    check("hostname tak terdaftar → False", not g.is_target_authorized("evil.com"))

    print("== CIDR IPv4 ==")
    g = _fresh_db([("10.0.0.0/24", 1)])
    check("IP dalam CIDR /24 → True", g.is_target_authorized("10.0.0.99"))
    check("IP batas bawah jaringan → True", g.is_target_authorized("10.0.0.0"))
    check("IP batas atas (broadcast) → True", g.is_target_authorized("10.0.0.255"))
    check("IP di luar CIDR /24 → False", not g.is_target_authorized("10.0.1.1"))
    check("IP tetangga di luar → False", not g.is_target_authorized("10.0.2.50"))

    print("== CIDR /32 (host tunggal) ==")
    g = _fresh_db([("172.16.5.5/32", 1)])
    check("host /32 cocok eksak → True", g.is_target_authorized("172.16.5.5"))
    check("host /32 tetangga → False", not g.is_target_authorized("172.16.5.6"))

    print("== CIDR IPv6 ==")
    g = _fresh_db([("2001:db8::/32", 1)])
    check("IPv6 dalam CIDR → True", g.is_target_authorized("2001:db8::1"))
    check("IPv6 di luar CIDR → False", not g.is_target_authorized("2001:dead::1"))

    print("== Flag active: target nonaktif tak boleh ==")
    g = _fresh_db([("203.0.113.10", 0), ("203.0.113.20", 1)])
    check("target active=0 → False (di-skip query)", not g.is_target_authorized("203.0.113.10"))
    check("target active=1 → True", g.is_target_authorized("203.0.113.20"))

    print("== Upaya bypass / input rusak ==")
    g = _fresh_db([("10.0.0.0/24", 1), ("host.example", 1)])
    # String kosong tak boleh lolos.
    check("target kosong → False", not g.is_target_authorized(""))
    # IP malformed terhadap entri CIDR: ipaddress.ip_address gagal → tak match.
    check("IP rusak terhadap CIDR → False", not g.is_target_authorized("10.0.0.999"))
    check("teks acak terhadap CIDR → False", not g.is_target_authorized("notanip"))
    # Substring/awalan dari host SAH tak boleh dianggap match (perbandingan eksak).
    check("substring hostname bukan match", not g.is_target_authorized("host.example.evil.com"))
    # CATATAN PERILAKU: target yang PERSIS sama dengan string entri CIDR ("10.0.0.0/24")
    # akan cocok lewat fallback exact-string (ip_address gagal utk target ber-'/',
    # lalu entry==target). Bukan bypass — butuh string CIDR identik; modul attack
    # men-sanitasi target ke host/IP tunggal sebelum ini, jadi '/' tak akan lolos.
    check("string CIDR identik cocok lewat fallback exact-match (perilaku terkini)",
          g.is_target_authorized("10.0.0.0/24"))
    check("CIDR berbeda sebagai string literal bukan match",
          not g.is_target_authorized("10.0.0.0/16"))
    # Spasi di sekitar entri DB di-trim; query tetap eksak terhadap target.
    g2 = _fresh_db([("  192.168.9.9  ", 1)])
    check("entri DB dengan spasi → di-trim & cocok", g2.is_target_authorized("192.168.9.9"))

    print("== Entri CIDR rusak di DB tak meledak ==")
    g = _fresh_db([("garbage/notcidr", 1), ("198.51.100.7", 1)])
    check("entri CIDR rusak diabaikan, target valid lain tetap jalan",
          g.is_target_authorized("198.51.100.7"))
    check("target acak vs entri CIDR rusak → False (fail-closed)",
          not g.is_target_authorized("198.51.100.8"))

    print("== require_authorization mengangkat ScopeError ==")
    g = _fresh_db([("192.168.1.50", 1)])
    raised = False
    try:
        g.require_authorization("8.8.8.8")
    except ScopeError:
        raised = True
    check("require_authorization out-of-scope → ScopeError", raised)
    check("ScopeError adalah PermissionError", issubclass(ScopeError, PermissionError))
    # in-scope: tak mengangkat apa pun.
    ok = True
    try:
        g.require_authorization("192.168.1.50")
    except Exception:
        ok = False
    check("require_authorization in-scope → tak raise", ok)

    print("== Fail-closed bila tabel/DB tak ada ==")
    missing = ScopeGuard(path=os.path.join(_tmp, "does_not_exist.db"))
    check("DB hilang → is_target_authorized False (fail-closed)",
          not missing.is_target_authorized("192.168.1.50"))

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES SCOPE GUARD LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

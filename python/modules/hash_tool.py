# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/hash_tool.py
"""
Modul Hash Identifier & Cracker.

Dua submode:
  - identify : deteksi tipe hash berdasarkan panjang/charset/struktur
               (murni Python, nyata — tanpa data palsu).
  - crack    : serangan dictionary NYATA memakai hashlib di atas sebuah
               wordlist (md5/sha1/sha256/sha512/ntlm). Untuk tipe yang tidak
               didukung secara native, mengarahkan ke hashcat/john bila
               terpasang di sistem.

CATATAN PENGGUNAAN (AUTHORIZED USE ONLY):
  Modul ini hanya untuk audit keamanan yang SAH atas hash milik sendiri atau
  yang Anda punya izin tertulis untuk diuji. Penggunaan terhadap data pihak
  lain tanpa izin adalah ilegal. Tidak ada hasil yang difabrikasi: setiap
  plaintext yang dilaporkan benar-benar terverifikasi terhadap hash target.

Hanya memakai stdlib: hashlib, re, os.
"""
import os
import re
import hashlib
from typing import List, Dict

from core.stream_handler import emit_line
from core.subprocess_runner import tool_available  # noqa: F401  (dipakai di crack)


# ---------------------------------------------------------------- identify
# Tabel aturan identifikasi. Tiap kandidat berisi nama, mode hashcat (angka
# bila diketahui, '' bila tidak), dan format john (bila diketahui).
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


def _is_hex(s: str) -> bool:
    return bool(s) and bool(_HEX_RE.match(s))


def identify(h: str) -> List[Dict]:
    """Kembalikan daftar kandidat tipe hash untuk string `h`."""
    candidates: List[Dict] = []

    def add(name, hashcat_mode='', john_format=''):
        candidates.append({
            'name': name,
            'hashcat_mode': hashcat_mode,
            'john_format': john_format,
        })

    length = len(h)

    # --- pola berprefiks (struktur) lebih dulu, paling spesifik ---
    if re.match(r'^\$2[aby]\$', h):
        add('bcrypt', 3200, 'bcrypt')
        return candidates
    if h.startswith('$6$'):
        add('sha512crypt', 1800, 'sha512crypt')
        return candidates
    if h.startswith('$5$'):
        add('sha256crypt', 7400, 'sha256crypt')
        return candidates
    if h.startswith('$1$'):
        add('md5crypt', 500, 'md5crypt')
        return candidates

    # MySQL 4.1+ : diawali '*' diikuti 40 hex (total 41 char)
    if h.startswith('*') and len(h) == 41 and _is_hex(h[1:]):
        add('MySQL4.1', 300, 'mysql-sha1')
        return candidates

    # --- pola berbasis panjang + charset hex ---
    if _is_hex(h):
        if length == 8:
            add('CRC32', '', 'crc32')
        elif length == 16:
            add('MySQL323', 200, 'mysql')
            add('LM', 3000, 'LM')
        elif length == 32:
            add('MD5', 0, 'raw-md5')
            add('NTLM', 1000, 'NT')
            add('MD4', 900, 'raw-md4')
            add('LM', 3000, 'LM')
        elif length == 40:
            add('SHA1', 100, 'raw-sha1')
            add('MySQL4.1', 300, 'mysql-sha1')
        elif length == 56:
            add('SHA224', 1300, 'raw-sha224')
        elif length == 64:
            add('SHA256', 1400, 'raw-sha256')
        elif length == 96:
            add('SHA384', 10800, 'raw-sha384')
        elif length == 128:
            add('SHA512', 1700, 'raw-sha512')

    # --- terlihat seperti base64 (dan belum cocok hex apa pun) ---
    if not candidates and len(h) >= 8 and _BASE64_RE.match(h):
        add('base64-encoded (kemungkinan)', '', '')

    if not candidates:
        add('Tidak dikenali', '', '')

    return candidates


# ------------------------------------------------------------------- crack
_ALGO_BY_LEN = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}
_SUPPORTED = {'md5', 'sha1', 'sha256', 'sha512', 'ntlm'}
_MAX_LINES = 5_000_000


def _digest(algo: str, pw: str) -> str:
    """Hitung digest hex untuk satu password kandidat menurut algoritma."""
    if algo == 'ntlm':
        # NTLM = MD4 dari password yang di-encode UTF-16-LE.
        return hashlib.new('md4', pw.encode('utf-16-le')).hexdigest()
    return hashlib.new(algo, pw.encode('utf-8')).hexdigest()


def _algo_for(h: str, hashtype: str) -> str:
    """Tentukan algoritma untuk hash `h` sesuai `hashtype` ('auto' = dari panjang)."""
    if hashtype and hashtype != 'auto':
        return hashtype
    return _ALGO_BY_LEN.get(len(h), '')


def _parse_targets(hashes: str, single: str) -> List[str]:
    raw = hashes or single or ''
    parts = re.split(r'[,\n\r]+', raw)
    out = []
    for p in parts:
        p = p.strip().lower()
        if p:
            out.append(p)
    return out


def crack(hashes: str, single: str, wordlist: str, hashtype: str) -> dict:
    """Lakukan serangan dictionary nyata. Tidak pernah memfabrikasi hasil."""
    # Default wordlist yang masuk akal bila kosong.
    if not wordlist:
        for default in (os.path.join('wordlists', 'rockyou.txt'),
                        os.path.join('wordlists', 'rockyou_full.txt')):
            if os.path.exists(default):
                wordlist = default
                emit_line(f'[*] Memakai wordlist default: {default}')
                break

    if not wordlist or not os.path.isfile(wordlist):
        emit_line('[ERROR] wordlist tidak ditemukan')
        return {'module': 'hash_tool', 'submode': 'crack',
                'error': 'wordlist diperlukan', 'cracked': [], 'total': 0}

    targets = _parse_targets(hashes, single)
    if not targets:
        emit_line('[ERROR] tidak ada hash target')
        return {'module': 'hash_tool', 'submode': 'crack',
                'error': 'hash target diperlukan', 'cracked': [], 'total': 0}

    # Petakan tiap hash ke algoritmanya; peringatkan yang tak didukung.
    algo_map: Dict[str, str] = {}
    unsupported = []
    for h in targets:
        a = _algo_for(h, hashtype)
        if a in _SUPPORTED:
            algo_map[h] = a
        else:
            unsupported.append(h)

    if unsupported:
        emit_line(f'[!] {len(unsupported)} hash tidak didukung native (algoritma '
                  f'tak diketahui dari panjang/charset).')
        for tool in ('hashcat', 'john'):
            try:
                if tool_available(tool):
                    emit_line(f'[*] {tool} terpasang — gunakan {tool} untuk tipe ini '
                              f'(mis. hash dengan salt/format khusus).')
                    break
            except Exception:
                pass
        else:
            emit_line('[*] hashcat/john tidak terpasang — tipe tak didukung dilewati.')

    remaining = set(algo_map.keys())
    cracked: List[Dict] = []
    attempted = 0

    emit_line(f'[*] {len(remaining)} hash didukung, mulai dictionary attack '
              f'(wordlist: {wordlist})')

    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if not remaining:
                    break
                if attempted >= _MAX_LINES:
                    emit_line(f'[!] Batas {_MAX_LINES} baris tercapai — berhenti.')
                    break
                pw = line.rstrip('\r\n')
                attempted += 1

                # Cache digest per-algo agar hash ber-algo sama tak dihitung ulang.
                digest_cache: Dict[str, str] = {}
                for h in list(remaining):
                    algo = algo_map[h]
                    d = digest_cache.get(algo)
                    if d is None:
                        d = _digest(algo, pw)
                        digest_cache[algo] = d
                    if d == h:
                        cracked.append({'hash': h, 'plaintext': pw, 'type': algo})
                        remaining.discard(h)
                        emit_line(f'[+] CRACKED {h} : {pw}')

                if attempted % 50000 == 0:
                    emit_line(f'[*] {attempted} percobaan... '
                              f'{len(cracked)} cracked, {len(remaining)} tersisa')
    except OSError as e:
        emit_line(f'[ERROR] gagal membaca wordlist: {e}')
        return {'module': 'hash_tool', 'submode': 'crack',
                'error': f'gagal membaca wordlist: {e}',
                'cracked': cracked, 'total': len(targets)}
    except Exception as e:  # pragma: no cover
        emit_line(f'[ERROR] kesalahan saat cracking: {e}')

    emit_line(f'[+] Selesai: {len(cracked)}/{len(targets)} cracked '
              f'dalam {attempted} percobaan')

    return {
        'module': 'hash_tool',
        'submode': 'crack',
        'cracked': cracked,
        'attempted': attempted,
        'total': len(targets),
        'remaining': len(targets) - len(cracked),
    }


# -------------------------------------------------------------------- entry
def run(submode: str = 'identify', hash: str = '', hashes: str = '',
        wordlist: str = '', hashtype: str = 'auto', **kwargs) -> dict:
    """Entry point publik. submode: 'identify' | 'crack'.

    AUTHORIZED USE ONLY — lihat docstring modul.
    """
    if submode == 'crack':
        return crack(hashes, hash, wordlist, hashtype)

    # default: identify
    h = (hash or '').strip()
    if not h:
        emit_line('[ERROR] hash kosong')
        return {'module': 'hash_tool', 'submode': 'identify',
                'error': 'hash diperlukan', 'input': '', 'length': 0,
                'candidates': []}

    candidates = identify(h)
    for c in candidates:
        mode = c['hashcat_mode']
        mode_s = f' (hashcat -m {mode})' if mode != '' else ''
        emit_line(f'[*] {c["name"]}{mode_s}')
    emit_line(f'[+] {len(candidates)} kemungkinan tipe')

    return {
        'module': 'hash_tool',
        'submode': 'identify',
        'input': h,
        'length': len(h),
        'candidates': candidates,
    }

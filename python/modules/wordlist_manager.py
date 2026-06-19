# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/wordlist_manager.py
"""Modul Wordlist Manager — SDD v2 §5.18. Download/update wordlist (SecLists)."""
import os
from typing import Callable, List, Optional

from core.stream_handler import emit_line

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

WORDLIST_SOURCES = {
    'common-dirs': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
    'subdomains-top5000': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
    'api-endpoints': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt',
    'top-usernames': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt',
    'common-passwords': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
}


class WordlistManager:
    def __init__(self, wordlist_dir: str = 'wordlists'):
        self.dir = wordlist_dir
        os.makedirs(wordlist_dir, exist_ok=True)

    def download(self, name: str, output_callback: Optional[Callable] = None) -> dict:
        cb = output_callback or emit_line
        url = WORDLIST_SOURCES.get(name)
        if not url:
            return {'ok': False, 'error': f'Wordlist tidak dikenal: {name}'}
        dest = os.path.join(self.dir, f'{name}.txt')
        cb(f'[*] Mengunduh {name} dari SecLists...')
        if not _HAS_REQUESTS:
            return {'ok': False, 'error': 'modul requests belum terpasang (pip install requests)'}
        try:
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                total = 0
                with open(dest, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        f.write(chunk)
                        total += len(chunk)
                        if total % (262144) < 65536:
                            cb(f'    {round(total/1024)} KB...')
            cb(f'[OK] Tersimpan: {dest} ({round(total/1024,1)} KB)')
            return {'ok': True, 'path': dest, 'size_kb': round(total / 1024, 1)}
        except Exception as e:
            cb(f'[ERROR] {e}')
            return {'ok': False, 'error': str(e)}

    def list_local(self) -> List[dict]:
        out = []
        for f in sorted(os.listdir(self.dir)):
            path = os.path.join(self.dir, f)
            if os.path.isfile(path):
                try:
                    with open(path, 'rb') as fh:
                        lines = sum(1 for _ in fh)
                except Exception:
                    lines = 0
                out.append({'name': f, 'lines': lines,
                            'size_kb': round(os.path.getsize(path) / 1024, 1)})
        return out

    def available_sources(self) -> List[str]:
        return list(WORDLIST_SOURCES.keys())


def run(submode: str = 'list', name: str = '', **kwargs) -> dict:
    mgr = WordlistManager()
    if submode == 'download':
        res = mgr.download(name)
        return {'module': 'wordlist', 'submode': 'download', 'name': name,
                'result': res, 'local': mgr.list_local()}
    return {'module': 'wordlist', 'submode': 'list', 'local': mgr.list_local(),
            'sources': mgr.available_sources()}

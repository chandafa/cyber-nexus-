# nexus/python/modules/api_tester.py
"""Modul API Security Tester — SDD v2 §5.10. ffuf + GraphQL introspection + demo."""
import subprocess
import json
import os
import tempfile
from typing import Callable, List, Optional

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

SUSPECT_HEADERS = ['X-Forwarded-For', 'X-Original-URL', 'X-Rewrite-URL', 'X-Host']


class ApiSecurityTester:
    def fuzz_endpoints(self, base_url: str, wordlist: str = 'wordlists/common_dirs.txt',
                       output_callback: Optional[Callable] = None) -> List[dict]:
        cb = output_callback or emit_line
        target = base_url.rstrip('/') + '/FUZZ'
        if not tool_available('ffuf'):
            cb('[DEMO] ffuf tidak terpasang — endpoint discovery demo.')
            return self._demo_endpoints(base_url, cb)
        out = os.path.join(tempfile.gettempdir(), 'ffuf_out.json')
        cmd = ['ffuf', '-u', target, '-w', wordlist,
               '-mc', '200,201,204,301,302,401,403', '-of', 'json', '-o', out, '-s']
        cb(f'$ {" ".join(cmd)}')
        cb('[*] Fuzzing endpoint (timeout 120s)...')
        try:
            cmd = fix_tool_cmd(cmd)
            rp = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            for line in (rp.stdout or '').splitlines()[:60]:
                cb(line)
            res = []
            # ffuf dengan -s & 0 match kadang tak menulis file output → anggap kosong.
            if os.path.exists(out):
                with open(out, encoding='utf-8', errors='replace') as f:
                    data = json.load(f)
                res = [{'url': r.get('url'), 'status': r.get('status'), 'length': r.get('length')}
                       for r in data.get('results', [])]
            cb(f'[=] Selesai. {len(res)} endpoint ditemukan.')
            return res  # hasil NYATA (boleh kosong) — jangan dipalsukan dengan demo
        except subprocess.TimeoutExpired:
            cb('[!] ffuf timeout.')
            return self._demo_endpoints(base_url, cb)
        except Exception as e:
            cb(f'[!] {e}.')
            return self._demo_endpoints(base_url, cb)

    def check_graphql_introspection(self, endpoint: str,
                                    cb: Optional[Callable] = None) -> dict:
        cb = cb or emit_line
        cb(f'[*] GraphQL introspection check: {endpoint}')
        from core.subprocess_runner import demo_disabled, DemoDisabled
        if not _HAS_REQUESTS:
            if demo_disabled():
                cb('[REAL] Library "requests" tidak tersedia — tidak bisa cek '
                   'introspection. Mode eksekusi nyata: hasil contoh tidak ditampilkan.')
                raise DemoDisabled('graphql: requests tidak tersedia')
            cb('[DEMO] requests tidak tersedia — hasil demo.')
            return {'introspection_enabled': True, 'type_count': 42, 'risk': 'medium',
                    'recommendation': 'Disable introspection di production'}
        try:
            resp = requests.post(endpoint, json={'query': '{ __schema { types { name } } }'},
                                 timeout=10)
            types = resp.json().get('data', {}).get('__schema', {}).get('types', [])
            return {'introspection_enabled': len(types) > 0, 'type_count': len(types),
                    'risk': 'medium' if types else 'none',
                    'recommendation': 'Disable introspection di production' if types else 'Aman'}
        except Exception as e:
            # Mode nyata: jangan palsukan "enabled" — laporkan endpoint tak terjangkau.
            cb(f'[!] GraphQL endpoint tidak terjangkau / bukan GraphQL: {e}')
            return {'introspection_enabled': False, 'type_count': 0, 'risk': 'unknown',
                    'error': str(e),
                    'recommendation': 'Endpoint tidak merespons query introspection'}

    def _demo_endpoints(self, base: str, cb: Callable) -> List[dict]:
        found = [
            {'url': base.rstrip('/') + '/api/v1/users', 'status': 200, 'length': 1843},
            {'url': base.rstrip('/') + '/api/v1/admin', 'status': 403, 'length': 102},
            {'url': base.rstrip('/') + '/api/v1/login', 'status': 401, 'length': 67},
            {'url': base.rstrip('/') + '/api/v1/debug', 'status': 200, 'length': 5021},
            {'url': base.rstrip('/') + '/graphql', 'status': 200, 'length': 412},
        ]
        lines = [f'$ ffuf -u {base}/FUZZ (demo)'] + [
            f"  {r['status']}   {r['url']}  [{r['length']}b]" for r in found]
        simulate_stream(lines, cb, delay=0.05)
        return found


def run(target: str, submode: str = 'endpoints',
        wordlist: str = 'wordlists/common_dirs.txt', **kwargs) -> dict:
    tester = ApiSecurityTester()
    if submode == 'graphql':
        gql = tester.check_graphql_introspection(target)
        return {'module': 'api', 'target': target, 'submode': 'graphql', 'graphql': gql}
    endpoints = tester.fuzz_endpoints(target, wordlist)
    # cek graphql bila ditemukan
    gql = None
    if any('/graphql' in e['url'] for e in endpoints):
        gql = tester.check_graphql_introspection(target.rstrip('/') + '/graphql')
    return {'module': 'api', 'target': target, 'submode': 'endpoints',
            'endpoints': endpoints, 'graphql': gql, 'total': len(endpoints)}

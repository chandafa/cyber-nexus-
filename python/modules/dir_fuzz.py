# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/dir_fuzz.py
"""Modul Directory / Web Fuzzing.

Melakukan fuzzing direktori & file umum pada target web. Mengutamakan tool
eksternal gobuster/ffuf jika terpasang (deteksi via tool_available), namun untuk
hasil yang DETERMINISTIK dan portabel (Windows + Linux) modul ini selalu memakai
fuzzer pure-Python berbasis urllib (stdlib) — TANPA data palsu/demo.

Cara kerja fuzzer pure-Python:
  - Membangun opener urllib dengan HTTPRedirectHandler kustom yang MENCATAT 3xx
    (tidak mengikuti redirect).
  - Tiap path diuji GET (dengan fallback HEAD->GET), User-Agent "Nexus-Fuzzer/1.0",
    timeout 5 detik, SSL verification dimatikan untuk target https.
  - Concurrency via ThreadPoolExecutor(max_workers=20).
  - Status 200,201,204,301,302,307,401,403 dianggap "ditemukan"; 404 dilewati.

Entry point: run(target, wordlist='', extensions='') -> dict
"""
import ssl
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.stream_handler import emit_line
from core.subprocess_runner import tool_available, fix_tool_cmd  # noqa: F401

USER_AGENT = 'Nexus-Fuzzer/1.0'
REQUEST_TIMEOUT = 5  # detik
MAX_WORKERS = 20
MAX_WORDLIST = 5000

# Status yang dianggap menarik / ditemukan (404 dilewati).
INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403}

# ~120 path umum bila tidak ada wordlist eksternal.
COMMON_PATHS = [
    'admin', 'login', 'dashboard', 'api', 'robots.txt', '.git/HEAD', '.env',
    'config.php', 'config', 'backup', 'backup.zip', 'backup.tar.gz', 'wp-admin',
    'wp-login.php', 'wp-content', 'wp-includes', 'phpinfo.php', 'info.php',
    'server-status', 'server-info', 'uploads', 'upload', 'images', 'img', 'css',
    'js', 'assets', 'static', 'test', 'tests', 'dev', 'staging', 'old', 'tmp',
    'temp', 'db', 'database', 'sql', '.htaccess', '.htpasswd', 'web.config',
    'sitemap.xml', 'README.md', 'readme.txt', 'LICENSE', 'CHANGELOG.md',
    'admin.php', 'administrator', 'user', 'users', 'account', 'accounts',
    'register', 'signup', 'signin', 'logout', 'search', 'download', 'downloads',
    'files', 'file', 'data', 'private', 'secret', 'hidden', '.svn', '.svn/entries',
    '.DS_Store', '.bash_history', 'swagger', 'swagger-ui', 'swagger.json',
    'api-docs', 'api/v1', 'api/v2', 'api/v3', 'graphql', 'graphiql', 'health',
    'healthz', 'metrics', 'status', 'debug', 'console', 'shell', 'cmd', 'panel',
    'cpanel', 'webmail', 'mail', 'phpmyadmin', 'pma', 'adminer', 'manager',
    'portal', 'home', 'index.php', 'index.html', 'main', 'app', 'apps', 'core',
    'lib', 'vendor', 'node_modules', 'composer.json', 'package.json', 'Dockerfile',
    'docker-compose.yml', '.dockerignore', '.gitignore', '.gitlab-ci.yml',
    'logs', 'log', 'error.log', 'access.log', 'cache', 'session', 'sessions',
    'cgi-bin', 'includes', 'include', 'classes', 'modules', 'plugins', 'themes',
    'media', 'public', 'protected', 'storage', 'var', 'etc', 'conf', 'settings',
    'setup', 'install', 'installer', 'update', 'upgrade', 'maintenance',
]


def _normalize_target(target: str) -> str:
    """Pastikan ada scheme (default http://) dan buang trailing slash."""
    t = (target or '').strip()
    if not t:
        return ''
    if not (t.startswith('http://') or t.startswith('https://')):
        t = 'http://' + t
    return t.rstrip('/')


def _load_wordlist(wordlist: str, extensions: str) -> list:
    """Bangun daftar path dari file (jika ada) atau daftar bawaan, lalu
    tambahkan ekstensi pada entri yang belum punya titik."""
    entries = []
    seen = set()

    def _add(p):
        p = p.strip().lstrip('/')
        if p and p not in seen:
            seen.add(p)
            entries.append(p)

    base = []
    wl = (wordlist or '').strip()
    if wl:
        try:
            with open(wl, encoding='utf-8', errors='replace') as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    base.append(s)
                    if len(base) >= MAX_WORDLIST:
                        break
        except OSError:
            base = list(COMMON_PATHS)
    else:
        base = list(COMMON_PATHS)

    exts = [e.strip().lstrip('.') for e in (extensions or '').split(',') if e.strip()]

    for entry in base:
        _add(entry)
        # Tambah varian berekstensi hanya untuk entri tanpa titik (bukan file).
        if exts and '.' not in entry:
            for e in exts:
                _add(f'{entry}.{e}')

    return entries[:MAX_WORDLIST]


class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Catat status 3xx tanpa mengikuti redirect (raise HTTPError)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # jangan ikuti redirect; biarkan kode 3xx muncul sbg HTTPError


def _build_opener(target: str):
    handlers = [_RecordingRedirectHandler()]
    if target.startswith('https://'):
        ctx = ssl._create_unverified_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _probe(opener, url: str, method: str = 'GET'):
    """Kembalikan (status, length) atau None bila gagal/skip (mis. 404/URLError)."""
    req = urllib.request.Request(url, method=method, headers={'User-Agent': USER_AGENT})
    try:
        resp = opener.open(req, timeout=REQUEST_TIMEOUT)
        code = resp.getcode()
        length = resp.headers.get('Content-Length')
        try:
            length = int(length) if length is not None else None
        except (TypeError, ValueError):
            length = None
        resp.close()
        return code, length
    except urllib.error.HTTPError as e:
        # HTTPError membawa .code — termasuk 301/302/307/401/403 (redirect dicegah).
        length = None
        try:
            length = e.headers.get('Content-Length') if e.headers else None
            length = int(length) if length is not None else None
        except (TypeError, ValueError):
            length = None
        return e.code, length
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
        return None
    except Exception:
        return None


def _fuzz_one(opener, base: str, path: str):
    """Uji satu path. GET dengan fallback HEAD->GET. Kembalikan hit dict atau None."""
    url = f'{base}/{path}'
    res = _probe(opener, url, method='GET')
    if res is None:
        # fallback HEAD (beberapa server menolak GET / membatasi)
        res = _probe(opener, url, method='HEAD')
    if res is None:
        return None
    code, length = res
    if code == 404 or code not in INTERESTING:
        return None
    return {'path': '/' + path, 'status': code, 'length': length, 'type': _reason(code)}


def _reason(code: int) -> str:
    if code in (301, 302, 307):
        return 'redirect'
    if code in (401, 403):
        return 'protected'
    if code in (200, 201, 204):
        return 'ok'
    return 'found'


def run(target: str, wordlist: str = '', extensions: str = '', **kwargs) -> dict:
    """Jalankan directory/web fuzzing pure-Python pada `target`.

    Args:
        target: URL/host target (scheme opsional, default http://).
        wordlist: path file wordlist opsional; bila kosong pakai daftar bawaan.
        extensions: daftar ekstensi dipisah koma (mis. "php,txt,bak").

    Returns:
        dict dengan kunci 'module' = 'dir_fuzz', berisi daftar 'found',
        'total', dan 'tested'.
    """
    cb = emit_line
    base = _normalize_target(target)
    if not base:
        return {'module': 'dir_fuzz', 'error': 'target kosong'}

    paths = _load_wordlist(wordlist, extensions)
    tested = len(paths)

    # Informasi tool eksternal (tidak dipakai untuk hasil — pure-Python deterministik).
    ext_tool = next((t for t in ('ffuf', 'gobuster') if tool_available(t)), None)
    if ext_tool:
        cb(f'[i] Tool eksternal terdeteksi: {ext_tool} (menggunakan fuzzer pure-Python untuk hasil deterministik).')

    cb(f'$ nexus-fuzzer --url {base} --paths {tested} --threads {MAX_WORKERS}')
    cb(f'[*] Memulai fuzzing {tested} path pada {base} (timeout {REQUEST_TIMEOUT}s/req)...')

    opener = _build_opener(base)
    found = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_fuzz_one, opener, base, p): p for p in paths}
        for fut in as_completed(futures):
            try:
                hit = fut.result()
            except Exception:
                hit = None
            if hit:
                length_s = hit['length'] if hit['length'] is not None else '-'
                cb(f"[+] {hit['status']} {hit['path']} ({length_s})")
                found.append(hit)

    found.sort(key=lambda h: (h['status'], h['path']))
    cb(f'[=] Selesai. {len(found)} ditemukan dari {tested} diuji.')

    return {
        'module': 'dir_fuzz',
        'target': base,
        'found': found,
        'total': len(found),
        'tested': tested,
    }

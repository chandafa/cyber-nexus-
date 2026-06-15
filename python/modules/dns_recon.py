# nexus/python/modules/dns_recon.py
"""
Modul Subdomain / DNS Recon.

Melakukan rekonesans DNS & enumerasi subdomain memakai HANYA stdlib Python
(socket, concurrent.futures) — tanpa tool eksternal, tanpa data demo/palsu.
Hasil 100% nyata dari resolusi DNS host yang dijalankan. Berjalan di
Windows maupun Linux.

Alur:
  1. Normalisasi domain (buang skema/path/whitespace).
  2. Resolusi record A/AAAA untuk apex, www, dan mail.
  3. Enumerasi subdomain dari wordlist bawaan (~60 prefix) atau file
     wordlist yang diberikan, secara paralel (ThreadPoolExecutor).
"""
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from core.stream_handler import emit_line

# Timeout per-resolusi agar host yang tidak ada tidak menggantung lama.
socket.setdefaulttimeout(3)

# Wordlist subdomain bawaan (~60 prefix umum).
DEFAULT_PREFIXES = [
    'www', 'mail', 'ftp', 'dev', 'api', 'staging', 'test', 'admin', 'vpn',
    'ns1', 'ns2', 'smtp', 'webmail', 'portal', 'm', 'blog', 'shop', 'cdn',
    'app', 'git', 'gitlab', 'jenkins', 'jira', 'db', 'mysql', 'redis',
    'grafana', 'kibana', 'status', 'support', 'docs', 'store', 'secure',
    'login', 'dashboard', 'internal', 'intranet', 'proxy', 'gateway', 'beta',
    'demo', 'cpanel', 'autodiscover', 'owa', 'remote', 'mx', 'mx1', 'mx2',
    'ns', 'dns', 'files', 'share', 'backup', 'monitor', 'metrics', 'assets',
    'static', 'img', 'video', 'media', 'auth', 'sso', 'ldap', 'vault',
]

MAX_WORDLIST = 2000


def _normalize_domain(raw: str) -> str:
    """Buang skema, path, whitespace dari input domain."""
    d = (raw or '').strip()
    if not d:
        return ''
    if '://' not in d:
        d = '//' + d
    parsed = urlparse(d)
    host = parsed.netloc or parsed.path
    host = host.split('/')[0].split('@')[-1].split(':')[0].strip()
    return host.strip('.').lower()


def _resolve_records(domain: str, cb) -> list:
    """Resolusi A/AAAA untuk apex, www, dan mail. Kembalikan list record."""
    records = []
    seen = set()
    targets = [domain, f'www.{domain}', f'mail.{domain}']
    for name in targets:
        cb(f'$ resolving {name}')
        try:
            infos = socket.getaddrinfo(name, None)
        except (socket.gaierror, OSError):
            continue
        for info in infos:
            family = info[0]
            addr = info[4][0]
            rtype = 'AAAA' if family == socket.AF_INET6 else 'A'
            key = (rtype, name, addr)
            if key in seen:
                continue
            seen.add(key)
            records.append({'type': rtype, 'name': name, 'value': addr})
            cb(f'[+] {rtype} {name} -> {addr}')
    return records


def _load_prefixes(wordlist: str, cb) -> list:
    """Muat prefix dari file wordlist bila valid, jika tidak pakai bawaan."""
    if wordlist and os.path.isfile(wordlist):
        try:
            prefixes = []
            with open(wordlist, encoding='utf-8', errors='replace') as f:
                for line in f:
                    p = line.strip()
                    if not p or p.startswith('#'):
                        continue
                    prefixes.append(p)
            cb(f'[*] memuat {len(prefixes)} prefix dari wordlist: {wordlist}')
            return prefixes[:MAX_WORDLIST]
        except OSError as e:
            cb(f'[!] gagal membaca wordlist ({e}) — pakai daftar bawaan')
    return DEFAULT_PREFIXES[:MAX_WORDLIST]


def _probe(fqdn: str):
    """Resolusi satu host. Kembalikan (fqdn, ip) atau None bila gagal."""
    try:
        ip = socket.gethostbyname(fqdn)
        return (fqdn, ip)
    except (socket.gaierror, OSError):
        return None


def run(domain: str, wordlist: str = '') -> dict:
    """Entry point dipanggil runner.py. Kembalikan dict hasil JSON-serializable."""
    cb = emit_line
    domain = _normalize_domain(domain)
    if not domain:
        return {'module': 'dns_recon', 'error': 'domain kosong'}

    cb(f'[*] Subdomain / DNS Recon untuk: {domain}')

    # 1) DNS records.
    records = _resolve_records(domain, cb)
    cb(f'[*] {len(records)} DNS record ditemukan')

    # 2) Enumerasi subdomain paralel.
    prefixes = _load_prefixes(wordlist, cb)
    fqdns = [f'{p}.{domain}' for p in prefixes]
    cb(f'[*] menguji {len(fqdns)} kandidat subdomain (paralel)...')

    subs = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = [ex.submit(_probe, fq) for fq in fqdns]
        for fut in as_completed(futures):
            hit = fut.result()
            if hit:
                fqdn, ip = hit
                subs.append({'subdomain': fqdn, 'ip': ip})
                cb(f'[+] found {fqdn} -> {ip}')

    subs.sort(key=lambda s: s['subdomain'])
    cb(f'[*] selesai — {len(subs)} subdomain aktif ditemukan')

    return {
        'module': 'dns_recon',
        'domain': domain,
        'records': records,
        'subdomains': subs,
        'total': len(subs),
    }

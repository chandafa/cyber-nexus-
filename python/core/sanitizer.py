# nexus/python/core/sanitizer.py
"""
Input sanitization — mencegah command injection sebelum input user
dimasukkan ke subprocess. Sesuai SDD bagian 12.3.
"""
import re
import ipaddress
import os

# Karakter yang berbahaya untuk shell / argument injection.
_DANGEROUS = [';', '&&', '||', '`', '$', '(', ')', '<', '>', '|', '\\', '\n', '\r']


class SanitizeError(ValueError):
    """Dilempar saat input gagal validasi."""


def sanitize_target(target: str) -> str:
    """Validasi dan sanitasi target IP, CIDR, atau domain."""
    if target is None:
        raise SanitizeError('Target kosong')
    target = target.strip()
    if not target:
        raise SanitizeError('Target kosong')

    # Buang skema URL bila ada (http://, https://) untuk validasi host.
    host = re.sub(r'^[a-zA-Z]+://', '', target).split('/')[0].split(':')[0]

    for char in _DANGEROUS:
        if char in target:
            raise SanitizeError(f'Karakter tidak diizinkan: {char!r}')

    # Coba parse sebagai IP / CIDR.
    try:
        ipaddress.ip_network(host, strict=False)
        return target
    except ValueError:
        pass

    # Validasi sebagai domain/hostname.
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$'
    if re.match(domain_pattern, host):
        return target

    raise SanitizeError(f'Target tidak valid: {target}')


def sanitize_url(url: str) -> str:
    """Validasi URL untuk scanner web (nikto/gobuster/nuclei)."""
    url = (url or '').strip()
    if not url:
        raise SanitizeError('URL kosong')
    for char in _DANGEROUS:
        if char in url:
            raise SanitizeError(f'Karakter tidak diizinkan: {char!r}')
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    if not re.match(r'^https?://[a-zA-Z0-9\-\._:/%\?\&=]+$', url):
        raise SanitizeError(f'URL tidak valid: {url}')
    return url


def sanitize_port(port) -> int:
    """Validasi nomor port (1-65535)."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise SanitizeError(f'Port harus angka, dapat: {port!r}')
    if not (1 <= p <= 65535):
        raise SanitizeError(f'Port harus antara 1-65535, dapat: {p}')
    return p


def sanitize_filepath(path: str, must_exist: bool = False) -> str:
    """Validasi path file (wordlist, hash file, log file)."""
    path = (path or '').strip()
    if not path:
        raise SanitizeError('Path kosong')
    # Cegah null byte
    if '\x00' in path:
        raise SanitizeError('Path mengandung null byte')
    if must_exist and not os.path.isfile(path):
        raise SanitizeError(f'File tidak ditemukan: {path}')
    return path


def sanitize_interface(iface: str) -> str:
    """Validasi nama interface jaringan (alfanumerik, titik, underscore)."""
    iface = (iface or '').strip()
    if not re.match(r'^[a-zA-Z0-9_\-\.\\{}: ]+$', iface):
        raise SanitizeError(f'Nama interface tidak valid: {iface}')
    return iface

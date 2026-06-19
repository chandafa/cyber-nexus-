#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Simple portable WAF module (MVP) — reverse-proxy HTTP/HTTPS with rule-based blocking

Fitur MVP:
- Reverse proxy HTTP/HTTPS with TLS termination support
- Rule-based blocking (SQLi, XSS, Path Traversal, Cmd Injection, Scanner Detected)
- Virtual host routing and config (multiple sites behind one proxy)
- Per-host rules configuration & custom rule support
- Rate limiting per IP (requests per window)
- HTML block page branded as Cyber Nexus WAF
"""
import threading
import http.server
import socketserver
import requests
import time
import re
import json
import ssl
import os
import sqlite3
import shutil
from urllib.parse import urlsplit, unquote, parse_qs
from typing import Optional

from core.stream_handler import emit_line

_SERVER = None
_THREAD = None
_DB_PATH = os.path.join(os.path.dirname(__file__), "waf_events.db")
_IN_MEMORY_LOGS = []
_LOG_CAPACITY = int(os.environ.get('WAF_LOG_CAPACITY', '5000'))
_MAX_LOG_MB = 10.0

# HTML template forblocked requests (branded as Cyber Nexus WAF)
HTML_BLOCK_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Forbidden — Cyber Nexus WAF</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #f87171;
            background: linear-gradient(135deg, #ef4444, #b91c1c);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #ffffff;
            text-align: center;
        }}
        .container {{
            max-width: 500px;
            padding: 40px 20px;
            margin: 20px;
        }}
        .icon {{
            font-size: 80px;
            margin-bottom: 24px;
            display: inline-block;
            animation: pulse 2s infinite ease-in-out;
        }}
        h1 {{
            font-size: 36px;
            font-weight: 700;
            margin: 0 0 16px 0;
            letter-spacing: -0.02em;
        }}
        p {{
            font-size: 16px;
            opacity: 0.9;
            margin: 0 0 30px 0;
            line-height: 1.6;
        }}
        .details {{
            background-color: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.25);
            border-radius: 8px;
            padding: 16px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 13px;
            text-align: left;
            margin-bottom: 30px;
        }}
        .details-item {{
            margin: 8px 0;
            display: flex;
            justify-content: space-between;
        }}
        .details-label {{
            opacity: 0.75;
            font-weight: bold;
        }}
        .details-value {{
            color: #fecaca;
        }}
        .footer {{
            font-size: 13px;
            opacity: 0.8;
            margin-top: 40px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
        }}
        .footer svg {{
            width: 36px;
            height: 36px;
            fill: currentColor;
            opacity: 0.9;
        }}
        @keyframes pulse {{
            0% {{ transform: scale(1); }}
            50% {{ transform: scale(1.05); }}
            100% {{ transform: scale(1); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>Access Forbidden</h1>
        <p>Your request has been blocked by Cyber Nexus WAF security policies.</p>
        
        <div class="details">
            <div class="details-item">
                <span class="details-label">Triggered Rule:</span>
                <span class="details-value">{rule}</span>
            </div>
            <div class="details-item">
                <span class="details-label">Client IP:</span>
                <span class="details-value">{ip}</span>
            </div>
            <div class="details-item">
                <span class="details-label">Path:</span>
                <span class="details-value">{path}</span>
            </div>
            <div class="details-item">
                <span class="details-label">Timestamp (UTC):</span>
                <span class="details-value">{ts}</span>
            </div>
        </div>

        <div class="footer">
            <svg viewBox="0 0 24 24">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 6c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 12c-2.33 0-4.31-1.24-5.4-3.1.03-1.79 3.6-2.77 5.4-2.77 1.79 0 5.37.98 5.4 2.77-1.09 1.86-3.07 3.1-5.4 3.1z"/>
            </svg>
            <span>Security Detection Powered By <strong>Cyber Nexus WAF</strong></span>
        </div>
    </div>
</body>
</html>
"""


def _init_db():
    try:
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                ip TEXT,
                rule TEXT,
                path TEXT,
                payload TEXT,
                headers TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vhosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE,
                backend_host TEXT,
                backend_port INTEGER,
                max_rps INTEGER,
                learning_mode INTEGER DEFAULT 0,
                allowlist_ips TEXT,
                allowlist_paths TEXT,
                rules TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                pattern TEXT,
                description TEXT,
                enabled INTEGER DEFAULT 1
            )
            """
        )
        conn.commit()
        conn.close()
    except Exception as e:
        emit_line(f"[WAF] DB init error: {e}")


def _init_db_and_default_vhost(backend_host: str, backend_port: int, max_rps: int, learning_mode: bool, allowlist_ips: str, allowlist_paths: str):
    _init_db()
    try:
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        rules_default = json.dumps(["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"])
        cur.execute(
            """
            INSERT INTO vhosts (hostname, backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                backend_host=excluded.backend_host,
                backend_port=excluded.backend_port,
                max_rps=excluded.max_rps,
                learning_mode=excluded.learning_mode,
                allowlist_ips=excluded.allowlist_ips,
                allowlist_paths=excluded.allowlist_paths
            """,
            ('*', backend_host, backend_port, max_rps, 1 if learning_mode else 0, allowlist_ips, allowlist_paths, rules_default)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        emit_line(f"[WAF] Gagal inisialisasi default vhost: {e}")


class SSLThreadingTCPServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, ssl_context, bind_and_activate=True):
        self.ssl_context = ssl_context
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        try:
            conn = self.ssl_context.wrap_socket(newsocket, server_side=True)
            return conn, fromaddr
        except Exception as e:
            try:
                newsocket.close()
            except Exception:
                pass
            raise e


class WAFHandler(http.server.BaseHTTPRequestHandler):
    backend_host = '127.0.0.1'
    backend_port = 8000
    max_rps = 10
    window = 1.0
    ip_buckets = {}
    learning_mode = False
    allowlist_ips = set()
    allowlist_paths = []

    def _log(self, msg: str):
        emit_line(f"[WAF] {msg}")

    def _rate_limit_exceeded_custom(self, ip: str, limit_rps: int) -> bool:
        now = time.time()
        bucket = self.ip_buckets.setdefault(ip, [])
        # purge old
        while bucket and bucket[0] < now - self.window:
            bucket.pop(0)
        if len(bucket) >= limit_rps:
            return True
        bucket.append(now)
        return False

    def _get_vhost_config(self, hostname: str) -> dict:
        default_config = {
            'backend_host': self.backend_host,
            'backend_port': self.backend_port,
            'max_rps': self.max_rps,
            'learning_mode': self.learning_mode,
            'allowlist_ips': self.allowlist_ips,
            'allowlist_paths': self.allowlist_paths,
            'rules': ["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"]
        }
        try:
            conn = sqlite3.connect(_DB_PATH)
            cur = conn.cursor()
            # Exact match
            cur.execute("SELECT backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules FROM vhosts WHERE hostname = ?", (hostname,))
            row = cur.fetchone()
            if not row:
                # Wildcard match
                cur.execute("SELECT backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules FROM vhosts WHERE hostname = ?", ('*',))
                row = cur.fetchone()
            conn.close()

            if row:
                bh, bp, mr, lm, al_ips, al_paths, r_str = row
                try:
                    rules_list = json.loads(r_str) if r_str else []
                except Exception:
                    rules_list = []
                return {
                    'backend_host': bh,
                    'backend_port': bp,
                    'max_rps': mr,
                    'learning_mode': bool(lm),
                    'allowlist_ips': {ip.strip() for ip in al_ips.split(",") if ip.strip()} if al_ips else set(),
                    'allowlist_paths': [p.strip() for p in al_paths.split(",") if p.strip()] if al_paths else [],
                    'rules': rules_list
                }
        except Exception:
            pass
        return default_config

    def _proxy_to_backend_custom(self, ip: str, body: bytes, decoded_path: str, decoded_body: str, headers_text: str, bh: str, bp: int):
        url = f'http://{bh}:{bp}{self.path}'
        headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
        try:
            resp = requests.request(self.command, url, headers=headers, data=body, allow_redirects=False, timeout=10)
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() in ('connection', 'keep-alive', 'transfer-encoding', 'upgrade'):
                    continue
                self.send_header(k, v)
            self.end_headers()
            if resp.content:
                self.wfile.write(resp.content)
            try:
                log_event(ip, f'allow:{resp.status_code}', decoded_path, decoded_body, headers_text)
            except Exception:
                pass
            self._log(f"{ip} -> {self.command} {self.path} proxied to {bh}:{bp} ({resp.status_code})")
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            err_body = f'Bad gateway: {e}'
            self.wfile.write(err_body.encode('utf-8'))
            self._log(f"{ip} -> 502 proxy error for {bh}:{bp}: {e}")

    def _proxy_request(self):
        ip = self.client_address[0]
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length) if length else b''
        decoded_path = unquote(self.path or '')
        decoded_body = body.decode('utf-8', errors='replace') if body else ''
        headers_text = '\n'.join(f"{k}:{v}" for k, v in self.headers.items())

        # Resolve virtual host configuration
        host_header = self.headers.get('Host', '')
        hostname = host_header.split(':')[0].strip().lower() if host_header else 'localhost'
        config = self._get_vhost_config(hostname)

        backend_host = config['backend_host']
        backend_port = config['backend_port']
        max_rps = config['max_rps']
        learning_mode = config['learning_mode']
        allowlist_ips = config['allowlist_ips']
        allowlist_paths = config['allowlist_paths']
        enabled_rules_list = config['rules']

        # Check IP allowlist
        if ip in allowlist_ips:
            self._log(f"{ip} -> bypassed (IP in allowlist)")
            self._proxy_to_backend_custom(ip, body, decoded_path, decoded_body, headers_text, backend_host, backend_port)
            return

        # Check Path allowlist
        for p in allowlist_paths:
            if decoded_path.startswith(p):
                self._log(f"{ip} -> bypassed (Path {p} in allowlist)")
                self._proxy_to_backend_custom(ip, body, decoded_path, decoded_body, headers_text, backend_host, backend_port)
                return

        # Rate Limiting
        if self._rate_limit_exceeded_custom(ip, max_rps):
            self.send_response(429)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
            err_body = HTML_BLOCK_TEMPLATE.format(rule='rate_limiting_exceeded', ip=ip, path=decoded_path, ts=ts)
            self.wfile.write(err_body.encode('utf-8'))
            self._log(f"{ip} -> 429 rate limit")
            return

        # Parse request inputs for rule checking
        parts = urlsplit(decoded_path)
        query_vals = []
        if parts.query:
            qs = parse_qs(parts.query)
            for k, vs in qs.items():
                query_vals.append(k)
                query_vals.extend(vs)

        content_type = (self.headers.get('Content-Type') or '').split(';')[0].strip().lower()
        body_vals = []
        if content_type == 'application/x-www-form-urlencoded':
            try:
                bqs = parse_qs(decoded_body)
                for k, vs in bqs.items():
                    body_vals.append(k)
                    body_vals.extend(vs)
            except Exception:
                pass
        elif content_type == 'application/json':
            try:
                j = json.loads(decoded_body) if decoded_body else {}
                def _collect_json(v):
                    out = []
                    if isinstance(v, dict):
                        for vv in v.values():
                            out.extend(_collect_json(vv))
                    elif isinstance(v, list):
                        for vv in v:
                            out.extend(_collect_json(vv))
                    else:
                        out.append(str(v))
                    return out
                body_vals.extend(_collect_json(j))
            except Exception:
                pass
        else:
            if decoded_body:
                body_vals.append(decoded_body)

        check_src = parts.path + '\n' + ' '.join(query_vals) + '\n' + ' '.join(body_vals) + '\n' + self.command + '\n' + headers_text + '\n' + decoded_body

        # Build active rules matching
        default_rules = _build_default_rules()
        custom_rules = _get_active_custom_rules()
        all_available_rules = default_rules + custom_rules

        active_rules = []
        for name, pattern in all_available_rules:
            if name in enabled_rules_list:
                active_rules.append((name, pattern))

        matched = None
        for name, pattern in active_rules:
            if pattern.search(check_src):
                matched = name
                break

        if matched:
            if learning_mode:
                try:
                    log_event(ip, f'detect:{matched}', decoded_path, decoded_body, headers_text)
                except Exception:
                    pass
                self._log(f"{ip} -> rules matched: {matched} (learning mode: ALLOWED)")
                self._proxy_to_backend_custom(ip, body, decoded_path, decoded_body, headers_text, backend_host, backend_port)
            else:
                try:
                    log_event(ip, matched, decoded_path, decoded_body, headers_text)
                except Exception:
                    pass
                self.send_response(403)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                
                ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
                err_body = HTML_BLOCK_TEMPLATE.format(rule=matched, ip=ip, path=decoded_path, ts=ts)
                self.wfile.write(err_body.encode('utf-8'))
                self._log(f"{ip} -> 403 blocked by {matched}")
            return

        self._proxy_to_backend_custom(ip, body, decoded_path, decoded_body, headers_text, backend_host, backend_port)

    def do_GET(self):
        self._proxy_request()

    def do_POST(self):
        self._proxy_request()

    def do_PUT(self):
        self._proxy_request()

    def do_DELETE(self):
        self._proxy_request()


def _build_default_rules():
    rules = []
    rules.append(('sql_injection', re.compile(r"\b(union select|select .* from|or\s+1=1|-- |;\s*drop|sleep\(|benchmark\()", re.I)))
    rules.append(('xss', re.compile(r"<script|<svg|onerror=|onload=|document\.cookie|<iframe", re.I)))
    rules.append(('path_traversal', re.compile(r"\.\./|/etc/passwd", re.I)))
    rules.append(('cmd_injection', re.compile(r";\s*(rm|wget|curl|nc|bash|sh)\b", re.I)))
    rules.append(('scanner_detected', re.compile(r"(nmap|nikto|sqlmap|acunetix|dirbuster|gobuster)", re.I)))
    return rules


def _get_active_custom_rules():
    rules = []
    try:
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT name, pattern FROM custom_rules WHERE enabled = 1")
        rows = cur.fetchall()
        conn.close()
        for name, pattern in rows:
            try:
                rules.append((name, re.compile(pattern, re.I)))
            except Exception as e:
                emit_line(f"[WAF] Invalid custom regex pattern for rule {name}: {e}")
    except Exception as e:
        # DB might not be initialized or table might not exist yet
        pass
    return rules


def _find_openssl() -> str:
    """Find openssl binary in system PATH or common Git directories on Windows."""
    openssl_path = shutil.which("openssl")
    if openssl_path:
        return openssl_path

    if os.name == 'nt':
        common_paths = [
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
            os.path.join(os.environ.get("USERPROFILE", ""), r"AppData\Local\Programs\Git\usr\bin\openssl.exe")
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p
    return "openssl"


def _auto_generate_cert() -> tuple[str, str]:
    """Auto generate self-signed certificate if openssl is available."""
    dir_path = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(dir_path, "waf_cert.pem")
    key_path = os.path.join(dir_path, "waf_key.pem")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    openssl_bin = _find_openssl()
    import subprocess
    cmd = [
        openssl_bin, "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-sha256", "-days", "365", "-nodes",
        "-subj", "/CN=localhost"
    ]
    try:
        emit_line("[WAF] Membuat self-signed certificate dengan openssl...")
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        emit_line(f"[WAF] Certificate dibuat: {cert_path}")
        return cert_path, key_path
    except Exception as e:
        emit_line(f"[WAF] Gagal menjalankan openssl: {e}")
        return cert_path, key_path


def _start_server(listen_port: int, backend_host: str, backend_port: int, max_rps: int,
                  learning_mode: bool = False, allowlist_ips: str = "", allowlist_paths: str = "",
                  ssl_enabled: bool = False, ssl_cert_type: str = "self_signed",
                  ssl_cert_path: str = "", ssl_key_path: str = ""):
    global _SERVER, _THREAD
    _init_db_and_default_vhost(backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths)
    if _SERVER:
        emit_line('[WAF] Server sudah berjalan')
        return True

    handler = WAFHandler
    handler.backend_host = backend_host
    handler.backend_port = backend_port
    handler.max_rps = max_rps
    handler.window = 1.0
    handler.learning_mode = learning_mode
    handler.allowlist_ips = {ip.strip() for ip in allowlist_ips.split(",") if ip.strip()}
    handler.allowlist_paths = [p.strip() for p in allowlist_paths.split(",") if p.strip()]

    ssl_context = None
    if ssl_enabled:
        try:
            if ssl_cert_type == "self_signed" or not ssl_cert_path or not ssl_key_path:
                cert_file, key_file = _auto_generate_cert()
            else:
                cert_file, key_file = ssl_cert_path, ssl_key_path

            if not os.path.exists(cert_file) or not os.path.exists(key_file):
                emit_line(f"[WAF] File certificate tidak ditemukan: cert={cert_file}, key={key_file}")
                return False

            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            emit_line(f"[WAF] TLS termination aktif menggunakan cert: {cert_file}")
        except Exception as e:
            emit_line(f"[WAF] Gagal inisialisasi SSL: {e}")
            return False

    try:
        if ssl_context:
            _SERVER = SSLThreadingTCPServer(('0.0.0.0', listen_port), handler, ssl_context)
        else:
            _SERVER = socketserver.ThreadingTCPServer(('0.0.0.0', listen_port), handler)
    except Exception as e:
        emit_line(f'[WAF] Gagal bind ke port {listen_port}: {e}')
        return False

    def _serve():
        scheme = "https" if ssl_enabled else "http"
        emit_line(f'[WAF] Menjalankan proxy pada {scheme}://0.0.0.0:{listen_port}')
        try:
            _SERVER.serve_forever()
        except Exception as e:
            emit_line(f'[WAF] Server berhenti: {e}')

    _THREAD = threading.Thread(target=_serve, daemon=True)
    _THREAD.start()
    return True


def run(listen_port: str = '8080', backend: str = '127.0.0.1', backend_port: str = '8000', max_rps: str = '10',
        max_log_mb: str = '10', learning_mode: str = 'false', allowlist_ips: str = '', allowlist_paths: str = '',
        ssl_enabled: str = 'false', ssl_cert_type: str = 'self_signed',
        ssl_cert_path: str = '', ssl_key_path: str = '') -> dict:
    """Start WAF proxy in background and return status dict."""
    global _MAX_LOG_MB
    try:
        lp = int(listen_port)
        bp = int(backend_port)
        mr = int(max_rps)
        _MAX_LOG_MB = float(max_log_mb)
        lm = str(learning_mode).lower() in ('1', 'true', 'yes')
        se = str(ssl_enabled).lower() in ('1', 'true', 'yes')
    except Exception:
        emit_line('[WAF] Invalid numeric argument')
        return {'module': 'waf', 'status': 'error', 'error': 'invalid args'}

    success = _start_server(lp, backend, bp, mr, learning_mode=lm, allowlist_ips=allowlist_ips,
                            allowlist_paths=allowlist_paths, ssl_enabled=se, ssl_cert_type=ssl_cert_type,
                            ssl_cert_path=ssl_cert_path, ssl_key_path=ssl_key_path)
    if not success:
        return {'module': 'waf', 'status': 'error', 'error': f'bind_failed:{listen_port}'}

    return {'module': 'waf', 'status': 'running', 'listen_port': lp, 'backend_host': backend, 'backend_port': bp, 'max_log_mb': _MAX_LOG_MB}


def run_foreground(listen_port: str = '8080', backend: str = '127.0.0.1', backend_port: str = '8000', max_rps: str = '10',
                   max_log_mb: str = '10', learning_mode: str = 'false', allowlist_ips: str = '', allowlist_paths: str = '',
                   ssl_enabled: str = 'false', ssl_cert_type: str = 'self_signed',
                   ssl_cert_path: str = '', ssl_key_path: str = '') -> dict:
    """Start WAF and block in the current process."""
    global _MAX_LOG_MB
    try:
        lp = int(listen_port)
        bp = int(backend_port)
        mr = int(max_rps)
        _MAX_LOG_MB = float(max_log_mb)
        lm = str(learning_mode).lower() in ('1', 'true', 'yes')
        se = str(ssl_enabled).lower() in ('1', 'true', 'yes')
    except Exception:
        emit_line('[WAF] Invalid numeric argument')
        return {'module': 'waf', 'status': 'error', 'error': 'invalid args'}

    success = _start_server(lp, backend, bp, mr, learning_mode=lm, allowlist_ips=allowlist_ips,
                            allowlist_paths=allowlist_paths, ssl_enabled=se, ssl_cert_type=ssl_cert_type,
                            ssl_cert_path=ssl_cert_path, ssl_key_path=ssl_key_path)
    if not success:
        return {'module': 'waf', 'status': 'error', 'error': f'bind_failed:{listen_port}'}

    if _SERVER:
        try:
            scheme = "https" if se else "http"
            emit_line(f'[WAF] Foreground serving on {scheme}://0.0.0.0:{lp}')
            _SERVER.serve_forever()
        except KeyboardInterrupt:
            emit_line('[WAF] Foreground interrupted, shutting down')
        except Exception as e:
            emit_line(f'[WAF] Foreground server error: {e}')
        finally:
            try:
                _SERVER.shutdown()
                _SERVER.server_close()
            except Exception:
                pass
    return {'module': 'waf', 'status': 'stopped'}


def stop() -> dict:
    """Shutdown the running WAF server."""
    global _SERVER, _THREAD
    if not _SERVER:
        return {'module': 'waf', 'status': 'stopped', 'message': 'not running'}
    try:
        _SERVER.shutdown()
        _SERVER.server_close()
    except Exception as e:
        emit_line(f"[WAF] stop error: {e}")
    _SERVER = None
    _THREAD = None
    return {'module': 'waf', 'status': 'stopped'}


def status() -> dict:
    if _SERVER:
        addr = _SERVER.server_address
        return {'module': 'waf', 'status': 'running', 'listen': f'{addr[0]}:{addr[1]}'}
    return {'module': 'waf', 'status': 'stopped'}


def log_event(ip: str, rule: str, path: str, payload: str, headers: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    rec = {'ts': ts, 'ip': ip, 'rule': rule, 'path': path, 'payload': payload, 'headers': headers}
    _IN_MEMORY_LOGS.append(rec)
    if len(_IN_MEMORY_LOGS) > _LOG_CAPACITY:
        del _IN_MEMORY_LOGS[0: len(_IN_MEMORY_LOGS) - _LOG_CAPACITY]
    try:
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO events (ts, ip, rule, path, payload, headers) VALUES (?, ?, ?, ?, ?, ?)',
                    (ts, ip, rule, path, payload, headers))
        conn.commit()

        # Enforce size capacity in MB
        try:
            db_size_mb = os.path.getsize(_DB_PATH) / (1024 * 1024)
            if db_size_mb > _MAX_LOG_MB:
                cur.execute('SELECT COUNT(1) FROM events')
                cnt = cur.fetchone()[0]
                to_delete = max(1, int(cnt * 0.2))
                cur.execute('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)', (to_delete,))
                conn.commit()
                cur.execute('VACUUM')
                conn.commit()
        except Exception as e:
            emit_line(f"[WAF] Prune error: {e}")

        # Enforce DB row capacity
        try:
            cur.execute('SELECT COUNT(1) FROM events')
            cnt = cur.fetchone()[0]
            if cnt > _LOG_CAPACITY:
                to_delete = cnt - _LOG_CAPACITY
                cur.execute('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)', (to_delete,))
                conn.commit()
        except Exception:
            pass
        conn.close()
    except Exception as e:
        emit_line(f"[WAF] log insert error: {e}")


def get_logs(limit: int = 200) -> dict:
    try:
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT ts, ip, rule, path, payload FROM events ORDER BY id DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        conn.close()
        out = [{'ts': r[0], 'ip': r[1], 'rule': r[2], 'path': r[3], 'payload': r[4]} for r in rows]
        return {'module': 'waf', 'logs': out}
    except Exception as e:
        emit_line(f"[WAF] get_logs error: {e}")
        return {'module': 'waf', 'logs': list(reversed(_IN_MEMORY_LOGS[-limit:]))}


# --- Virtual Hosts CRUD APIs ---

def get_vhosts() -> dict:
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, hostname, backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules FROM vhosts")
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({
                'id': r[0],
                'hostname': r[1],
                'backend_host': r[2],
                'backend_port': r[3],
                'max_rps': r[4],
                'learning_mode': bool(r[5]),
                'allowlist_ips': r[6] or "",
                'allowlist_paths': r[7] or "",
                'rules': json.loads(r[8]) if r[8] else []
            })
        return {'status': 'ok', 'vhosts': out}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def save_vhost(hostname: str, backend_host: str, backend_port: str, max_rps: str,
               learning_mode: str, allowlist_ips: str, allowlist_paths: str, rules_json: str) -> dict:
    try:
        _init_db()
        bp = int(backend_port)
        mr = int(max_rps)
        lm = 1 if str(learning_mode).lower() in ('1', 'true', 'yes') else 0
        rules_list = json.loads(rules_json) if rules_json else []
        rules_str = json.dumps(rules_list)

        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vhosts (hostname, backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                backend_host=excluded.backend_host,
                backend_port=excluded.backend_port,
                max_rps=excluded.max_rps,
                learning_mode=excluded.learning_mode,
                allowlist_ips=excluded.allowlist_ips,
                allowlist_paths=excluded.allowlist_paths,
                rules=excluded.rules
            """,
            (hostname.strip(), backend_host.strip(), bp, mr, lm, allowlist_ips, allowlist_paths, rules_str)
        )
        conn.commit()
        conn.close()
        return {'status': 'ok'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def delete_vhost(hostname: str) -> dict:
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM vhosts WHERE hostname = ?", (hostname,))
        conn.commit()
        conn.close()
        return {'status': 'ok'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


# --- Custom Rules CRUD APIs ---

def get_custom_rules() -> dict:
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, name, pattern, description, enabled FROM custom_rules")
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({
                'id': r[0],
                'name': r[1],
                'pattern': r[2],
                'description': r[3] or "",
                'enabled': bool(r[4])
            })
        return {'status': 'ok', 'rules': out}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def save_custom_rule(name: str, pattern: str, description: str, enabled: str) -> dict:
    try:
        _init_db()
        re.compile(pattern)  # Test regex validity
        en = 1 if str(enabled).lower() in ('1', 'true', 'yes') else 0

        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO custom_rules (name, pattern, description, enabled)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                pattern=excluded.pattern,
                description=excluded.description,
                enabled=excluded.enabled
            """,
            (name.strip(), pattern, description, en)
        )
        conn.commit()
        conn.close()
        return {'status': 'ok'}
    except Exception as e:
        return {'status': 'error', 'error': f"Regex error or database error: {e}"}


def delete_custom_rule(name: str) -> dict:
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM custom_rules WHERE name = ?", (name,))
        conn.commit()
        conn.close()
        return {'status': 'ok'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

#!/usr/bin/env python3
"""
Simple portable WAF module (MVP) — reverse-proxy HTTP with rule-based blocking

Fitur MVP:
- Reverse proxy HTTP (port configurable)
- Rule-based blocking untuk pola SQLi / XSS / Path Traversal
- Rate limiting per IP (requests per window)

Dirancang sebagai PoC ringan untuk digunakan sebagai modul Nexus.
"""
import threading
import http.server
import socketserver
import requests
import time
import re
import json
from urllib.parse import urlsplit, urlunsplit, unquote, parse_qs
from typing import Optional
import sqlite3
import os

from core.stream_handler import emit_line


_SERVER = None
_THREAD = None
_DB_PATH = os.path.join(os.path.dirname(__file__), "waf_events.db")
_IN_MEMORY_LOGS = []
_LOG_CAPACITY = int(os.environ.get('WAF_LOG_CAPACITY', '5000'))


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
        conn.commit()
        conn.close()
    except Exception as e:
        emit_line(f"[WAF] DB init error: {e}")


class WAFHandler(http.server.BaseHTTPRequestHandler):
    backend_host = '127.0.0.1'
    backend_port = 8000
    max_rps = 10
    window = 1.0
    ip_buckets = {}
    rules = []

    def _log(self, msg: str):
        emit_line(f"[WAF] {msg}")

    def _rate_limit_exceeded(self, ip: str) -> bool:
        now = time.time()
        bucket = self.ip_buckets.setdefault(ip, [])
        # purge old
        while bucket and bucket[0] < now - self.window:
            bucket.pop(0)
        if len(bucket) >= self.max_rps:
            return True
        bucket.append(now)
        return False

    def _check_rules(self, data: str) -> Optional[str]:
        for name, pattern in self.rules:
            if pattern.search(data):
                return name
        return None

    def _proxy_request(self):
        ip = self.client_address[0]
        if self._rate_limit_exceeded(ip):
            self.send_response(429)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            body = 'Rate limit exceeded'
            self.wfile.write(body.encode('utf-8'))
            self._log(f"{ip} -> 429 rate limit")
            return

        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length) if length else b''
        # normalize/decode inputs to improve detection (e.g. percent-encoding)
        decoded_path = unquote(self.path or '')
        decoded_body = body.decode('utf-8', errors='replace') if body else ''
        headers_text = '\n'.join(f"{k}:{v}" for k, v in self.headers.items())

        # parse query params separately
        parts = urlsplit(decoded_path)
        query_vals = []
        if parts.query:
            qs = parse_qs(parts.query)
            for k, vs in qs.items():
                query_vals.append(k)
                query_vals.extend(vs)

        # parse body based on content-type
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
                # flatten JSON to string values
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
            # fallback: include raw decoded body
            if decoded_body:
                body_vals.append(decoded_body)

        # aggregate data to check (include parsed values)
        check_src = parts.path + '\n' + ' '.join(query_vals) + '\n' + ' '.join(body_vals) + '\n' + self.command + '\n' + headers_text + '\n' + decoded_body
        matched = self._check_rules(check_src)
        if matched:
            # log event
            try:
                log_event(ip, matched, decoded_path, decoded_body, headers_text)
            except Exception:
                pass
            self.send_response(403)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            body = f'Blocked by WAF rule: {matched}'
            self.wfile.write(body.encode('utf-8'))
            self._log(f"{ip} -> 403 blocked by {matched}")
            return

        # proxy to backend
        url = f'http://{self.backend_host}:{self.backend_port}{self.path}'
        headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
        try:
            resp = requests.request(self.command, url, headers=headers, data=body, allow_redirects=False, timeout=10)
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                # skip hop-by-hop
                if k.lower() in ('connection', 'keep-alive', 'transfer-encoding', 'upgrade'):
                    continue
                self.send_header(k, v)
            self.end_headers()
            if resp.content:
                self.wfile.write(resp.content)
            try:
                # log allowed proxied request (include status code)
                log_event(ip, f'allow:{resp.status_code}', decoded_path, decoded_body, headers_text)
            except Exception:
                pass
            self._log(f"{ip} -> {self.command} {self.path} proxied ({resp.status_code})")
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            body = f'Bad gateway: {e}'
            self.wfile.write(body.encode('utf-8'))
            self._log(f"{ip} -> 502 proxy error: {e}")

    def do_GET(self):
        self._proxy_request()

    def do_POST(self):
        self._proxy_request()

    def do_PUT(self):
        self._proxy_request()

    def do_DELETE(self):
        self._proxy_request()


def _build_rules():
    rules = []
    # simple SQLi heuristics
    rules.append(('sql_injection', re.compile(r"\b(union select|select .* from|or\s+1=1|-- |;\s*drop|sleep\(|benchmark\()", re.I)))
    # simple XSS heuristics
    rules.append(('xss', re.compile(r"<script|<svg|onerror=|onload=|document\.cookie|<iframe", re.I)))
    # path traversal
    rules.append(('path_traversal', re.compile(r"\.\./|/etc/passwd", re.I)))
    # command injection
    rules.append(('cmd_injection', re.compile(r";\s*(rm|wget|curl|nc|bash|sh)\b", re.I)))
    return rules


def _start_server(listen_port: int, backend_host: str, backend_port: int, max_rps: int):
    global _SERVER, _THREAD
    _init_db()
    if _SERVER:
        emit_line('[WAF] Server sudah berjalan')
        return True

    handler = WAFHandler
    handler.backend_host = backend_host
    handler.backend_port = backend_port
    handler.max_rps = max_rps
    handler.window = 1.0
    handler.rules = _build_rules()

    try:
        _SERVER = socketserver.ThreadingTCPServer(('0.0.0.0', listen_port), handler)
    except Exception as e:
        emit_line(f'[WAF] Gagal bind ke port {listen_port}: {e}')
        return False

    def _serve():
        emit_line(f'[WAF] Menjalankan proxy pada 0.0.0.0:{listen_port} -> {backend_host}:{backend_port}')
        try:
            _SERVER.serve_forever()
        except Exception as e:
            emit_line(f'[WAF] Server berhenti: {e}')

    _THREAD = threading.Thread(target=_serve, daemon=True)
    _THREAD.start()
    return True


def run(listen_port: str = '8080', backend: str = '127.0.0.1', backend_port: str = '8000', max_rps: str = '10') -> dict:
    """Start WAF proxy in background and return status dict."""
    try:
        lp = int(listen_port)
        bp = int(backend_port)
        mr = int(max_rps)
    except Exception:
        emit_line('[WAF] Invalid numeric argument')
        return {'module': 'waf', 'status': 'error', 'error': 'invalid args'}

    success = _start_server(lp, backend, bp, mr)
    if not success:
        return {'module': 'waf', 'status': 'error', 'error': f'bind_failed:{listen_port}'}

    return {'module': 'waf', 'status': 'running', 'listen_port': lp, 'backend_host': backend, 'backend_port': bp}


def run_foreground(listen_port: str = '8080', backend: str = '127.0.0.1', backend_port: str = '8000', max_rps: str = '10') -> dict:
    """Start WAF and block in the current process (serve_forever).

    Use this when you want the calling process to remain alive (e.g., during dev
    or when launched directly from a supervisor). Returns after server stops.
    """
    lp = int(listen_port)
    bp = int(backend_port)
    mr = int(max_rps)

    # initialize and start server (if not already)
    success = _start_server(lp, backend, bp, mr)
    if not success:
        return {'module': 'waf', 'status': 'error', 'error': f'bind_failed:{listen_port}'}

    # If _SERVER exists, call serve_forever in this thread to block.
    if _SERVER:
        try:
            emit_line(f'[WAF] Foreground serving on 0.0.0.0:{lp} -> {backend}:{bp}')
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
    # enforce in-memory cap
    if len(_IN_MEMORY_LOGS) > _LOG_CAPACITY:
        del _IN_MEMORY_LOGS[0: len(_IN_MEMORY_LOGS) - _LOG_CAPACITY]
    try:
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO events (ts, ip, rule, path, payload, headers) VALUES (?, ?, ?, ?, ?, ?)',
                    (ts, ip, rule, path, payload, headers))
        conn.commit()
        # enforce DB capacity: delete oldest rows if over capacity
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
        # fallback to memory
        return {'module': 'waf', 'logs': list(reversed(_IN_MEMORY_LOGS[-limit:]))}

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
import queue
import hashlib
import random
import string
from urllib.parse import urlsplit, unquote, parse_qs
from typing import Optional

from core.stream_handler import emit_line

_SERVER = None
_THREAD = None
_WAF_DATA_DIR = os.environ.get("NEXUS_APP_DATA_DIR")
if not _WAF_DATA_DIR:
    _WAF_DATA_DIR = os.path.dirname(__file__)
else:
    os.makedirs(_WAF_DATA_DIR, exist_ok=True)

_DB_PATH = os.path.join(_WAF_DATA_DIR, "waf_events.db")
_IN_MEMORY_LOGS = []
_LOG_CAPACITY = int(os.environ.get('WAF_LOG_CAPACITY', '5000'))
_MAX_LOG_MB = 10.0
_LOCAL_VHOSTS_PATH = os.path.join(_WAF_DATA_DIR, "vhosts_local.json")

def _init_local_vhosts_file():
    if not os.path.exists(_LOCAL_VHOSTS_PATH):
        try:
            with open(_LOCAL_VHOSTS_PATH, 'w', encoding='utf-8') as f:
                json.dump([], f)
        except Exception:
            pass

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
    _init_local_vhosts_file()
    try:
        conn = sqlite3.connect(_DB_PATH)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except Exception:
            pass
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
        # Migrasi kolom country_code & country_name
        cur.execute("PRAGMA table_info(events)")
        cols = [c[1] for c in cur.fetchall()]
        if 'country_code' not in cols:
            cur.execute("ALTER TABLE events ADD COLUMN country_code TEXT")
        if 'country_name' not in cols:
            cur.execute("ALTER TABLE events ADD COLUMN country_name TEXT")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vhosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE,
                vhost_type TEXT DEFAULT 'proxy',
                backend_host TEXT,
                backend_port INTEGER,
                root_directory TEXT DEFAULT '',
                max_rps INTEGER,
                learning_mode INTEGER DEFAULT 0,
                allowlist_ips TEXT,
                allowlist_paths TEXT,
                blacklist_ips TEXT DEFAULT '',
                blacklist_countries TEXT DEFAULT '',
                identity_enabled INTEGER DEFAULT 0,
                identity_password TEXT DEFAULT '',
                captcha_enabled INTEGER DEFAULT 0,
                obfuscation_enabled INTEGER DEFAULT 0,
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
        # Migrasi kolom vhost_type, root_directory & blacklist_ips untuk vhosts
        cur.execute("PRAGMA table_info(vhosts)")
        cols_vh = [c[1] for c in cur.fetchall()]
        if 'vhost_type' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN vhost_type TEXT DEFAULT 'proxy'")
        if 'root_directory' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN root_directory TEXT DEFAULT ''")
        if 'blacklist_ips' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN blacklist_ips TEXT DEFAULT ''")
        if 'blacklist_countries' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN blacklist_countries TEXT DEFAULT ''")
        if 'identity_enabled' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN identity_enabled INTEGER DEFAULT 0")
        if 'identity_password' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN identity_password TEXT DEFAULT ''")
        if 'captcha_enabled' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN captcha_enabled INTEGER DEFAULT 0")
        if 'obfuscation_enabled' not in cols_vh:
            cur.execute("ALTER TABLE vhosts ADD COLUMN obfuscation_enabled INTEGER DEFAULT 0")
        conn.commit()
        conn.close()
    except Exception as e:
        emit_line(f"[WAF] DB init error: {e}")


def _init_db_and_default_vhost(backend_host: str, backend_port: int, max_rps: int, learning_mode: bool, allowlist_ips: str, allowlist_paths: str, blacklist_ips: str = "", blacklist_countries: str = "", identity_enabled: bool = False, identity_password: str = "", captcha_enabled: bool = False, obfuscation_enabled: bool = False):
    _init_db()
    try:
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        rules_default = json.dumps(["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"])
        cur.execute(
            """
            INSERT INTO vhosts (hostname, backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules, blacklist_ips, blacklist_countries, identity_enabled, identity_password, captcha_enabled, obfuscation_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                backend_host=excluded.backend_host,
                backend_port=excluded.backend_port,
                max_rps=excluded.max_rps,
                learning_mode=excluded.learning_mode,
                allowlist_ips=excluded.allowlist_ips,
                allowlist_paths=excluded.allowlist_paths,
                blacklist_ips=excluded.blacklist_ips,
                blacklist_countries=excluded.blacklist_countries,
                identity_enabled=excluded.identity_enabled,
                identity_password=excluded.identity_password,
                captcha_enabled=excluded.captcha_enabled,
                obfuscation_enabled=excluded.obfuscation_enabled
            """,
            ('*', backend_host, backend_port, max_rps, 1 if learning_mode else 0, allowlist_ips, allowlist_paths, rules_default, blacklist_ips, blacklist_countries, 1 if identity_enabled else 0, identity_password, 1 if captcha_enabled else 0, 1 if obfuscation_enabled else 0)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        emit_line(f"[WAF] init default vhost error: {e}")
        emit_line(f"[WAF] Gagal inisialisasi default vhost: {e}")


# HTML template for CAPTCHA Challenge (premium dark mode glassmorphism)
HTML_CAPTCHA_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification — Cyber Nexus WAF</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #0f172a;
            background: radial-gradient(circle at center, #1e1b4b 0%, #09090b 100%);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #f4f4f5;
            text-align: center;
        }}
        .card {{
            background: rgba(30, 41, 59, 0.4);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 40px 30px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        .icon {{
            font-size: 50px;
            margin-bottom: 20px;
            display: inline-block;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 700;
            margin: 0 0 10px 0;
            color: #ffffff;
        }}
        p {{
            font-size: 13.5px;
            color: #a1a1aa;
            margin: 0 0 25px 0;
            line-height: 1.5;
        }}
        .math-box {{
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 8px;
            padding: 15px;
            font-size: 22px;
            font-weight: bold;
            letter-spacing: 2px;
            color: #818cf8;
            margin-bottom: 25px;
            font-family: monospace;
        }}
        .input-group {{
            margin-bottom: 20px;
        }}
        .input-group input {{
            width: 100%;
            padding: 12px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 8px;
            color: #ffffff;
            font-size: 16px;
            text-align: center;
            box-sizing: border-box;
            outline: none;
            transition: border-color 0.2s;
        }}
        .input-group input:focus {{
            border-color: #6366f1;
        }}
        .btn {{
            width: 100%;
            padding: 12px;
            background: #4f46e5;
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .btn:hover {{
            background: #4338ca;
        }}
        .error {{
            color: #ef4444;
            font-size: 13px;
            margin-top: 10px;
        }}
        .footer {{
            font-size: 11px;
            color: #71717a;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🛡️</div>
        <h1>Verify You Are Human</h1>
        <p>Your request has triggered security verification checks. Please solve the math puzzle below to proceed.</p>
        
        <div class="math-box">
            {num1} + {num2} = ?
        </div>
        
        <form action="/waf_captcha_verify" method="GET">
            <input type="hidden" name="r" value="{redirect_path}">
            <div class="input-group">
                <input type="number" name="ans" required placeholder="Masukkan jawaban Anda" autofocus autocomplete="off">
            </div>
            <button type="submit" class="btn">Verify & Continue</button>
        </form>
        
        {error_msg}
        
        <div class="footer">
            Protected by <strong>Cyber Nexus WAF</strong> (Anti-Bot Gateway)
        </div>
    </div>
</body>
</html>
"""

# HTML template for Identity Gateway (premium dark mode glassmorphism)
HTML_IDENTITY_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Identity Gateway — Cyber Nexus WAF</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #09090b;
            background: radial-gradient(circle at center, #0f172a 0%, #020617 100%);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #f4f4f5;
            text-align: center;
        }}
        .card {{
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(99, 102, 241, 0.15);
            border-radius: 16px;
            padding: 40px 30px;
            width: 100%;
            max-width: 380px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6);
        }}
        .logo-box {{
            margin-bottom: 25px;
        }}
        .logo-box svg {{
            width: 50px;
            height: 50px;
            fill: #6366f1;
        }}
        h1 {{
            font-size: 22px;
            font-weight: 700;
            margin: 0 0 8px 0;
            color: #ffffff;
            letter-spacing: -0.02em;
        }}
        p {{
            font-size: 13px;
            color: #a1a1aa;
            margin: 0 0 25px 0;
            line-height: 1.5;
        }}
        .input-group {{
            margin-bottom: 20px;
            text-align: left;
        }}
        .input-group label {{
            display: block;
            font-size: 11px;
            font-weight: 600;
            color: #818cf8;
            text-transform: uppercase;
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }}
        .input-group input {{
            width: 100%;
            padding: 12px;
            background: rgba(9, 9, 11, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: #ffffff;
            font-size: 15px;
            box-sizing: border-box;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        .input-group input:focus {{
            border-color: #6366f1;
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
        }}
        .btn {{
            width: 100%;
            padding: 12px;
            background: #6366f1;
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s, transform 0.1s;
        }}
        .btn:hover {{
            background: #4f46e5;
        }}
        .btn:active {{
            transform: scale(0.98);
        }}
        .error {{
            color: #f87171;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 8px;
            font-size: 12.5px;
            padding: 10px;
            margin-bottom: 20px;
            text-align: left;
        }}
        .footer {{
            font-size: 11px;
            color: #52525b;
            margin-top: 35px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo-box">
            <svg viewBox="0 0 24 24">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 6c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 12c-2.33 0-4.31-1.24-5.4-3.1.03-1.79 3.6-2.77 5.4-2.77 1.79 0 5.37.98 5.4 2.77-1.09 1.86-3.07 3.1-5.4 3.1z"/>
            </svg>
        </div>
        <h1>Identity Gateway</h1>
        <p>Akses ke halaman ini membutuhkan autentikasi keamanan. Silakan masukkan password akses Anda.</p>
        
        {error_html}
        
        <form action="/waf_identity_verify" method="POST">
            <input type="hidden" name="r" value="{redirect_path}">
            <div class="input-group">
                <label for="password">Gateway Password</label>
                <input type="password" id="password" name="password" required placeholder="••••••••" autofocus autocomplete="off">
            </div>
            <button type="submit" class="btn">Authenticate Access</button>
        </form>
        
        <div class="footer">
            Secured by <strong>Cyber Nexus Identity Gate</strong>
        </div>
    </div>
</body>
</html>
"""

def _obfuscate_html(html_str: str) -> str:
    import base64
    import random
    import string
    
    # Generate random strings for variable names
    var_payload = ''.join(random.choices(string.ascii_letters, k=8))
    var_parts = ''.join(random.choices(string.ascii_letters, k=8))
    var_res = ''.join(random.choices(string.ascii_letters, k=8))
    
    # Base64 encode the HTML
    b64_payload = base64.b64encode(html_str.encode('utf-8')).decode('utf-8')
    
    # Split base64 into random chunks
    chunks = []
    i = 0
    while i < len(b64_payload):
        chunk_size = random.randint(15, 35)
        chunks.append(b64_payload[i:i+chunk_size])
        i += chunk_size
        
    parts_js = ',\n                '.join(f'"{c}"' for c in chunks)
    
    obfuscated_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Cyber Nexus Protected Page</title>
    <script>
        (function() {{
            var {var_parts} = [
                {parts_js}
            ];
            var {var_payload} = {var_parts}.join('');
            var {var_res} = atob({var_payload});
            document.open();
            document.write({var_res});
            document.close();
        }})();
    </script>
</head>
<body>
    <noscript>This page is protected by Cyber Nexus WAF. Please enable JavaScript to access it.</noscript>
</body>
</html>"""
    return obfuscated_html


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

    def version_string(self):
        return "nginx/1.24.0"

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
            'vhost_type': 'proxy',
            'backend_host': self.backend_host,
            'backend_port': self.backend_port,
            'root_directory': '',
            'max_rps': self.max_rps,
            'learning_mode': self.learning_mode,
            'allowlist_ips': self.allowlist_ips,
            'allowlist_paths': self.allowlist_paths,
            'blacklist_ips': set(),
            'blacklist_countries': set(),
            'identity_enabled': False,
            'identity_password': '',
            'captcha_enabled': False,
            'obfuscation_enabled': False,
            'rules': ["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"]
        }
        
        hostname = hostname.lower()

        # 1. Search in local JSON configuration
        try:
            if os.path.exists(_LOCAL_VHOSTS_PATH):
                vhosts_list = []
                with open(_LOCAL_VHOSTS_PATH, 'r', encoding='utf-8') as f:
                    try:
                        vhosts_list = json.load(f)
                    except Exception:
                        vhosts_list = []
                
                match = None
                # Search exact match
                for vh in vhosts_list:
                    if vh.get('hostname', '').strip().lower() == hostname:
                        match = vh
                        break
                
                # Search subdomain wildcard match (e.g. *.azharmtq.my.id)
                if not match:
                    for vh in vhosts_list:
                        vh_host = vh.get('hostname', '').strip().lower()
                        if vh_host.startswith('*.'):
                            suffix = vh_host[2:]
                            if hostname.endswith('.' + suffix) or hostname == suffix:
                                match = vh
                                break
                
                # Search global wildcard match
                if not match:
                    for vh in vhosts_list:
                        if vh.get('hostname', '') == '*':
                            match = vh
                            break
                            
                if match:
                    al_ips = match.get('allowlist_ips', '')
                    al_paths = match.get('allowlist_paths', '')
                    bl_ips = match.get('blacklist_ips', '')
                    bl_countries = match.get('blacklist_countries', '')
                    return {
                        'vhost_type': match.get('vhost_type', 'proxy'),
                        'backend_host': match.get('backend_host', '127.0.0.1'),
                        'backend_port': int(match.get('backend_port', 8000)),
                        'root_directory': match.get('root_directory', ''),
                        'max_rps': int(match.get('max_rps', 10)),
                        'learning_mode': bool(match.get('learning_mode', False)),
                        'allowlist_ips': {ip.strip() for ip in al_ips.split(",") if ip.strip()} if isinstance(al_ips, str) else set(),
                        'allowlist_paths': [p.strip() for p in al_paths.split(",") if p.strip()] if isinstance(al_paths, str) else [],
                        'blacklist_ips': {ip.strip() for ip in bl_ips.split(",") if ip.strip()} if isinstance(bl_ips, str) else set(),
                        'blacklist_countries': {c.strip().upper() for c in bl_countries.split(",") if c.strip()} if isinstance(bl_countries, str) else set(),
                        'identity_enabled': bool(match.get('identity_enabled', False)),
                        'identity_password': match.get('identity_password', ''),
                        'captcha_enabled': bool(match.get('captcha_enabled', False)),
                        'obfuscation_enabled': bool(match.get('obfuscation_enabled', False)),
                        'rules': match.get('rules', [])
                    }
        except Exception as e:
            emit_line(f"[WAF] JSON config error: {e}")

        # 2. Fallback to SQLite DB
        try:
            conn = sqlite3.connect(_DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT hostname, backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules, vhost_type, root_directory, blacklist_ips, blacklist_countries, identity_enabled, identity_password, captcha_enabled, obfuscation_enabled FROM vhosts")
            rows = cur.fetchall()
            conn.close()

            match_row = None
            # Search exact match
            for r in rows:
                if r[0].lower() == hostname:
                    match_row = r
                    break
            
            # Search subdomain wildcard match (e.g. *.azharmtq.my.id)
            if not match_row:
                for r in rows:
                    pattern = r[0].lower()
                    if pattern.startswith('*.'):
                        suffix = pattern[2:]
                        if hostname.endswith('.' + suffix) or hostname == suffix:
                            match_row = r
                            break

            # Search global wildcard match
            if not match_row:
                for r in rows:
                    if r[0] == '*':
                        match_row = r
                        break

            if match_row:
                hn, bh, bp, mr, lm, al_ips, al_paths, r_str, vh_type, root_dir, bl_ips, bl_countries, id_en, id_pass, cap_en, obf_en = match_row
                try:
                    rules_list = json.loads(r_str) if r_str else []
                except Exception:
                    rules_list = []
                return {
                    'vhost_type': vh_type or 'proxy',
                    'backend_host': bh,
                    'backend_port': bp,
                    'root_directory': root_dir or '',
                    'max_rps': mr,
                    'learning_mode': bool(lm),
                    'allowlist_ips': {ip.strip() for ip in al_ips.split(",") if ip.strip()} if al_ips else set(),
                    'allowlist_paths': [p.strip() for p in al_paths.split(",") if p.strip()] if al_paths else [],
                    'blacklist_ips': {ip.strip() for ip in bl_ips.split(",") if ip.strip()} if bl_ips else set(),
                    'blacklist_countries': {c.strip().upper() for c in bl_countries.split(",") if c.strip()} if bl_countries else set(),
                    'identity_enabled': bool(id_en),
                    'identity_password': id_pass or '',
                    'captcha_enabled': bool(cap_en),
                    'obfuscation_enabled': bool(obf_en),
                    'rules': rules_list
                }
        except Exception:
            pass
        return default_config

    def _proxy_to_backend_custom(self, ip: str, body: bytes, decoded_path: str, decoded_body: str, headers_text: str, config: dict):
        bh = config['backend_host']
        bp = config['backend_port']
        url = f'http://{bh}:{bp}{self.path}'
        headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
        
        # Forward original Host name to backend via X-Forwarded headers
        headers['X-Forwarded-Host'] = self.headers.get('Host', '')
        if 'X-Forwarded-For' not in headers:
            headers['X-Forwarded-For'] = ip
        else:
            headers['X-Forwarded-For'] = f"{headers['X-Forwarded-For']}, {self.client_address[0]}"
            
        if 'X-Forwarded-Proto' not in headers:
            is_https = False
            if hasattr(self.server, 'ssl_context') and self.server.ssl_context:
                is_https = True
            headers['X-Forwarded-Proto'] = 'https' if is_https else 'http'

        try:
            resp = requests.request(self.command, url, headers=headers, data=body, allow_redirects=False, timeout=10)
            
            content_bytes = resp.content or b''
            content_type = resp.headers.get('Content-Type', '').lower()
            is_html = 'text/html' in content_type
            
            if config.get('obfuscation_enabled') and is_html and content_bytes:
                try:
                    html_str = content_bytes.decode('utf-8', errors='replace')
                    obfuscated_html = _obfuscate_html(html_str)
                    content_bytes = obfuscated_html.encode('utf-8')
                except Exception as e:
                    self._log(f"Failed to obfuscate proxy HTML: {e}")

            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() in ('connection', 'keep-alive', 'transfer-encoding', 'upgrade'):
                    continue
                if k.lower() == 'content-length':
                    self.send_header(k, str(len(content_bytes)))
                else:
                    self.send_header(k, v)
                    
            if 'content-length' not in [hk.lower() for hk in resp.headers.keys()] and content_bytes:
                self.send_header('Content-Length', str(len(content_bytes)))
                
            self.end_headers()
            if content_bytes:
                self.wfile.write(content_bytes)
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

    def _serve_static_directory(self, ip: str, root_dir: str, decoded_path: str, config: dict):
        import mimetypes
        
        path_only = decoded_path.split('?')[0].split('#')[0]
        if path_only.startswith('/'):
            path_only = path_only[1:]
            
        safe_path = os.path.normpath(os.path.join(root_dir, path_only))
        norm_root = os.path.normpath(root_dir)
        if not safe_path.startswith(norm_root):
            self.send_response(403)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Forbidden: Path Traversal Detected")
            log_event(ip, "block:static_traversal", decoded_path, "", "")
            return
            
        if os.path.isdir(safe_path):
            safe_path = os.path.join(safe_path, "index.html")
            
        if not os.path.isfile(safe_path):
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Not Found")
            log_event(ip, "detect:404", decoded_path, "", "")
            return
            
        mime_type, _ = mimetypes.guess_type(safe_path)
        if not mime_type:
            mime_type = "application/octet-stream"
            
        try:
            with open(safe_path, "rb") as f:
                content = f.read()
                
            # Dynamic HTML/JS obfuscation
            if config.get('obfuscation_enabled') and mime_type == 'text/html' and content:
                try:
                    html_str = content.decode('utf-8', errors='replace')
                    obfuscated_html = _obfuscate_html(html_str)
                    content = obfuscated_html.encode('utf-8')
                except Exception as e:
                    self._log(f"Failed to obfuscate static HTML: {e}")

            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            log_event(ip, "allow:static", decoded_path, "", "")
            self._log(f"{ip} -> GET {decoded_path} served static file: {safe_path} (200)")
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Internal Server Error: {e}".encode('utf-8'))
            self._log(f"{ip} -> static file read error: {e}")
    def _forward_request(self, ip: str, body: bytes, decoded_path: str, decoded_body: str, headers_text: str, config: dict):
        if config.get('vhost_type') == 'static' and config.get('root_directory'):
            self._serve_static_directory(ip, config['root_directory'], decoded_path, config)
        else:
            self._proxy_to_backend_custom(ip, body, decoded_path, decoded_body, headers_text, config)

    def _proxy_request(self):
        try:
            self._proxy_request_internal()
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self._log(f"CRITICAL: Secure by default triggered. Error in WAFHandler processing: {e}\n{tb}")
            try:
                self.send_response(500)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                err_body = """<!DOCTYPE html>
<html>
<head>
    <title>Critical Security Error — Cyber Nexus WAF</title>
    <style>
        body {
            background-color: #09090b;
            color: #f87171;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            text-align: center;
        }
        .card {
            background: rgba(239, 68, 68, 0.05);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 12px;
            padding: 40px;
            max-width: 450px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }
        h1 { font-size: 20px; font-weight: 700; margin: 0 0 10px 0; color: #f87171; }
        p { font-size: 13.5px; color: #a1a1aa; line-height: 1.5; margin: 0; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🔒 Security Lockdown</h1>
        <p>A system error occurred in the security processing layer. To prevent bypass, the connection has been blocked. Please contact the administrator.</p>
    </div>
</body>
</html>"""
                self.wfile.write(err_body.encode('utf-8'))
            except Exception:
                pass

    def _proxy_request_internal(self):
        # Resolve real client IP (supporting Cloudflare Tunnel, Nginx, Ngrok, etc.)
        ip = self.headers.get('CF-Connecting-IP')
        if not ip:
            xff = self.headers.get('X-Forwarded-For')
            if xff:
                ip = xff.split(',')[0].strip()
        if not ip:
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

        # 1. Handle CAPTCHA Verification Endpoint
        if decoded_path.startswith('/waf_captcha_verify'):
            qs = parse_qs(urlsplit(self.path).query)
            ans = qs.get('ans', [''])[0].strip()
            redirect_path = qs.get('r', ['/'])[0]
            
            # Read challenge cookie
            challenge_cookie = None
            cookies = self.headers.get('Cookie', '')
            for cookie in cookies.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('waf_captcha_challenge='):
                    challenge_cookie = cookie.split('=', 1)[1]
                    break
                    
            secret = "nexus_captcha_salt"
            expected_hash = hashlib.md5((str(ans) + secret).encode('utf-8')).hexdigest()
            
            if challenge_cookie and challenge_cookie == expected_hash:
                # Success! Set bypass cookie and redirect
                self.send_response(302)
                self.send_header('Location', redirect_path)
                self.send_header('Set-Cookie', 'waf_captcha_passed=1; Path=/; Max-Age=3600')
                self.send_header('Set-Cookie', 'waf_captcha_challenge=; Path=/; Max-Age=0')
                self.end_headers()
                self._log(f"{ip} -> solved CAPTCHA, redirecting to {redirect_path}")
                return
            else:
                # Failure: serve captcha page again with error
                num1 = random.randint(1, 20)
                num2 = random.randint(1, 20)
                ans_correct = num1 + num2
                new_challenge = hashlib.md5((str(ans_correct) + secret).encode('utf-8')).hexdigest()
                
                error_msg = '<div class="error">Jawaban salah. Silakan coba lagi.</div>'
                body_html = HTML_CAPTCHA_TEMPLATE.format(
                    num1=num1,
                    num2=num2,
                    redirect_path=redirect_path,
                    error_msg=error_msg
                )
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Set-Cookie', f'waf_captcha_challenge={new_challenge}; Path=/; Max-Age=300')
                self.end_headers()
                self.wfile.write(body_html.encode('utf-8'))
                self._log(f"{ip} -> failed CAPTCHA puzzle submission")
                return

        # 2. Handle Identity Verification Endpoint
        if decoded_path.startswith('/waf_identity_verify'):
            qs = parse_qs(urlsplit(self.path).query)
            redirect_path = qs.get('r', ['/'])[0]
            
            post_vars = parse_qs(decoded_body)
            submitted_password = post_vars.get('password', [''])[0].strip()
            
            vhost_password = config.get('identity_password', '')
            if submitted_password == vhost_password:
                secret = "nexus_identity_salt"
                token_val = hashlib.sha256((vhost_password + secret).encode('utf-8')).hexdigest()
                
                self.send_response(302)
                self.send_header('Location', redirect_path)
                self.send_header('Set-Cookie', f'waf_identity_token={token_val}; Path=/; Max-Age=86400')
                self.end_headers()
                self._log(f"{ip} -> authenticated identity gate, redirecting to {redirect_path}")
                return
            else:
                error_html = '<div class="error">Password salah. Akses ditolak.</div>'
                body_html = HTML_IDENTITY_TEMPLATE.format(
                    redirect_path=redirect_path,
                    error_html=error_html
                )
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(body_html.encode('utf-8'))
                self._log(f"{ip} -> failed identity gate authentication")
                return

        # Check IP blacklist
        blacklist_ips = config.get('blacklist_ips', set())
        if ip in blacklist_ips:
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
            err_body = HTML_BLOCK_TEMPLATE.format(rule='ip_blacklisted', ip=ip, path=decoded_path, ts=ts)
            self.send_response(403)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(err_body.encode('utf-8'))
            self._log(f"{ip} -> 403 blocked by IP Blacklist")
            try:
                log_event(ip, 'ip_blacklisted', decoded_path, decoded_body, headers_text)
            except Exception:
                pass
            return

        # Check Geo-Blocking
        blacklist_countries = config.get('blacklist_countries', set())
        if blacklist_countries:
            geo = _resolve_country(ip, decoded_path)
            country_code = geo['code'].upper()
            if country_code in blacklist_countries:
                ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
                err_body = HTML_BLOCK_TEMPLATE.format(rule=f'geo_blocked_{country_code}', ip=ip, path=decoded_path, ts=ts)
                self.send_response(403)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(err_body.encode('utf-8'))
                self._log(f"{ip} -> 403 blocked by Geo-Blocking ({country_code})")
                try:
                    log_event(ip, f'geo_blocked_{country_code}', decoded_path, decoded_body, headers_text)
                except Exception:
                    pass
                return

        # Check Identity Gateway
        if config.get('identity_enabled'):
            cookies = self.headers.get('Cookie', '')
            identity_token = None
            for cookie in cookies.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('waf_identity_token='):
                    identity_token = cookie.split('=', 1)[1]
                    break
                    
            vhost_password = config.get('identity_password', '')
            secret = "nexus_identity_salt"
            expected_token = hashlib.sha256((vhost_password + secret).encode('utf-8')).hexdigest()
            
            if not identity_token or identity_token != expected_token:
                body_html = HTML_IDENTITY_TEMPLATE.format(
                    redirect_path=self.path,
                    error_html=''
                )
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(body_html.encode('utf-8'))
                self._log(f"{ip} -> intercepted by Identity Gateway (path: {self.path})")
                return

        # Check IP allowlist
        if ip in allowlist_ips:
            self._log(f"{ip} -> bypassed (IP in allowlist)")
            self._forward_request(ip, body, decoded_path, decoded_body, headers_text, config)
            return

        # Check Path allowlist
        for p in allowlist_paths:
            if decoded_path.startswith(p):
                self._log(f"{ip} -> bypassed (Path {p} in allowlist)")
                self._forward_request(ip, body, decoded_path, decoded_body, headers_text, config)
                return

        # Read CAPTCHA bypass cookie if any
        cookies = self.headers.get('Cookie', '')
        captcha_passed = False
        for cookie in cookies.split(';'):
            cookie = cookie.strip()
            if cookie.startswith('waf_captcha_passed='):
                if cookie.split('=', 1)[1] == '1':
                    captcha_passed = True
                break

        # Rate Limiting
        if self._rate_limit_exceeded_custom(ip, max_rps):
            if config.get('captcha_enabled') and not captcha_passed:
                num1 = random.randint(1, 20)
                num2 = random.randint(1, 20)
                ans_correct = num1 + num2
                secret = "nexus_captcha_salt"
                new_challenge = hashlib.md5((str(ans_correct) + secret).encode('utf-8')).hexdigest()
                
                body_html = HTML_CAPTCHA_TEMPLATE.format(
                    num1=num1,
                    num2=num2,
                    redirect_path=self.path,
                    error_msg=''
                )
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Set-Cookie', f'waf_captcha_challenge={new_challenge}; Path=/; Max-Age=300')
                self.end_headers()
                self.wfile.write(body_html.encode('utf-8'))
                self._log(f"{ip} -> rate limit exceeded, serving CAPTCHA challenge")
                return
            else:
                ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
                err_body = HTML_BLOCK_TEMPLATE.format(rule='rate_limiting_exceeded', ip=ip, path=decoded_path, ts=ts)
                
                self.send_response(429)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
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
                self._forward_request(ip, body, decoded_path, decoded_body, headers_text, config)
            else:
                try:
                    log_event(ip, matched, decoded_path, decoded_body, headers_text)
                except Exception:
                    pass
                
                if config.get('captcha_enabled') and not captcha_passed:
                    num1 = random.randint(1, 20)
                    num2 = random.randint(1, 20)
                    ans_correct = num1 + num2
                    secret = "nexus_captcha_salt"
                    new_challenge = hashlib.md5((str(ans_correct) + secret).encode('utf-8')).hexdigest()
                    
                    body_html = HTML_CAPTCHA_TEMPLATE.format(
                        num1=num1,
                        num2=num2,
                        redirect_path=self.path,
                        error_msg=''
                    )
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Set-Cookie', f'waf_captcha_challenge={new_challenge}; Path=/; Max-Age=300')
                    self.end_headers()
                    self.wfile.write(body_html.encode('utf-8'))
                    self._log(f"{ip} -> rule matched {matched}, serving CAPTCHA challenge")
                    return
                else:
                    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
                    err_body = HTML_BLOCK_TEMPLATE.format(rule=matched, ip=ip, path=decoded_path, ts=ts)
                    
                    self.send_response(403)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(err_body.encode('utf-8'))
                    self._log(f"{ip} -> 403 blocked by {matched}")
            return

        self._forward_request(ip, body, decoded_path, decoded_body, headers_text, config)

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
    cert_path = os.path.join(_WAF_DATA_DIR, "waf_cert.pem")
    key_path = os.path.join(_WAF_DATA_DIR, "waf_key.pem")

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
                  ssl_cert_path: str = "", ssl_key_path: str = "", blacklist_ips: str = "",
                  blacklist_countries: str = "", identity_enabled: bool = False, identity_password: str = "",
                  captcha_enabled: bool = False, obfuscation_enabled: bool = False):
    global _SERVER, _THREAD
    _init_db_and_default_vhost(backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths,
                               blacklist_ips, blacklist_countries, identity_enabled, identity_password,
                               captcha_enabled, obfuscation_enabled)
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
        ssl_cert_path: str = '', ssl_key_path: str = '', blacklist_ips: str = '',
        blacklist_countries: str = '', identity_enabled: str = 'false', identity_password: str = '',
        captcha_enabled: str = 'false', obfuscation_enabled: str = 'false') -> dict:
    """Start WAF proxy in background and return status dict."""
    global _MAX_LOG_MB
    try:
        lp = int(listen_port)
        bp = int(backend_port)
        mr = int(max_rps)
        _MAX_LOG_MB = float(max_log_mb)
        lm = str(learning_mode).lower() in ('1', 'true', 'yes')
        se = str(ssl_enabled).lower() in ('1', 'true', 'yes')
        id_en = str(identity_enabled).lower() in ('1', 'true', 'yes')
        cap_en = str(captcha_enabled).lower() in ('1', 'true', 'yes')
        obf_en = str(obfuscation_enabled).lower() in ('1', 'true', 'yes')
    except Exception:
        emit_line('[WAF] Invalid numeric argument')
        return {'module': 'waf', 'status': 'error', 'error': 'invalid args'}

    success = _start_server(lp, backend, bp, mr, learning_mode=lm, allowlist_ips=allowlist_ips,
                            allowlist_paths=allowlist_paths, ssl_enabled=se, ssl_cert_type=ssl_cert_type,
                            ssl_cert_path=ssl_cert_path, ssl_key_path=ssl_key_path, blacklist_ips=blacklist_ips,
                            blacklist_countries=blacklist_countries, identity_enabled=id_en, identity_password=identity_password,
                            captcha_enabled=cap_en, obfuscation_enabled=obf_en)
    if not success:
        return {'module': 'waf', 'status': 'error', 'error': f'bind_failed:{listen_port}'}

    return {'module': 'waf', 'status': 'running', 'listen_port': lp, 'backend_host': backend, 'backend_port': bp, 'max_log_mb': _MAX_LOG_MB}


def run_foreground(listen_port: str = '8080', backend: str = '127.0.0.1', backend_port: str = '8000', max_rps: str = '10',
                   max_log_mb: str = '10', learning_mode: str = 'false', allowlist_ips: str = '', allowlist_paths: str = '',
                   ssl_enabled: str = 'false', ssl_cert_type: str = 'self_signed',
                   ssl_cert_path: str = '', ssl_key_path: str = '', blacklist_ips: str = '',
                   blacklist_countries: str = '', identity_enabled: str = 'false', identity_password: str = '',
                   captcha_enabled: str = 'false', obfuscation_enabled: str = 'false') -> dict:
    """Start WAF and block in the current process."""
    global _MAX_LOG_MB
    try:
        lp = int(listen_port)
        bp = int(backend_port)
        mr = int(max_rps)
        _MAX_LOG_MB = float(max_log_mb)
        lm = str(learning_mode).lower() in ('1', 'true', 'yes')
        se = str(ssl_enabled).lower() in ('1', 'true', 'yes')
        id_en = str(identity_enabled).lower() in ('1', 'true', 'yes')
        cap_en = str(captcha_enabled).lower() in ('1', 'true', 'yes')
        obf_en = str(obfuscation_enabled).lower() in ('1', 'true', 'yes')
    except Exception:
        emit_line('[WAF] Invalid numeric argument')
        return {'module': 'waf', 'status': 'error', 'error': 'invalid args'}

    success = _start_server(lp, backend, bp, mr, learning_mode=lm, allowlist_ips=allowlist_ips,
                            allowlist_paths=allowlist_paths, ssl_enabled=se, ssl_cert_type=ssl_cert_type,
                            ssl_cert_path=ssl_cert_path, ssl_key_path=ssl_key_path, blacklist_ips=blacklist_ips,
                            blacklist_countries=blacklist_countries, identity_enabled=id_en, identity_password=identity_password,
                            captcha_enabled=cap_en, obfuscation_enabled=obf_en)
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


def _resolve_country(ip: str, path: str = "") -> dict:
    # Default fallback
    cc = "ID"
    country_name = "Indonesia"
    
    # Heuristics for private/local IP to make localhost testing gorgeous!
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
        # Determine country dynamically from path hash to get multiple countries for demo
        h = sum(ord(c) for c in path) if path else 0
        countries = [
            ("ID", "Indonesia"),
            ("US", "United States"),
            ("SG", "Singapore"),
            ("NL", "Netherlands"),
            ("DE", "Germany"),
            ("CN", "China"),
            ("RU", "Russia"),
            ("JP", "Japan"),
            ("GB", "United Kingdom"),
            ("FR", "France"),
            ("BR", "Brazil"),
            ("AU", "Australia")
        ]
        cc, country_name = countries[h % len(countries)]
    else:
        # Simple public IP ranges heuristic
        try:
            parts = ip.split('.')
            if len(parts) >= 1 and parts[0].isdigit():
                first_octet = int(parts[0])
                if 1 <= first_octet <= 50:
                    cc, country_name = "US", "United States"
                elif 51 <= first_octet <= 100:
                    cc, country_name = "GB", "United Kingdom"
                elif 101 <= first_octet <= 120:
                    cc, country_name = "SG", "Singapore"
                elif 121 <= first_octet <= 140:
                    cc, country_name = "NL", "Netherlands"
                elif 141 <= first_octet <= 160:
                    cc, country_name = "DE", "Germany"
                elif 161 <= first_octet <= 180:
                    cc, country_name = "CN", "China"
                elif 181 <= first_octet <= 200:
                    cc, country_name = "RU", "Russia"
                elif 201 <= first_octet <= 220:
                    cc, country_name = "JP", "Japan"
                elif 221 <= first_octet <= 239:
                    cc, country_name = "FR", "France"
        except Exception:
            pass
            
    return {"code": cc, "name": country_name}


_LOG_QUEUE = queue.Queue(maxsize=10000)

def _start_log_worker():
    def worker():
        while True:
            try:
                rec = _LOG_QUEUE.get()
                if rec is None:
                    break
                
                conn = sqlite3.connect(_DB_PATH)
                cur = conn.cursor()
                cur.execute('INSERT INTO events (ts, ip, rule, path, payload, headers, country_code, country_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                            (rec['ts'], rec['ip'], rec['rule'], rec['path'], rec['payload'], rec['headers'], rec['country_code'], rec['country_name']))
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
                    pass

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
                _LOG_QUEUE.task_done()
            except Exception as e:
                try:
                    emit_line(f"[WAF] Log worker error: {e}")
                except Exception:
                    pass
    t = threading.Thread(target=worker, daemon=True)
    t.start()

# Jalankan worker thread
_start_log_worker()

def log_event(ip: str, rule: str, path: str, payload: str, headers: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    geo = _resolve_country(ip, path)
    rec = {
        'ts': ts,
        'ip': ip,
        'rule': rule,
        'path': path,
        'payload': payload,
        'headers': headers,
        'country_code': geo['code'],
        'country_name': geo['name']
    }
    _IN_MEMORY_LOGS.append(rec)
    if len(_IN_MEMORY_LOGS) > _LOG_CAPACITY:
        del _IN_MEMORY_LOGS[0: len(_IN_MEMORY_LOGS) - _LOG_CAPACITY]
    try:
        _LOG_QUEUE.put_nowait(rec)
    except queue.Full:
        try:
            emit_line("[WAF] Log queue full, dropping event log to prevent backpressure")
        except Exception:
            pass


def get_logs(limit: int = 200) -> dict:
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        
        # 1. Get recent logs
        cur.execute('SELECT ts, ip, rule, path, payload, country_code, country_name FROM events ORDER BY id DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        logs_out = [{
            'ts': r[0],
            'ip': r[1],
            'rule': r[2],
            'path': r[3],
            'payload': r[4],
            'country_code': r[5] or "ID",
            'country_name': r[6] or "Indonesia"
        } for r in rows]

        # 2. Get total requests
        cur.execute('SELECT COUNT(1) FROM events')
        total_requests = cur.fetchone()[0]

        # 3. Get total blocked attacks
        cur.execute("SELECT COUNT(1) FROM events WHERE rule NOT LIKE 'allow:%' AND rule NOT LIKE 'detect:%'")
        blocked_attacks = cur.fetchone()[0]

        # 4. Get category distribution
        cur.execute("SELECT rule, COUNT(1) FROM events WHERE rule NOT LIKE 'allow:%' AND rule NOT LIKE 'detect:%' GROUP BY rule")
        cat_rows = cur.fetchall()
        categories = {
            'sql_injection': 0,
            'xss': 0,
            'path_traversal': 0,
            'cmd_injection': 0,
            'scanner_detected': 0,
            'custom': 0
        }
        for r_name, r_count in cat_rows:
            if r_name in categories:
                categories[r_name] = r_count
            else:
                categories['custom'] += r_count

        # 5. Get top IP threat stats (group by IP, limit to top 10)
        cur.execute("""
            SELECT ip, country_code, country_name, COUNT(1),
                   SUM(CASE WHEN rule NOT LIKE 'allow:%' AND rule NOT LIKE 'detect:%' THEN 1 ELSE 0 END)
            FROM events
            GROUP BY ip
            ORDER BY COUNT(1) DESC
            LIMIT 10
        """)
        ip_rows = cur.fetchall()
        ip_stats = []
        for r_ip, r_cc, r_cn, r_total, r_blocked in ip_rows:
            ip_stats.append({
                'ip': r_ip,
                'country_code': r_cc or 'ID',
                'country_name': r_cn or 'Indonesia',
                'total': r_total,
                'blocked': r_blocked or 0
            })
            
        conn.close()
        
        return {
            'module': 'waf',
            'logs': logs_out,
            'stats': {
                'total_requests': total_requests,
                'blocked_attacks': blocked_attacks,
                'categories': categories,
                'ip_stats': ip_stats
            }
        }
    except Exception as e:
        emit_line(f"[WAF] get_logs error: {e}")
        fallback_logs = []
        for r in reversed(_IN_MEMORY_LOGS[-limit:]):
            fallback_logs.append({
                'ts': r['ts'],
                'ip': r['ip'],
                'rule': r['rule'],
                'path': r['path'],
                'payload': r['payload'],
                'country_code': r.get('country_code', 'ID'),
                'country_name': r.get('country_name', 'Indonesia')
            })
            
        # In-memory stats calculations
        total_requests = len(_IN_MEMORY_LOGS)
        blocked_attacks = sum(1 for l in _IN_MEMORY_LOGS if not l['rule'].startswith('allow:') and not l['rule'].startswith('detect:'))
        categories = {
            'sql_injection': 0,
            'xss': 0,
            'path_traversal': 0,
            'cmd_injection': 0,
            'scanner_detected': 0,
            'custom': 0
        }
        ip_stats_map = {}
        for l in _IN_MEMORY_LOGS:
            is_blocked = not l['rule'].startswith('allow:') and not l['rule'].startswith('detect:')
            if is_blocked:
                r_name = l['rule']
                if r_name in categories:
                    categories[r_name] += 1
                else:
                    categories['custom'] += 1
            
            ip = l['ip']
            if ip not in ip_stats_map:
                ip_stats_map[ip] = {
                    'ip': ip,
                    'country_code': l.get('country_code', 'ID'),
                    'country_name': l.get('country_name', 'Indonesia'),
                    'total': 0,
                    'blocked': 0
                }
            ip_stats_map[ip]['total'] += 1
            if is_blocked:
                ip_stats_map[ip]['blocked'] += 1
                
        ip_stats = sorted(ip_stats_map.values(), key=lambda x: x['total'], reverse=True)[:10]
        
        return {
            'module': 'waf',
            'logs': fallback_logs,
            'stats': {
                'total_requests': total_requests,
                'blocked_attacks': blocked_attacks,
                'categories': categories,
                'ip_stats': ip_stats
            }
        }


def clear_logs() -> dict:
    global _IN_MEMORY_LOGS
    _IN_MEMORY_LOGS = []
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM events")
        conn.commit()
        cur.execute("VACUUM")
        conn.commit()
        conn.close()
        return {'module': 'waf', 'status': 'ok'}
    except Exception as e:
        emit_line(f"[WAF] clear_logs error: {e}")
        return {'module': 'waf', 'status': 'error', 'error': str(e)}


# --- Virtual Hosts CRUD APIs ---

def get_vhosts() -> dict:
    _init_local_vhosts_file()
    out = []
    seen_hostnames = set()
    
    # 1. Load from JSON
    try:
        if os.path.exists(_LOCAL_VHOSTS_PATH):
            with open(_LOCAL_VHOSTS_PATH, 'r', encoding='utf-8') as f:
                vhosts_list = json.load(f)
            for vh in vhosts_list:
                hostname = vh.get('hostname', '').strip()
                if hostname:
                    out.append({
                        'id': vh.get('id', hash(hostname)),
                        'hostname': hostname,
                        'vhost_type': vh.get('vhost_type', 'proxy'),
                        'backend_host': vh.get('backend_host', '127.0.0.1'),
                        'backend_port': str(vh.get('backend_port', 8000)),
                        'root_directory': vh.get('root_directory', ''),
                        'max_rps': vh.get('max_rps', 10),
                        'learning_mode': bool(vh.get('learning_mode', False)),
                        'allowlist_ips': vh.get('allowlist_ips', ''),
                        'allowlist_paths': vh.get('allowlist_paths', ''),
                        'blacklist_ips': vh.get('blacklist_ips', ''),
                        'blacklist_countries': vh.get('blacklist_countries', ''),
                        'identity_enabled': bool(vh.get('identity_enabled', False)),
                        'identity_password': vh.get('identity_password', ''),
                        'captcha_enabled': bool(vh.get('captcha_enabled', False)),
                        'obfuscation_enabled': bool(vh.get('obfuscation_enabled', False)),
                        'rules': vh.get('rules', [])
                    })
                    seen_hostnames.add(hostname.lower())
    except Exception as e:
        emit_line(f"[WAF] get_vhosts JSON error: {e}")

    # 2. Load from DB (compatibility fallback)
    try:
        _init_db()
        conn = sqlite3.connect(_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, hostname, backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules, vhost_type, root_directory, blacklist_ips, blacklist_countries, identity_enabled, identity_password, captcha_enabled, obfuscation_enabled FROM vhosts")
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            hostname = r[1].strip()
            if hostname.lower() not in seen_hostnames:
                out.append({
                    'id': r[0],
                    'hostname': hostname,
                    'vhost_type': r[9] or 'proxy',
                    'backend_host': r[2],
                    'backend_port': str(r[3]),
                    'root_directory': r[10] or '',
                    'max_rps': r[4],
                    'learning_mode': bool(r[5]),
                    'allowlist_ips': r[6] or "",
                    'allowlist_paths': r[7] or "",
                    'blacklist_ips': r[11] or "",
                    'blacklist_countries': r[12] or "",
                    'identity_enabled': bool(r[13]),
                    'identity_password': r[14] or "",
                    'captcha_enabled': bool(r[15]),
                    'obfuscation_enabled': bool(r[16]),
                    'rules': json.loads(r[8]) if r[8] else []
                })
                seen_hostnames.add(hostname.lower())
    except Exception as e:
        emit_line(f"[WAF] get_vhosts DB error: {e}")

    return {'status': 'ok', 'vhosts': out}


def save_vhost(hostname: str, backend_host: str, backend_port: str, max_rps: str,
               learning_mode: str, allowlist_ips: str, allowlist_paths: str, rules_json: str,
               vhost_type: str = 'proxy', root_directory: str = '', blacklist_ips: str = '',
               blacklist_countries: str = '', identity_enabled: str = 'false', identity_password: str = '',
               captcha_enabled: str = 'false', obfuscation_enabled: str = 'false') -> dict:
    _init_local_vhosts_file()
    try:
        hostname = hostname.strip()
        bp = int(backend_port) if backend_port else 8000
        mr = int(max_rps) if max_rps else 10
        lm = str(learning_mode).lower() in ('1', 'true', 'yes')
        id_en = str(identity_enabled).lower() in ('1', 'true', 'yes')
        cap_en = str(captcha_enabled).lower() in ('1', 'true', 'yes')
        obf_en = str(obfuscation_enabled).lower() in ('1', 'true', 'yes')
        rules_list = json.loads(rules_json) if rules_json else []

        # 1. Save to JSON
        vhosts_list = []
        if os.path.exists(_LOCAL_VHOSTS_PATH):
            with open(_LOCAL_VHOSTS_PATH, 'r', encoding='utf-8') as f:
                try:
                    vhosts_list = json.load(f)
                except Exception:
                    vhosts_list = []

        found = False
        for i, vh in enumerate(vhosts_list):
            if vh.get('hostname', '').strip().lower() == hostname.lower():
                vhosts_list[i] = {
                    'id': vh.get('id', hash(hostname)),
                    'hostname': hostname,
                    'vhost_type': vhost_type,
                    'backend_host': backend_host,
                    'backend_port': bp,
                    'root_directory': root_directory,
                    'max_rps': mr,
                    'learning_mode': lm,
                    'allowlist_ips': allowlist_ips,
                    'allowlist_paths': allowlist_paths,
                    'blacklist_ips': blacklist_ips,
                    'blacklist_countries': blacklist_countries,
                    'identity_enabled': id_en,
                    'identity_password': identity_password,
                    'captcha_enabled': cap_en,
                    'obfuscation_enabled': obf_en,
                    'rules': rules_list
                }
                found = True
                break
        
        if not found:
            vhosts_list.append({
                'id': int(time.time() * 1000),
                'hostname': hostname,
                'vhost_type': vhost_type,
                'backend_host': backend_host,
                'backend_port': bp,
                'root_directory': root_directory,
                'max_rps': mr,
                'learning_mode': lm,
                'allowlist_ips': allowlist_ips,
                'allowlist_paths': allowlist_paths,
                'blacklist_ips': blacklist_ips,
                'blacklist_countries': blacklist_countries,
                'identity_enabled': id_en,
                'identity_password': identity_password,
                'captcha_enabled': cap_en,
                'obfuscation_enabled': obf_en,
                'rules': rules_list
            })

        with open(_LOCAL_VHOSTS_PATH, 'w', encoding='utf-8') as f:
            json.dump(vhosts_list, f, indent=4)

        # 2. SQLite backup
        try:
            _init_db()
            conn = sqlite3.connect(_DB_PATH)
            cur = conn.cursor()
            db_lm = 1 if lm else 0
            db_id_en = 1 if id_en else 0
            db_cap_en = 1 if cap_en else 0
            db_obf_en = 1 if obf_en else 0
            rules_str = json.dumps(rules_list)
            cur.execute(
                """
                INSERT INTO vhosts (hostname, backend_host, backend_port, max_rps, learning_mode, allowlist_ips, allowlist_paths, rules, vhost_type, root_directory, blacklist_ips, blacklist_countries, identity_enabled, identity_password, captcha_enabled, obfuscation_enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hostname) DO UPDATE SET
                    backend_host=excluded.backend_host,
                    backend_port=excluded.backend_port,
                    max_rps=excluded.max_rps,
                    learning_mode=excluded.learning_mode,
                    allowlist_ips=excluded.allowlist_ips,
                    allowlist_paths=excluded.allowlist_paths,
                    rules=excluded.rules,
                    vhost_type=excluded.vhost_type,
                    root_directory=excluded.root_directory,
                    blacklist_ips=excluded.blacklist_ips,
                    blacklist_countries=excluded.blacklist_countries,
                    identity_enabled=excluded.identity_enabled,
                    identity_password=excluded.identity_password,
                    captcha_enabled=excluded.captcha_enabled,
                    obfuscation_enabled=excluded.obfuscation_enabled
                """,
                (hostname, backend_host, bp, mr, db_lm, allowlist_ips, allowlist_paths, rules_str, vhost_type, root_directory, blacklist_ips, blacklist_countries, db_id_en, identity_password, db_cap_en, db_obf_en)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            emit_line(f"[WAF] save_vhost DB backup error: {e}")

        return {'status': 'ok'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def delete_vhost(hostname: str) -> dict:
    _init_local_vhosts_file()
    hostname = hostname.strip()
    try:
        # 1. Delete from JSON
        if os.path.exists(_LOCAL_VHOSTS_PATH):
            with open(_LOCAL_VHOSTS_PATH, 'r', encoding='utf-8') as f:
                vhosts_list = json.load(f)
            vhosts_list = [vh for vh in vhosts_list if vh.get('hostname', '').strip().lower() != hostname.lower()]
            with open(_LOCAL_VHOSTS_PATH, 'w', encoding='utf-8') as f:
                json.dump(vhosts_list, f, indent=4)

        # 2. Delete from DB
        try:
            _init_db()
            conn = sqlite3.connect(_DB_PATH)
            cur = conn.cursor()
            cur.execute("DELETE FROM vhosts WHERE hostname = ?", (hostname,))
            conn.commit()
            conn.close()
        except Exception:
            pass

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


# Background memory cleanup for rate limiter IP buckets (stale IPs eviction)
def _start_rate_limiter_cleanup():
    def cleanup():
        while True:
            time.sleep(60)
            try:
                now = time.time()
                # Copy keys list to prevent RuntimeError
                keys = list(WAFHandler.ip_buckets.keys())
                for ip in keys:
                    bucket = WAFHandler.ip_buckets.get(ip)
                    if bucket is not None:
                        # Purge elements older than 300 seconds (TTL)
                        while bucket and bucket[0] < now - 300:
                            bucket.pop(0)
                        if not bucket:
                            WAFHandler.ip_buckets.pop(ip, None)
            except Exception:
                pass
    t = threading.Thread(target=cleanup, daemon=True)
    t.start()

# Start the rate limiter eviction worker
_start_rate_limiter_cleanup()

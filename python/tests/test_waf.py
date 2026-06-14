import unittest
import urllib.request
import urllib.error
import threading
import time
import socket
import ssl
import http.server
import socketserver
import os
import json
import sqlite3
import sys

# Add python directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import waf

class MockBackendHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress console logging during tests
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "backend_ok", "host": self.headers.get("Host")}).encode('utf-8'))

class TestWAF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_port = cls.get_free_port()
        cls.backend_server = socketserver.TCPServer(('127.0.0.1', cls.backend_port), MockBackendHandler)
        cls.backend_thread = threading.Thread(target=cls.backend_server.serve_forever, daemon=True)
        cls.backend_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.backend_server.shutdown()
        cls.backend_server.server_close()

    @staticmethod
    def get_free_port():
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def setUp(self):
        waf.stop()

    def tearDown(self):
        waf.stop()

    def test_waf_lifecycle_and_blocking(self):
        listen_port = self.get_free_port()
        res = waf.run(
            listen_port=str(listen_port),
            backend='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='100',
            learning_mode='false'
        )
        self.assertEqual(res.get('status'), 'running')
        time.sleep(0.5)

        # Test normal request gets proxied
        url = f"http://127.0.0.1:{listen_port}/normal-path"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as response:
            self.assertEqual(response.status, 200)
            body = json.loads(response.read().decode('utf-8'))
            self.assertEqual(body.get("status"), "backend_ok")

        # Test SQL Injection block
        sqli_url = f"http://127.0.0.1:{listen_port}/search?q=1%20or%201=1"
        try:
            urllib.request.urlopen(sqli_url, timeout=2)
            self.fail("SQLi request should have returned 403 Forbidden")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

        # Test Path Traversal block
        pt_url = f"http://127.0.0.1:{listen_port}/file?name=../../etc/passwd"
        try:
            urllib.request.urlopen(pt_url, timeout=2)
            self.fail("Path traversal request should have returned 403 Forbidden")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

    def test_rate_limiting(self):
        listen_port = self.get_free_port()
        waf.run(
            listen_port=str(listen_port),
            backend='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='2'
        )
        time.sleep(0.5)

        url = f"http://127.0.0.1:{listen_port}/"
        try:
            for _ in range(5):
                urllib.request.urlopen(url, timeout=2)
            self.fail("RPS limit should have triggered 429 Too Many Requests")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 429)

    def test_custom_rule_blocking(self):
        listen_port = self.get_free_port()
        waf.run(
            listen_port=str(listen_port),
            backend='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='100'
        )
        time.sleep(0.5)

        # Add custom rule
        waf.save_custom_rule("custom_block", "malicious_path", "Block malicious keyword", "true")

        # Enable it in wildcard vhost rules
        rules_list = ["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected", "custom_block"]
        waf.save_vhost(
            hostname='*',
            backend_host='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='100',
            learning_mode='false',
            allowlist_ips='',
            allowlist_paths='',
            rules_json=json.dumps(rules_list)
        )

        url = f"http://127.0.0.1:{listen_port}/some-action?data=malicious_path"
        try:
            urllib.request.urlopen(url, timeout=2)
            self.fail("Custom rule should have returned 403 Forbidden")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

        waf.delete_custom_rule("custom_block")

    def test_tls_termination(self):
        listen_port = self.get_free_port()
        res = waf.run(
            listen_port=str(listen_port),
            backend='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='100',
            ssl_enabled='true',
            ssl_cert_type='self_signed'
        )
        self.assertEqual(res.get('status'), 'running')
        time.sleep(0.5)

        url = f"https://127.0.0.1:{listen_port}/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=2) as response:
            self.assertEqual(response.status, 200)

if __name__ == '__main__':
    unittest.main()

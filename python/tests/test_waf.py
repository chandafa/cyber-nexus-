# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

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
        self.wfile.write(json.dumps({
            "status": "backend_ok",
            "host": self.headers.get("Host"),
            "x_forwarded_host": self.headers.get("X-Forwarded-Host")
        }).encode('utf-8'))

class TestWAF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend_port = cls.get_free_port()
        cls.backend_server = socketserver.TCPServer(('127.0.0.1', cls.backend_port), MockBackendHandler)
        cls.backend_thread = threading.Thread(target=cls.backend_server.serve_forever, daemon=True)
        cls.backend_thread.start()

        cls.vhosts_json_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "vhosts_local.json")
        cls.vhosts_json_backup = cls.vhosts_json_path + ".backup"
        if os.path.exists(cls.vhosts_json_path):
            if os.path.exists(cls.vhosts_json_backup):
                try:
                    os.remove(cls.vhosts_json_backup)
                except Exception:
                    pass
            try:
                os.rename(cls.vhosts_json_path, cls.vhosts_json_backup)
            except Exception:
                pass

        cls.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "waf_events.db")
        cls.db_backup = cls.db_path + ".backup"
        if os.path.exists(cls.db_path):
            if os.path.exists(cls.db_backup):
                try:
                    os.remove(cls.db_backup)
                except Exception:
                    pass
            try:
                os.rename(cls.db_path, cls.db_backup)
            except Exception:
                pass

    @classmethod
    def tearDownClass(cls):
        cls.backend_server.shutdown()
        cls.backend_server.server_close()

        if hasattr(cls, 'vhosts_json_path'):
            if os.path.exists(cls.vhosts_json_path):
                try:
                    os.remove(cls.vhosts_json_path)
                except Exception:
                    pass
            if os.path.exists(cls.vhosts_json_backup):
                try:
                    os.rename(cls.vhosts_json_backup, cls.vhosts_json_path)
                except Exception:
                    pass

        if hasattr(cls, 'db_path'):
            if os.path.exists(cls.db_path):
                try:
                    os.remove(cls.db_path)
                except Exception:
                    pass
            if os.path.exists(cls.db_backup):
                try:
                    os.rename(cls.db_backup, cls.db_path)
                except Exception:
                    pass

    @staticmethod
    def get_free_port():
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def setUp(self):
        waf.stop()
        if os.path.exists(self.vhosts_json_path):
            try:
                os.remove(self.vhosts_json_path)
            except Exception:
                pass

    def tearDown(self):
        waf.stop()
        if os.path.exists(self.vhosts_json_path):
            try:
                os.remove(self.vhosts_json_path)
            except Exception:
                pass

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

        # Test Clear Logs
        log_res = waf.get_logs()
        self.assertGreater(len(log_res.get('logs', [])), 0)
        self.assertGreater(log_res.get('stats', {}).get('total_requests', 0), 0)

        clear_res = waf.clear_logs()
        self.assertEqual(clear_res.get('status'), 'ok')

        log_res_after = waf.get_logs()
        self.assertEqual(len(log_res_after.get('logs', [])), 0)
        self.assertEqual(log_res_after.get('stats', {}).get('total_requests', 0), 0)

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

    def test_static_directory_serving(self):
        import tempfile
        import shutil

        # Create temporary directory and static file
        temp_dir = tempfile.mkdtemp(dir=os.path.dirname(os.path.abspath(__file__)))
        index_file = os.path.join(temp_dir, "index.html")
        with open(index_file, "w", encoding="utf-8") as f:
            f.write("<h1>Hello static!</h1>")

        try:
            listen_port = self.get_free_port()
            waf.run(
                listen_port=str(listen_port),
                backend='127.0.0.1',
                backend_port=str(self.backend_port),
                max_rps='100'
            )
            time.sleep(0.5)

            # Save static vhost config
            rules_list = ["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"]
            waf.save_vhost(
                hostname='static-test.local',
                backend_host='127.0.0.1',
                backend_port=str(self.backend_port),
                max_rps='100',
                learning_mode='false',
                allowlist_ips='',
                allowlist_paths='',
                rules_json=json.dumps(rules_list),
                vhost_type='static',
                root_directory=temp_dir
            )

            # Request normal static file with Host header
            url = f"http://127.0.0.1:{listen_port}/"
            req = urllib.request.Request(url, headers={'Host': 'static-test.local'})
            with urllib.request.urlopen(req, timeout=2) as response:
                self.assertEqual(response.status, 200)
                content = response.read().decode('utf-8')
                self.assertIn("Hello static!", content)

            # Request static directory but with SQL injection (should block it!)
            sqli_url = f"http://127.0.0.1:{listen_port}/?q=1%20or%201=1"
            req_sqli = urllib.request.Request(sqli_url, headers={'Host': 'static-test.local'})
            try:
                urllib.request.urlopen(req_sqli, timeout=2)
                self.fail("SQLi request targeting static site should have returned 403 Forbidden")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_header_forwarding_and_ip_resolution(self):
        listen_port = self.get_free_port()
        waf.run(
            listen_port=str(listen_port),
            backend='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='100'
        )
        time.sleep(0.5)

        # Clear logs first
        waf.clear_logs()

        # Send request with CF-Connecting-IP header
        url = f"http://127.0.0.1:{listen_port}/normal-path"
        req = urllib.request.Request(url, headers={
            'CF-Connecting-IP': '203.0.113.195',
            'X-Forwarded-Proto': 'https'
        })
        with urllib.request.urlopen(req, timeout=2) as response:
            self.assertEqual(response.status, 200)
            body = json.loads(response.read().decode('utf-8'))
            self.assertEqual(body.get("status"), "backend_ok")

        # Verify WAF logged the real client IP (203.0.113.195) instead of 127.0.0.1
        logs_list = []
        for _ in range(10):
            logs_res = waf.get_logs()
            logs_list = logs_res.get('logs', [])
            if logs_list:
                break
            time.sleep(0.1)
        self.assertGreater(len(logs_list), 0)
        logged_ip = logs_list[0].get('ip')
        self.assertEqual(logged_ip, '203.0.113.195')

    def test_subdomain_wildcard_matching(self):
        listen_port = self.get_free_port()
        waf.run(
            listen_port=str(listen_port),
            backend='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='100'
        )
        time.sleep(0.5)

        # Save wildcard vhost config pointing to mock backend
        rules_list = ["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"]
        waf.save_vhost(
            hostname='*.azharmtq.my.id',
            backend_host='127.0.0.1',
            backend_port=str(self.backend_port),
            max_rps='100',
            learning_mode='false',
            allowlist_ips='',
            allowlist_paths='',
            rules_json=json.dumps(rules_list)
        )

        # Test dev.azharmtq.my.id (should match *.azharmtq.my.id)
        url1 = f"http://127.0.0.1:{listen_port}/"
        req1 = urllib.request.Request(url1, headers={'Host': 'dev.azharmtq.my.id'})
        with urllib.request.urlopen(req1, timeout=2) as response:
            self.assertEqual(response.status, 200)
            body = json.loads(response.read().decode('utf-8'))
            # Mock backend returns the forwarded host
            self.assertEqual(body.get("x_forwarded_host"), "dev.azharmtq.my.id")

        # Test test.azharmtq.my.id (should match *.azharmtq.my.id)
        req2 = urllib.request.Request(url1, headers={'Host': 'test.azharmtq.my.id'})
        with urllib.request.urlopen(req2, timeout=2) as response:
            self.assertEqual(response.status, 200)
            body = json.loads(response.read().decode('utf-8'))
            self.assertEqual(body.get("x_forwarded_host"), "test.azharmtq.my.id")

        # Test azharmtq.my.id (should match *.azharmtq.my.id too)
        req3 = urllib.request.Request(url1, headers={'Host': 'azharmtq.my.id'})
        with urllib.request.urlopen(req3, timeout=2) as response:
            self.assertEqual(response.status, 200)

if __name__ == '__main__':
    unittest.main()

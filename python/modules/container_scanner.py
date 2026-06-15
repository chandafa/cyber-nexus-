# nexus/python/modules/container_scanner.py
"""Modul Container Scanner — SDD v2 §5.12. Trivy + demo fallback."""
import subprocess
import shutil
import json
import os
import tempfile
from typing import Callable, List, Optional

from core.subprocess_runner import tool_available, simulate_stream, fix_tool_cmd
from core.stream_handler import emit_line

# Timeout besar: unduhan DB vuln trivy (~96 MB) hanya terjadi SEKALI (run pertama)
# dan bisa lama di koneksi lambat. Setelah ter-cache, scan berikutnya cepat.
TRIVY_TIMEOUT = 600  # detik


class ContainerScanner:
    def scan_image(self, image_name: str,
                   output_callback: Optional[Callable] = None) -> List[dict]:
        cb = output_callback or emit_line
        if not tool_available('trivy'):
            cb('[DEMO] trivy tidak terpasang — scan image demo.')
            return self._demo(image_name, cb)
        # Catatan: trivy TIDAK wajib Docker — bila daemon tidak ada, trivy menarik
        # image langsung dari registry (remote). Jadi jangan bail di sini; biarkan
        # trivy mencoba (Docker → containerd → podman → remote registry).
        if not shutil.which('docker'):
            cb('[i] Docker tidak terdeteksi — trivy akan menarik image langsung '
               'dari registry (remote). Unduhan DB/Image pertama bisa lebih lama.')

        out = os.path.join(tempfile.gettempdir(), 'trivy_out.json')
        # Biarkan trivy mengelola DB-nya sendiri (cache 24 jam). Catatan: jangan
        # pakai --skip-db-update — trivy menolaknya bila metadata DB belum lengkap.
        cmd = ['trivy', 'image', '--timeout', f'{TRIVY_TIMEOUT}s', '--format', 'json',
               '--output', out, '--severity', 'CRITICAL,HIGH,MEDIUM', image_name]
        cb(f'$ {" ".join(cmd)}')
        cb(f'[*] Memindai image (timeout {TRIVY_TIMEOUT}s). Bila DB vuln (~96 MB) perlu '
           f'diperbarui, run ini akan lebih lama — sekali saja per ~24 jam.')
        from core.subprocess_runner import DemoDisabled
        try:
            cmd = fix_tool_cmd(cmd)
            r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=TRIVY_TIMEOUT + 10)
            if r.stdout:
                for line in r.stdout.splitlines()[:40]:
                    cb(line)
            if r.returncode != 0:
                # Tampilkan alasan nyata dari stderr trivy (mis. timeout unduh DB).
                for e in (r.stderr or '').strip().splitlines()[-3:]:
                    cb(f'  trivy: {e}')
                cb(f'[!] trivy gagal (exit {r.returncode}).')
                return self._demo(image_name, cb)
            with open(out, encoding='utf-8', errors='replace') as f:
                data = json.load(f)
        except subprocess.TimeoutExpired:
            cb('[!] trivy timeout — kemungkinan unduh DB vuln pertama belum selesai. '
               'Coba lagi setelah DB ter-cache.')
            return self._demo(image_name, cb)
        except DemoDisabled:
            raise  # mode nyata: teruskan sebagai error bersih, jangan demo lagi
        except Exception as e:
            cb(f'[!] {e}.')
            return self._demo(image_name, cb)

        findings: List[dict] = []
        for result in data.get('Results', []):
            for v in result.get('Vulnerabilities', []) or []:
                findings.append({
                    'target': result.get('Target'),
                    'vuln_id': v.get('VulnerabilityID'),
                    'package': v.get('PkgName'),
                    'installed_version': v.get('InstalledVersion'),
                    'fixed_version': v.get('FixedVersion', 'Belum ada fix'),
                    'severity': (v.get('Severity', '') or '').lower(),
                    'title': v.get('Title', ''),
                })
        # 0 temuan = image bersih (hasil NYATA yang sah) — JANGAN palsukan demo.
        cb(f'[=] Selesai. {len(findings)} kerentanan (CRITICAL/HIGH/MEDIUM) ditemukan.')
        return findings

    def _demo(self, image: str, cb: Callable) -> List[dict]:
        lines = [
            f'$ trivy image {image} (demo)',
            f'{image} (debian 11.6)',
            'Total: 14 (CRITICAL: 2, HIGH: 5, MEDIUM: 7)',
        ]
        simulate_stream(lines, cb, delay=0.05)
        return [
            {'target': image, 'vuln_id': 'CVE-2023-0286', 'package': 'openssl',
             'installed_version': '1.1.1n', 'fixed_version': '1.1.1t', 'severity': 'high',
             'title': 'X.400 address type confusion in X.509 GeneralName'},
            {'target': image, 'vuln_id': 'CVE-2022-37434', 'package': 'zlib',
             'installed_version': '1.2.11', 'fixed_version': '1.2.12', 'severity': 'critical',
             'title': 'zlib heap buffer over-read/overflow in inflate'},
            {'target': image, 'vuln_id': 'CVE-2021-3711', 'package': 'libssl1.1',
             'installed_version': '1.1.1k', 'fixed_version': '1.1.1l', 'severity': 'critical',
             'title': 'SM2 decryption buffer overflow'},
            {'target': image, 'vuln_id': 'CVE-2022-1664', 'package': 'dpkg',
             'installed_version': '1.20.9', 'fixed_version': '1.20.10', 'severity': 'medium',
             'title': 'Directory traversal in dpkg-source'},
        ]


def run(image: str = 'nginx:latest', **kwargs) -> dict:
    findings = ContainerScanner().scan_image(image)
    by = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        by[f['severity']] = by.get(f['severity'], 0) + 1
    return {'module': 'container', 'image': image, 'vulnerabilities': findings,
            'by_severity': by, 'total': len(findings)}

# nexus/python/modules/cloud_checker.py
"""Modul Cloud Configuration Checker — SDD v2 §5.13. Prowler + demo."""
import subprocess
import json
import os
import tempfile
from typing import Callable, List, Optional

from core.subprocess_runner import tool_available, simulate_stream, tool_argv
from core.stream_handler import emit_line


class CloudConfigChecker:
    def run_prowler(self, provider: str = 'aws',
                    output_callback: Optional[Callable] = None) -> List[dict]:
        cb = output_callback or emit_line
        if not tool_available('prowler'):
            cb('[DEMO] prowler tidak terpasang — cek cloud demo.')
            return self._demo(provider, cb)
        outdir = tempfile.gettempdir()
        cmd = tool_argv('prowler', [provider, '-M', 'json', '-o', outdir])
        cb(f'$ {" ".join(cmd)}')
        findings: List[dict] = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                cb(line.rstrip('\n'))
            proc.wait()
            path = os.path.join(outdir, f'prowler-output-{provider}.json')
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    if item.get('Status') == 'FAIL':
                        findings.append({
                            'check_id': item.get('CheckID'),
                            'title': item.get('CheckTitle'),
                            'severity': (item.get('Severity', '') or '').lower(),
                            'resource': item.get('ResourceId'),
                            'remediation': item.get('Remediation', {}).get(
                                'Recommendation', {}).get('Text', ''),
                        })
        except Exception as e:
            cb(f'[ERROR] {e}')
        return findings

    def _demo(self, provider: str, cb: Callable) -> List[dict]:
        lines = [f'$ prowler {provider} (demo)',
                 'Checking 240 controls across account...']
        simulate_stream(lines, cb, delay=0.05)
        return [
            {'check_id': 's3_bucket_public', 'title': 'S3 bucket dapat diakses publik',
             'severity': 'critical', 'resource': 'arn:aws:s3:::company-backups',
             'remediation': 'Set bucket ACL ke private & blokir public access'},
            {'check_id': 'ec2_sg_open', 'title': 'Security group mengizinkan 0.0.0.0/0 ke port 22',
             'severity': 'high', 'resource': 'sg-0a1b2c3d',
             'remediation': 'Batasi sumber SSH ke IP/CIDR terpercaya'},
            {'check_id': 'iam_user_no_mfa', 'title': 'IAM user tanpa MFA',
             'severity': 'high', 'resource': 'iam::user/deploy-bot',
             'remediation': 'Aktifkan MFA untuk seluruh user konsol'},
            {'check_id': 'rds_unencrypted', 'title': 'RDS instance tanpa enkripsi at-rest',
             'severity': 'medium', 'resource': 'rds:prod-db',
             'remediation': 'Aktifkan encryption at-rest (KMS)'},
            {'check_id': 'cloudtrail_disabled', 'title': 'CloudTrail logging tidak aktif',
             'severity': 'medium', 'resource': 'account-level',
             'remediation': 'Aktifkan CloudTrail multi-region'},
        ]


def run(provider: str = 'aws', **kwargs) -> dict:
    findings = CloudConfigChecker().run_prowler(provider)
    by = {}
    for f in findings:
        by[f['severity']] = by.get(f['severity'], 0) + 1
    return {'module': 'cloud', 'provider': provider, 'findings': findings,
            'by_severity': by, 'total': len(findings)}

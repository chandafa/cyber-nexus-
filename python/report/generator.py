# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/report/generator.py
"""
Report Generator — SDD bagian 10.3.
Menghasilkan laporan PDF profesional dari hasil scan menggunakan Jinja2 +
WeasyPrint. Bila WeasyPrint tidak terpasang, fallback ke output HTML.
"""
import os
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    _HAS_JINJA = True
except ImportError:  # pragma: no cover
    _HAS_JINJA = False

try:
    from weasyprint import HTML
    _HAS_WEASY = True
except Exception:  # pragma: no cover - weasyprint butuh lib sistem
    _HAS_WEASY = False

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')


class ReportGenerator:
    def __init__(self, template_dir: str = _TEMPLATE_DIR):
        self.template_dir = template_dir
        if _HAS_JINJA:
            self.env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(['html', 'xml']),
            )
        else:
            self.env = None

    def generate(self, session_data: dict, report_type: str = 'full',
                 output_path: str = None, fmt: str = 'auto') -> str:
        """
        report_type: executive | technical | full
        fmt: 'auto' (pdf jika weasyprint ada, else html) | 'pdf' | 'html'
        """
        html_content = self._render(session_data, report_type)

        out_dir = os.path.dirname(output_path) if output_path else 'reports'
        os.makedirs(out_dir or 'reports', exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        want_pdf = (fmt == 'pdf') or (fmt == 'auto' and _HAS_WEASY)
        if want_pdf and _HAS_WEASY:
            path = output_path or f'reports/nexus_report_{report_type}_{ts}.pdf'
            HTML(string=html_content, base_url=self.template_dir).write_pdf(path)
            return os.path.abspath(path)

        # fallback HTML
        path = (output_path or f'reports/nexus_report_{report_type}_{ts}.html')
        if path.endswith('.pdf'):
            path = path[:-4] + '.html'
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return os.path.abspath(path)

    def _render(self, session_data: dict, report_type: str) -> str:
        context = {
            'title': f'Nexus Security Report — {session_data.get("target", "N/A")}',
            'generated_at': datetime.now().strftime('%d %B %Y %H:%M:%S'),
            'session': session_data,
            'summary': self._build_summary(session_data),
            'report_type': report_type,
        }
        if self.env:
            tmpl_name = f'report_{report_type}.html.j2'
            try:
                template = self.env.get_template(tmpl_name)
            except Exception:
                template = self.env.get_template('report_full.html.j2')
            return template.render(**context)
        return self._fallback_html(context)

    def _build_summary(self, data: dict) -> dict:
        vulns = data.get('vulnerabilities', []) or []
        return {
            'total_vulns': len(vulns),
            'critical': sum(1 for v in vulns if v.get('severity') == 'critical'),
            'high': sum(1 for v in vulns if v.get('severity') == 'high'),
            'medium': sum(1 for v in vulns if v.get('severity') == 'medium'),
            'low': sum(1 for v in vulns if v.get('severity') == 'low'),
            'info': sum(1 for v in vulns if v.get('severity') == 'info'),
            'total_ports': len(data.get('ports', []) or []),
            'total_anomalies': len(data.get('anomalies', []) or []),
        }

    def _fallback_html(self, ctx: dict) -> str:  # pragma: no cover
        s = ctx['summary']
        return (f"<html><body><h1>{ctx['title']}</h1>"
                f"<p>{ctx['generated_at']}</p>"
                f"<p>Vulns: {s['total_vulns']} | Ports: {s['total_ports']}</p>"
                f"</body></html>")


def run(session_json: str, report_type: str = 'full', output_path: str = '', **kwargs) -> dict:
    import json
    try:
        data = json.loads(session_json) if isinstance(session_json, str) else session_json
    except Exception:
        data = {'target': 'unknown'}
    gen = ReportGenerator()
    path = gen.generate(data, report_type, output_path or None)
    return {'module': 'report', 'report_type': report_type, 'output': path,
            'is_pdf': path.endswith('.pdf')}

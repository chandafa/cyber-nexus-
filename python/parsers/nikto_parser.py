# nexus/python/parsers/nikto_parser.py
"""Parser output JSON Nikto menjadi daftar temuan ternormalisasi."""
import json


def parse_nikto_json(json_string: str) -> list:
    try:
        data = json.loads(json_string)
    except (json.JSONDecodeError, TypeError):
        return []
    vulns = data.get('vulnerabilities', []) if isinstance(data, dict) else []
    out = []
    for v in vulns:
        out.append({
            'tool': 'nikto',
            'vuln_id': v.get('id', ''),
            'title': v.get('msg', ''),
            'url': v.get('url', ''),
            'method': v.get('method', 'GET'),
            'severity': 'medium',
        })
    return out

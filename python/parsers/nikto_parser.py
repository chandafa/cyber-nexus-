# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

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

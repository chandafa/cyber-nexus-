# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/parsers/hydra_parser.py
"""Parser output Hydra untuk mengekstrak kredensial yang ditemukan."""
import re

_CRED_RE = re.compile(
    r'host:\s*(?P<host>\S+)\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)'
)


def parse_hydra_output(output: str) -> list:
    """Ekstrak kredensial valid dari output hydra (multi-line)."""
    creds = []
    for line in output.splitlines():
        m = _CRED_RE.search(line)
        if m:
            creds.append({
                'host': m.group('host'),
                'login': m.group('login'),
                'password': m.group('password'),
            })
    return creds

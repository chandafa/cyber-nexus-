# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/parsers/tshark_parser.py
"""Parser baris field tshark (separator '|') menjadi dict paket."""

FIELDS = ['frame_number', 'time_relative', 'ip_src', 'ip_dst', 'ip_proto',
          'protocol', 'frame_len', 'tcp_srcport', 'tcp_dstport']


def parse_tshark_line(line: str) -> dict:
    """Parse satu baris field tshark -> dict, atau {} jika header/invalid."""
    parts = line.split('|')
    if len(parts) < len(FIELDS):
        return {}
    if not parts[0].strip().isdigit():
        return {}  # baris header
    row = dict(zip(FIELDS, [p.strip() for p in parts]))
    try:
        row['frame_len'] = int(row['frame_len'] or 0)
    except ValueError:
        row['frame_len'] = 0
    return row

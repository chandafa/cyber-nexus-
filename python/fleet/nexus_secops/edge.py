# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/edge.py
"""
Nexus Edge — ingest AGENTLESS untuk perangkat yang tak bisa memasang agent
(router, firewall, switch, perangkat IoT/OT). Perangkat ini umumnya mengirim
syslog; modul ini mengurai baris syslog (RFC3164/BSD & RFC5424) menjadi event
Nexus yang NYATA sehingga mengalir ke rule engine → alert → XDR/SOAR/notify.

Parser murni-stdlib & tanpa jaringan; manager (server.py) yang menyalurkan hasil
parse ke pipeline ingest. Cocok dipadukan dengan mode air-gapped.
"""
import re

# severity syslog (0..7) → severity Nexus
_SEV = {0: "critical", 1: "critical", 2: "critical", 3: "high",
        4: "medium", 5: "low", 6: "info", 7: "info"}
_FACILITY = {
    0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

# RFC5424:  <PRI>VER TIMESTAMP HOST APP PROCID MSGID [SD] MSG
_RE_5424 = re.compile(
    r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]|-)\s*(.*)$")
# RFC3164:  <PRI>MMM DD HH:MM:SS HOST TAG: MSG
_RE_3164 = re.compile(
    r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)[:\[]?\s*(.*)$")
# fallback: hanya <PRI> di depan
_RE_PRI = re.compile(r"^<(\d{1,3})>\s*(.*)$")


def _decode_pri(pri):
    pri = int(pri)
    sev = pri % 8
    fac = pri // 8
    return sev, fac


def parse_syslog(line: str) -> dict:
    """Urai satu baris syslog → dict event Nexus. Selalu mengembalikan event
    (tak pernah gagal): baris non-syslog jadi event 'info' apa adanya."""
    line = (line or "").strip()
    if not line:
        return {}
    pri = None
    ver = ""
    host = app = msg = ""
    m = _RE_5424.match(line)
    if m:
        pri, ver, _ts, host, app, _procid, _msgid, msg = m.groups()
    else:
        m = _RE_3164.match(line)
        if m:
            pri, _ts, host, app, msg = m.groups()
        else:
            m = _RE_PRI.match(line)
            if m:
                pri, msg = m.groups()
            else:
                msg = line
    if pri is not None:
        sev_n, fac_n = _decode_pri(pri)
        severity = _SEV.get(sev_n, "info")
        facility = _FACILITY.get(fac_n, str(fac_n))
    else:
        sev_n = 6
        severity = "info"
        facility = "unknown"
    host = host if (host and host != "-") else ""
    app = app if (app and app != "-") else ""
    title = f"syslog {facility}/{app}".strip("/ ") or "syslog"
    return {
        "type": "syslog", "source": "edge-syslog", "event_type": "syslog",
        "severity": severity, "origin": "real",
        "title": (msg[:80] or title),
        "detail": msg or line,
        "host": {"hostname": host} if host else {},
        "target": {"app": app, "facility": facility},
        "evidence": {"facility": facility, "syslog_severity": sev_n,
                     "app": app, "rfc": "5424" if ver else ("3164" if pri is not None else "raw")},
    }


def parse_many(lines) -> list:
    """Urai banyak baris (list atau teks multibaris) → daftar event (non-kosong)."""
    if isinstance(lines, str):
        lines = lines.splitlines()
    out = []
    for ln in (lines or []):
        ev = parse_syslog(ln)
        if ev:
            out.append(ev)
    return out

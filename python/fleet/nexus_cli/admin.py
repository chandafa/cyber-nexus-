# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_cli/admin.py
"""Operasi admin fleet lewat API HTTP/HTTPS manager (dipakai mode interaktif & flag)."""
from nexus_common import protocol as fc

_SCHEME = "http"


def set_scheme(scheme: str):
    """Atur http/https untuk panggilan admin (dukungan TLS untuk CLI/dashboard)."""
    global _SCHEME
    _SCHEME = scheme or "http"


def _url(host, port, path):
    return fc.manager_url(host, port, path, scheme=_SCHEME)


def agents(host, port, token):
    return fc.get_admin(_url(host, port, "/agents"), token)


def events(host, port, token, limit=100):
    return fc.get_admin(_url(host, port, f"/events?limit={limit}"), token)


def stats(host, port, token):
    return fc.get_admin(_url(host, port, "/stats"), token)


def alerts(host, port, token, limit=100, status=""):
    path = f"/alerts?limit={limit}" + (f"&status={status}" if status else "")
    return fc.get_admin(_url(host, port, path), token)


def ack(host, port, token, alert_id, status="ack"):
    return fc.post_admin(_url(host, port, "/alerts/ack"), {"id": alert_id, "status": status}, token)


def report(host, port, token, scope="fleet"):
    return fc.get_admin(_url(host, port, f"/report?scope={scope}"), token)


def health(host, port):
    return fc.get_admin(_url(host, port, "/health"))


def policy_get(host, port):
    return fc.get_admin(_url(host, port, "/policy"))


def policy_set(host, port, token, policy: dict):
    return fc.post_admin(_url(host, port, "/policy"), {"policy": policy}, token)


def command(host, port, token, agent_id, cmd, args=None):
    return fc.post_admin(_url(host, port, "/command"),
                         {"agent_id": agent_id, "command": cmd, "args": args or {}}, token)


def apply_license(host, port, token, license_token):
    return fc.post_admin(_url(host, port, "/license/apply"), {"token": license_token}, token)


def remove_agent(host, port, token, agent_id, purge=False):
    return fc.post_admin(_url(host, port, "/agents/remove"),
                         {"agent_id": agent_id, "purge": purge}, token)


def incidents(host, port, token, status="open"):
    return fc.get_admin(_url(host, port, f"/incidents?status={status}"), token)


def add_user(host, port, token, role="viewer"):
    return fc.post_admin(_url(host, port, "/users"), {"role": role}, token)


# --------------------------------------------------------------------------- SecOps (Pro)
# Membaca lapisan analitik SOC lewat API manager. Bila lisensi bukan Pro/Enterprise,
# manager membalas 403 (fitur 'secops' terkunci) — sama seperti gerbang GUI.
import urllib.parse as _up  # noqa: E402


def search(host, port, token, index="events", q="", limit=200):
    qs = _up.urlencode({"index": index, "q": q, "limit": limit})
    return fc.get_admin(_url(host, port, f"/search?{qs}"), token)


def xdr(host, port, token, status=""):
    return fc.get_admin(_url(host, port, f"/xdr/incidents?status={status}"), token)


def ueba(host, port, token):
    return fc.get_admin(_url(host, port, "/ueba/scores"), token)


def ti(host, port, token):
    return fc.get_admin(_url(host, port, "/ti/iocs"), token)


def ndr(host, port, token):
    return fc.get_admin(_url(host, port, "/ndr/talkers"), token)


def cloud(host, port, token):
    return fc.get_admin(_url(host, port, "/cloud/findings"), token)


def triage(host, port, token):
    return fc.get_admin(_url(host, port, "/ai/triage"), token)


def soar(host, port, token):
    return fc.get_admin(_url(host, port, "/soar/playbooks"), token)

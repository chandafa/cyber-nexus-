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


# --------------------------------------------------------------------- Admin (lanjutan)
# Endpoint admin yang dipakai GUI (Fleet Manager / Settings) tetapi sebelumnya belum
# punya padanan CLI. Semua memetakan langsung ke endpoint manager — nyata, bukan demo.

def list_users(host, port, token):
    return fc.get_admin(_url(host, port, "/users"), token)


def rules_get(host, port, token):
    return fc.get_admin(_url(host, port, "/rules"), token)


def rules_set(host, port, token, rules):
    return fc.post_admin(_url(host, port, "/rules"), {"rules": rules}, token)


def rules_sigma(host, port, token, sigma):
    return fc.post_admin(_url(host, port, "/rules/sigma"), {"sigma": sigma}, token)


def notify_set(host, port, token, webhook, min_level=12):
    return fc.post_admin(_url(host, port, "/notify"),
                         {"webhook": webhook, "min_level": min_level}, token)


def audit(host, port, token, limit=200):
    return fc.get_admin(_url(host, port, f"/audit?limit={limit}"), token)


def audit_verify(host, port, token):
    return fc.get_admin(_url(host, port, "/audit/verify"), token)


def vulndb_get(host, port, token):
    return fc.get_admin(_url(host, port, "/vulndb"), token)


def vulndb_set(host, port, token, vuln_db):
    return fc.post_admin(_url(host, port, "/vulndb"), {"vuln_db": vuln_db}, token)


def response_action(host, port, token, agent_id, action, ip="", target="", process=""):
    return fc.post_admin(_url(host, port, "/response/actions"),
                         {"agent_id": agent_id, "action": action, "ip": ip,
                          "target": target, "process": process}, token)


# ---- Hub notifikasi (telegram/email/slack/discord/webhook/whatsapp) ----
def notify_list(host, port, token):
    return fc.get_admin(_url(host, port, "/notify"), token)


def notify_channel_add(host, port, token, channel):
    return fc.post_admin(_url(host, port, "/notify/channel"), {"channel": channel}, token)


def notify_channel_del(host, port, token, cid):
    return fc.post_admin(_url(host, port, "/notify/channel/delete"), {"id": cid}, token)


def notify_test(host, port, token, cid="", channel=None):
    body = {"id": cid} if cid else {"channel": channel}
    return fc.post_admin(_url(host, port, "/notify/test"), body, token)


# ---- Nexus Canary (honeytokens) ----
def canary_mint(host, port, token, typ="url", label="", base_url=""):
    body = {"type": typ, "label": label}
    if base_url:
        body["base_url"] = base_url
    return fc.post_admin(_url(host, port, "/canary/mint"), body, token)


def canary_tokens(host, port, token):
    return fc.get_admin(_url(host, port, "/canary/tokens"), token)


def canary_delete(host, port, token, cid):
    return fc.post_admin(_url(host, port, "/canary/delete"), {"id": cid}, token)


def canary_stats(host, port, token):
    return fc.get_admin(_url(host, port, "/canary/stats"), token)


# ---- Time-travel replay + Air-gapped + offline TI bundle ----
def replay(host, port, token, agent_id="", from_ts=0, to_ts=0, incident="", limit=2000):
    qs = _up.urlencode({"agent_id": agent_id, "from": from_ts, "to": to_ts,
                        "incident": incident, "limit": limit})
    return fc.get_admin(_url(host, port, f"/replay?{qs}"), token)


def airgap_status(host, port, token):
    return fc.get_admin(_url(host, port, "/airgap"), token)


def airgap_set(host, port, token, on):
    return fc.post_admin(_url(host, port, "/airgap"), {"on": bool(on)}, token)


def ti_export(host, port, token):
    return fc.get_admin(_url(host, port, "/ti/bundle"), token)


def ti_import_bundle(host, port, token, bundle):
    return fc.post_admin(_url(host, port, "/ti/bundle"), {"bundle": bundle}, token)


# ---- Nexus Aware (phishing-sim) ----
def aware_templates(host, port, token):
    return fc.get_admin(_url(host, port, "/aware/templates"), token)


def aware_campaigns(host, port, token):
    return fc.get_admin(_url(host, port, "/aware/campaigns"), token)


def aware_score(host, port, token, campaign=""):
    qs = _up.urlencode({"campaign": campaign})
    return fc.get_admin(_url(host, port, f"/aware/score?{qs}"), token)


def aware_campaign(host, port, token, name, template_id, targets):
    return fc.post_admin(_url(host, port, "/aware/campaign"),
                         {"name": name, "template_id": template_id, "targets": targets}, token)


def aware_send(host, port, token, campaign_id, base_url=""):
    body = {"campaign_id": campaign_id}
    if base_url:
        body["base_url"] = base_url
    return fc.post_admin(_url(host, port, "/aware/send"), body, token)


def aware_delete(host, port, token, campaign_id):
    return fc.post_admin(_url(host, port, "/aware/delete"), {"campaign_id": campaign_id}, token)


# ---- Nexus Atlas (attack-path graph) ----
def atlas_graph(host, port, token):
    return fc.get_admin(_url(host, port, "/atlas/graph"), token)


def atlas_blast(host, port, token, node):
    qs = _up.urlencode({"node": node})
    return fc.get_admin(_url(host, port, f"/atlas/blast?{qs}"), token)


def atlas_exposed(host, port, token, limit=10):
    qs = _up.urlencode({"limit": limit})
    return fc.get_admin(_url(host, port, f"/atlas/exposed?{qs}"), token)


def atlas_stats(host, port, token):
    return fc.get_admin(_url(host, port, "/atlas/stats"), token)


# ---- Nexus Hub (content packs) ----
def pack_catalog(host, port, token):
    return fc.get_admin(_url(host, port, "/pack/catalog"), token)


def pack_export(host, port, token):
    return fc.get_admin(_url(host, port, "/pack/export"), token)


def pack_import(host, port, token, pack):
    return fc.post_admin(_url(host, port, "/pack/import"), {"pack": pack}, token)


def pack_install(host, port, token, pid):
    return fc.post_admin(_url(host, port, "/pack/install"), {"id": pid}, token)


# ---- Nexus Edge (ingest syslog agentless) ----
def syslog_ingest(host, port, token, lines, dev_host=""):
    return fc.post_admin(_url(host, port, "/ingest/syslog"),
                         {"lines": lines, "host": dev_host}, token)


# ---- Nexus Comply (UU PDP / ISO 27001) ----
def comply_frameworks(host, port, token):
    return fc.get_admin(_url(host, port, "/comply/frameworks"), token)


def comply_report(host, port, token, framework="uu-pdp"):
    qs = _up.urlencode({"framework": framework})
    return fc.get_admin(_url(host, port, f"/comply/report?{qs}"), token)


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


# --------------------------------------------------------------------- SecOps (lanjutan)
# Aksi baca-detail & aksi tulis untuk seluruh pilar SecOps. Semua memetakan langsung ke
# endpoint manager yang sudah ada (server.py do_GET/do_POST) — nyata, bukan demo.
# Sama seperti di atas: manager membalas 403 bila lisensi bukan Pro/Enterprise.

# ---- SIEM ----
def siem_stats(host, port, token, index="events", q="", top_field="event_type", top_n=10, buckets=24):
    qs = _up.urlencode({"index": index, "q": q, "top_field": top_field,
                        "top_n": top_n, "buckets": buckets})
    return fc.get_admin(_url(host, port, f"/siem/stats?{qs}"), token)


# ---- XDR ----
def xdr_get(host, port, token, incident_id):
    qs = _up.urlencode({"id": incident_id})
    return fc.get_admin(_url(host, port, f"/xdr/incident?{qs}"), token)


def xdr_ack(host, port, token, incident_id, status="ack"):
    return fc.post_admin(_url(host, port, "/xdr/ack"), {"id": incident_id, "status": status}, token)


def xdr_correlate(host, port, token, lookback=86400):
    return fc.post_admin(_url(host, port, "/xdr/correlate"), {"lookback": lookback}, token)


# ---- EDR ----
def edr_hosts(host, port, token):
    return fc.get_admin(_url(host, port, "/edr/hosts"), token)


def edr_tree(host, port, token, agent_id):
    qs = _up.urlencode({"agent_id": agent_id})
    return fc.get_admin(_url(host, port, f"/edr/tree?{qs}"), token)


def edr_processes(host, port, token, agent_id, q=""):
    qs = _up.urlencode({"agent_id": agent_id, "q": q})
    return fc.get_admin(_url(host, port, f"/edr/processes?{qs}"), token)


def edr_ancestry(host, port, token, agent_id, pid):
    qs = _up.urlencode({"agent_id": agent_id, "pid": pid})
    return fc.get_admin(_url(host, port, f"/edr/ancestry?{qs}"), token)


# ---- Threat Intel ----
def ti_matches(host, port, token, limit=200):
    qs = _up.urlencode({"limit": limit})
    return fc.get_admin(_url(host, port, f"/ti/matches?{qs}"), token)


def ti_stats(host, port, token):
    return fc.get_admin(_url(host, port, "/ti/stats"), token)


def ti_add(host, port, token, iocs, source="manual"):
    return fc.post_admin(_url(host, port, "/ti/iocs"), {"iocs": iocs, "source": source}, token)


def ti_import(host, port, token, url, fmt="text", source=None, threat="feed",
              severity="high", col=0):
    body = {"url": url, "fmt": fmt, "threat": threat, "severity": severity, "col": col}
    if source:
        body["source"] = source
    return fc.post_admin(_url(host, port, "/ti/import"), body, token)


def ti_delete(host, port, token, ioc_id):
    return fc.post_admin(_url(host, port, "/ti/delete"), {"id": ioc_id}, token)


def ti_scan(host, port, token, lookback=604800):
    return fc.post_admin(_url(host, port, "/ti/scan"), {"lookback": lookback}, token)


# ---- UEBA ----
def ueba_baselines(host, port, token):
    return fc.get_admin(_url(host, port, "/ueba/baselines"), token)


def ueba_peers(host, port, token, window=86400):
    qs = _up.urlencode({"window": window})
    return fc.get_admin(_url(host, port, f"/ueba/peers?{qs}"), token)


def ueba_train(host, port, token, lookback=1209600):
    return fc.post_admin(_url(host, port, "/ueba/train"), {"lookback": lookback}, token)


def ueba_scan(host, port, token, window=86400, emit=True):
    return fc.post_admin(_url(host, port, "/ueba/scan"), {"window": window, "emit": emit}, token)


# ---- AI ----
def ai_incident(host, port, token, incident_id):
    qs = _up.urlencode({"id": incident_id})
    return fc.get_admin(_url(host, port, f"/ai/incident?{qs}"), token)


def ai_model(host, port, token):
    return fc.get_admin(_url(host, port, "/ai/model"), token)


def ai_nl(host, port, token, q):
    qs = _up.urlencode({"q": q})
    return fc.get_admin(_url(host, port, f"/ai/nl?{qs}"), token)


def ai_train(host, port, token):
    return fc.post_admin(_url(host, port, "/ai/train"), {}, token)


def ai_run(host, port, token, incident_id="", status="open"):
    body = {"id": incident_id} if incident_id else {"status": status}
    return fc.post_admin(_url(host, port, "/ai/triage"), body, token)


# ---- Cloud (CSPM) ----
def cloud_posture(host, port, token):
    return fc.get_admin(_url(host, port, "/cloud/posture"), token)


def cloud_stats(host, port, token):
    return fc.get_admin(_url(host, port, "/cloud/stats"), token)


def cloud_scan(host, port, token, resources=None, prowler=None, provider="aws", account="default"):
    body = {"provider": provider, "account": account}
    if prowler is not None:
        body["prowler"] = prowler
    if resources is not None:
        body["resources"] = resources
    return fc.post_admin(_url(host, port, "/cloud/scan"), body, token)


# ---- NDR ----
def ndr_flows(host, port, token, agent_id="", limit=500):
    qs = _up.urlencode({"agent_id": agent_id, "limit": limit})
    return fc.get_admin(_url(host, port, f"/ndr/flows?{qs}"), token)


def ndr_stats(host, port, token):
    return fc.get_admin(_url(host, port, "/ndr/stats"), token)


# ---- SOAR ----
def soar_runs(host, port, token, limit=200):
    qs = _up.urlencode({"limit": limit})
    return fc.get_admin(_url(host, port, f"/soar/runs?{qs}"), token)


def soar_save(host, port, token, playbook):
    return fc.post_admin(_url(host, port, "/soar/playbook"), {"playbook": playbook}, token)


def soar_enable(host, port, token, playbook_id, enabled=True):
    return fc.post_admin(_url(host, port, "/soar/playbook/enable"),
                         {"id": playbook_id, "enabled": enabled}, token)


def soar_mode(host, port, token, playbook_id, mode="dry_run"):
    return fc.post_admin(_url(host, port, "/soar/playbook/mode"),
                         {"id": playbook_id, "mode": mode}, token)


def soar_delete(host, port, token, playbook_id):
    return fc.post_admin(_url(host, port, "/soar/playbook/delete"), {"id": playbook_id}, token)


def soar_run(host, port, token, playbook_id, ref_id=""):
    return fc.post_admin(_url(host, port, "/soar/run"),
                         {"id": playbook_id, "ref_id": ref_id}, token)

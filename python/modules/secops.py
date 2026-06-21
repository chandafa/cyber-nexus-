# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/secops.py
"""
Adapter desktop -> paket kanonik `fleet/nexus_secops` (SIEM + XDR).

Sama seperti adapter fleet_manager: logika TINGGAL SATU TEMPAT
(python/fleet/nexus_secops/), adapter ini hanya menambahkan folder fleet/ ke
sys.path dan mengekspor fungsi yang dipanggil runner.py. Semua kueri/korelasi
beroperasi atas store NYATA manager (events/alerts) — bukan demo/simulasi.
"""
import os
import sys

_FLEET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fleet")
if _FLEET not in sys.path:
    sys.path.insert(0, _FLEET)

from nexus_secops import siem as _siem            # noqa: E402
from nexus_secops import correlate as _xdr        # noqa: E402
from nexus_secops import soar as _soar            # noqa: E402
from nexus_secops import threatintel as _ti       # noqa: E402
from nexus_secops import ueba as _ueba             # noqa: E402
from nexus_secops import ai as _ai                 # noqa: E402
from nexus_secops import edr as _edr               # noqa: E402
from nexus_secops import cloud as _cloud           # noqa: E402
from nexus_secops import ndr as _ndr               # noqa: E402


# ---- SIEM (pencarian + agregasi) ----
def search(index="events", query="", limit=200, order="desc"):
    return _siem.search(index, query, int(limit), order)


def stats(index="events", query="", buckets=24, top_field="event_type", top_n=10):
    return _siem.stats(index, query, int(buckets), top_field, int(top_n))


def explain(query=""):
    return _siem.explain(query)


# ---- XDR (korelasi insiden) ----
def correlate(lookback=86400, tenant="default"):
    return _xdr.correlate(int(lookback), tenant=tenant)


def incidents(status="", limit=200, tenant="default"):
    return _xdr.list_incidents(status, int(limit), tenant)


def incident(incident_id="", tenant="default"):
    return _xdr.get_incident(incident_id, tenant)


def ack_incident(incident_id="", status="ack"):
    return _xdr.ack_incident(incident_id, status)


# ---- SOAR (playbook otomatis) ----
def soar_playbooks(tenant="default"):
    return _soar.list_playbooks(tenant)


def soar_save(playbook, tenant="default"):
    import json as _json
    if isinstance(playbook, str):
        playbook = _json.loads(playbook or "{}")
    return _soar.save_playbook(playbook, tenant)


def soar_enable(pb_id="", enabled=True):
    return _soar.set_enabled(pb_id, str(enabled).lower() in ("1", "true", "yes", "on"))


def soar_mode(pb_id="", mode="dry_run"):
    return _soar.set_mode(pb_id, mode)


def soar_delete(pb_id=""):
    return _soar.delete_playbook(pb_id)


def soar_runs(limit=200, tenant="default"):
    return _soar.list_runs(int(limit), tenant)


def soar_run(pb_id="", ref_id="", tenant="default"):
    return _soar.run_now(pb_id, ref_id, tenant)


def soar_process(lookback=21600, tenant="default"):
    return _soar.process(int(lookback), tenant)


# ---- Threat Intelligence (IOC) ----
def ti_iocs(type="", q="", limit=500, tenant="default"):
    return _ti.list_iocs(type, q, int(limit), tenant)


def ti_add(iocs, source="manual", tenant="default"):
    import json as _json
    if isinstance(iocs, str):
        try:
            iocs = _json.loads(iocs)
        except Exception:
            iocs = [x.strip() for x in iocs.splitlines() if x.strip()]
    return _ti.add_iocs(iocs, source, tenant)


def ti_import(url="", fmt="text", source=None, threat="feed", severity="high",
              col=0, tenant="default"):
    return _ti.import_feed(url, fmt, source, threat, severity, int(col), tenant)


def ti_delete(ioc_id=""):
    return _ti.delete_ioc(ioc_id)


def ti_clear(tenant="default"):
    return _ti.clear_iocs(tenant)


def ti_matches(limit=200, tenant="default"):
    return _ti.list_matches(int(limit), tenant)


def ti_stats(tenant="default"):
    return _ti.stats(tenant)


def ti_scan(lookback=604800):
    """Retro-hunt via manager (membuat alert utk kecocokan baru)."""
    from nexus_manager.server import threatintel_scan
    return threatintel_scan(int(lookback))


# ---- UEBA (behavioral analytics) ----
def ueba_train(lookback=1209600):
    from nexus_manager.server import ueba_train as _t
    return _t(int(lookback))


def ueba_scan(window=86400, emit=True):
    from nexus_manager.server import ueba_scan as _s
    return _s(int(window), str(emit).lower() in ("1", "true", "yes", "on"))


def ueba_baselines(tenant="default"):
    return _ueba.list_baselines(tenant)


def ueba_scores(limit=200, band="", tenant="default"):
    return _ueba.list_scores(int(limit), band, tenant)


def ueba_peers(window=86400, tenant="default"):
    return _ueba.peer_analysis(int(window), tenant)


# ---- Nexus AI (triase lokal, tanpa token) ----
def ai_train():
    from nexus_manager.server import ai_train as _t
    return _t()


def ai_triage(incident_id="", status="open"):
    from nexus_manager.server import ai_triage as _one, ai_triage_all as _all
    return _one(incident_id) if incident_id else _all(status)


def ai_list(priority="", tenant="default"):
    return _ai.list_triage(200, priority, tenant)


def ai_incident(incident_id="", tenant="default"):
    return _ai.triage_incident(incident_id, tenant, record=False)


def ai_nl(q=""):
    return _ai.nl_query(q)


def ai_status(tenant="default"):
    return _ai.model_status(tenant)


# ---- EDR (pohon proses) ----
def edr_hosts(tenant="default"):
    return _edr.hosts(tenant)


def edr_tree(agent_id="", tenant="default"):
    return _edr.build_tree(agent_id, tenant)


def edr_processes(agent_id="", q="", tenant="default"):
    return _edr.list_processes(agent_id, q, tenant)


def edr_ancestry(agent_id="", pid=0, tenant="default"):
    return _edr.ancestry(agent_id, pid, tenant)


# ---- Cloud Security (CSPM) ----
def cloud_scan(resources=None, prowler=None, provider="aws", account="default"):
    from nexus_manager.server import cloud_scan as _s
    return _s(resources, prowler, provider, account)


def cloud_findings(provider="", severity="", status="", tenant="default"):
    return _cloud.list_findings(provider, severity, status, 500, tenant)


def cloud_posture(tenant="default"):
    return _cloud.posture(tenant)


def cloud_stats(tenant="default"):
    return _cloud.stats(tenant)


# ---- NDR (network detection) ----
def ndr_flows(agent_id="", limit=500, tenant="default"):
    return _ndr.list_flows(agent_id, int(limit), tenant)


def ndr_talkers(window=86400, tenant="default"):
    return _ndr.top_talkers(int(window), tenant)


def ndr_stats(tenant="default"):
    return _ndr.stats(tenant)


def ndr_detect(agent_id="", window=86400, tenant="default"):
    return {"ok": True, "findings": _ndr.detect(agent_id, int(window), tenant)}

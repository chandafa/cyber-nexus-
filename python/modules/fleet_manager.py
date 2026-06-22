# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/fleet_manager.py
"""
Adapter desktop -> paket kanonik `fleet/nexus_manager`.

Logika manager TINGGAL SATU TEMPAT (python/fleet/nexus_manager/server.py) yang
juga dipakai standalone (`python -m nexus_manager`). Adapter ini hanya:
  - menambahkan folder fleet/ ke sys.path,
  - mengarahkan log paket ke terminal UI (emit_line),
  - mengekspor fungsi yang dipanggil runner.py.
"""
import os
import sys

_FLEET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fleet")
if _FLEET not in sys.path:
    sys.path.insert(0, _FLEET)

from core.stream_handler import emit_line  # noqa: E402
from nexus_common.log import set_sink  # noqa: E402

set_sink(emit_line)  # log paket -> terminal UI desktop

from nexus_manager.server import (  # noqa: E402,F401
    run, run_foreground, stop, manager_status,
    list_agents, list_events, stats, get_policy, set_policy, queue_command,
    get_enroll_key, get_admin_token, init_db,
    list_alerts, ack_alert, get_rules, set_rules, list_audit, report,
    posture, import_sigma, response_action, license_status, reload_license,
    get_vulndb, set_vulndb, set_notify, apply_license, remove_agent,
    incidents, add_user, list_users,
    # --- fitur ekosistem baru (W1-W4) ---
    verify_audit, replay, set_air_gapped, air_gapped_status,
    ti_export_bundle, ti_import_bundle, pack_export, pack_import,
    pack_catalog, pack_install, ingest_syslog, canary_mint,
    aware_create, aware_send, comply_report, comply_frameworks,
    list_notify, add_notify_channel, remove_notify_channel, test_notify,
)

# Beberapa fitur ada di modul nexus_secops (bukan server) — bungkus tipis dgn
# tenant default agar runner desktop bisa memanggilnya seragam.
from nexus_secops import canary as _canary, aware as _aware, atlas as _atlas  # noqa: E402


def canary_list(tenant="default"):
    return _canary.list_tokens(tenant)


def canary_delete(token_id):
    return _canary.delete_token(token_id)


def canary_stats(tenant="default"):
    return _canary.stats(tenant)


def aware_templates():
    return _aware.list_templates()


def aware_campaigns(tenant="default"):
    return _aware.list_campaigns(tenant)


def aware_score(campaign="", tenant="default"):
    return _aware.score(campaign, tenant)


def aware_delete(campaign_id):
    return _aware.delete_campaign(campaign_id)


def atlas_graph(tenant="default", window=604800):
    return _atlas.build_graph(tenant, int(window))


def atlas_blast(node, tenant="default"):
    return _atlas.blast_radius(node, tenant)


def atlas_exposed(tenant="default", limit=10):
    return _atlas.top_exposed(tenant, int(limit))


def atlas_stats(tenant="default"):
    return _atlas.stats(tenant)


# Pastikan skema DB manager siap sebelum command desktop apa pun dipanggil
# (init_db idempoten — membuat semua tabel fleet + secops bila belum ada).
try:
    init_db()
except Exception:
    pass

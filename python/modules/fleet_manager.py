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
)

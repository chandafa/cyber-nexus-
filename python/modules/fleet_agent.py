# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/fleet_agent.py
"""
Adapter desktop -> paket kanonik `fleet/nexus_agent`.

Logika agent tinggal satu tempat (python/fleet/nexus_agent/agent.py) yang juga
dipakai standalone (`python -m nexus_agent`). Adapter mengarahkan log paket ke
terminal UI dan mengekspor fungsi yang dipanggil runner.py.
"""
import os
import sys

_FLEET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fleet")
if _FLEET not in sys.path:
    sys.path.insert(0, _FLEET)

from core.stream_handler import emit_line  # noqa: E402
from nexus_common.log import set_sink  # noqa: E402

set_sink(emit_line)

from nexus_agent.agent import (  # noqa: E402,F401
    enroll, run_foreground, stop, status, reset, collect_all,
)

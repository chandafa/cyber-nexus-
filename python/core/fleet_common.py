# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/fleet_common.py
"""
Shim kompatibilitas -> protokol kanonik `fleet/nexus_common/protocol.py`.

Protokol Fleet dipindahkan ke paket mandiri agar bisa di-deploy terpisah
(agent ringan, manager, cli). Modul ini hanya meneruskan agar import lama
`from core import fleet_common as fc` tetap berfungsi.
"""
import os
import sys

_FLEET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fleet")
if _FLEET not in sys.path:
    sys.path.insert(0, _FLEET)

from nexus_common.protocol import *  # noqa: F401,F403,E402
from nexus_common import protocol as _p  # noqa: E402

# Pastikan nama ber-underscore / kelas ikut terekspor (import * melewatkannya).
HttpError = _p.HttpError
_request = _p._request
_data_dir = _p._data_dir

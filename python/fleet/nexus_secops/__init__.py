# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/__init__.py
"""
Nexus SecOps — lapisan *otak* SOC di atas pipa data Nexus Fleet.

Fleet menyediakan **data plane**: agent → manager → store (events/alerts) di
SQLite manager. SecOps menambah **analytics plane** di atas store yang sama —
tanpa menduplikasi data:

  • siem      — SIEM/log analytics: bahasa kueri NQL + agregasi (gaya
                Splunk SPL / Elastic / QRadar / Graylog — dedup: satu mesin
                pencarian, bukan lima).
  • correlate — XDR correlation: gabungkan banyak alert lintas-waktu &
                lintas-sumber menjadi SATU insiden ber-kill-chain (gaya
                Microsoft Defender XDR / Palo Alto Cortex XDR).
  • soar      — SOAR/automated response: playbook (trigger → steps) yang
                menjalankan active-response Fleet NYATA + webhook (gaya
                Palo Alto Cortex XSOAR / Google SecOps SOAR).
  • threatintel — Threat Intelligence: database IOC + pencocokan ke telemetri
                NYATA + import feed (gaya MISP / OTX / abuse.ch).
  • ueba      — User & Entity Behavior Analytics: baseline perilaku + skor
                anomali per entitas (gaya Securonix / Exabeam).
  • ai        — Mesin triase AI LOKAL (Naive Bayes + heuristik + NLG), tanpa
                API/token eksternal; jalan otomatis saat aplikasi dijalankan.
  • edr       — Endpoint Detection & Response: pohon proses (pid/ppid) +
                deteksi garis keturunan mencurigakan (gaya CrowdStrike/S1).
  • cloud     — Cloud Security Posture Management (CSPM): nilai konfigurasi
                cloud thd CIS + import Prowler (gaya Cortex/Defender for Cloud).
  • ndr       — Network Detection & Response: deteksi beaconing/C2, port scan,
                koneksi ke IOC (gaya Security Onion/Zeek + QRadar QFlow).

Stdlib-only — konsisten dengan komponen Fleet lain.
"""

try:
    from nexus_common import __version__  # noqa: F401 — sumber tunggal versi
except Exception:  # pragma: no cover — dijalankan lepas dari paket
    __version__ = "2.2.0"

from nexus_secops import siem          # noqa: E402,F401
from nexus_secops import correlate     # noqa: E402,F401
from nexus_secops import soar          # noqa: E402,F401
from nexus_secops import threatintel   # noqa: E402,F401
from nexus_secops import ueba          # noqa: E402,F401
from nexus_secops import ai            # noqa: E402,F401
from nexus_secops import edr           # noqa: E402,F401
from nexus_secops import cloud         # noqa: E402,F401
from nexus_secops import ndr           # noqa: E402,F401
# Fitur ekosistem (W1-W4)
from nexus_secops import canary        # noqa: E402,F401
from nexus_secops import aware         # noqa: E402,F401
from nexus_secops import atlas         # noqa: E402,F401
from nexus_secops import comply        # noqa: E402,F401
from nexus_secops import packs         # noqa: E402,F401
from nexus_secops import edge          # noqa: E402,F401

__all__ = ["siem", "correlate", "soar", "threatintel", "ueba", "ai", "edr", "cloud",
           "ndr", "canary", "aware", "atlas", "comply", "packs", "edge", "__version__"]

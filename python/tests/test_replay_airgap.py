# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# tests/test_replay_airgap.py
"""Uji Wave 2: time-travel replay (scrubber forensik), air-gapped mode, dan
bundle threat-intel offline."""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "fleet"))
os.environ["NEXUS_FLEET_DB"] = os.path.join(tempfile.mkdtemp(), "wave2.db")

from nexus_manager import server as mgr            # noqa: E402
from nexus_common import schema                    # noqa: E402
from nexus_secops import threatintel as ti         # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        _fail += 1


def main():
    mgr.init_db()
    now = mgr.fc.now()

    # --- Time-travel replay atas event NYATA ---
    c = mgr._conn()
    seq = [("failed_login", "medium", "Login gagal"),
           ("process_snapshot", "low", "Snapshot proses"),
           ("ioc_match", "high", "IOC cocok")]
    for i, (et, sev, title) in enumerate(seq):
        ev = schema.normalize_event({"type": et, "event_type": et, "severity": sev,
                                     "title": title, "detail": f"d{i}", "origin": "real"})
        ev = schema.enrich_event(ev, agent_id="agt1", tenant_id="default", host={})
        ev["ts"] = now - 100 + i * 10
        mgr._insert_event(c, ev, "agt1", "default", {})
    c.commit(); c.close()

    r = mgr.replay(agent_id="agt1", from_ts=now - 200, to_ts=now + 10)
    check("replay mengumpulkan 3 frame", r["frame_count"] == 3)
    check("frame terurut kronologis",
          all(r["frames"][i]["ts"] <= r["frames"][i + 1]["ts"]
              for i in range(len(r["frames"]) - 1)))
    check("hitungan kumulatif benar", r["frames"][-1]["cum_events"] == r["events"])
    r2 = mgr.replay(agent_id="agt-lain", from_ts=now - 200, to_ts=now + 10)
    check("scope agent menyaring", r2["frame_count"] == 0)

    # --- Air-gapped ---
    check("default tidak air-gapped", mgr.is_air_gapped() is False)
    mgr.set_air_gapped(True)
    check("air-gapped aktif", mgr.is_air_gapped() is True)
    check("status menjelaskan air-gapped", "air-gapped" in mgr.air_gapped_status()["note"])
    mgr.set_air_gapped(False)
    check("air-gapped nonaktif", mgr.is_air_gapped() is False)

    # --- Bundle threat-intel offline ---
    ti.add_iocs([{"type": "ip", "value": "203.0.113.5"},
                 {"type": "domain", "value": "evil.test"}], "manual", "default")
    b = mgr.ti_export_bundle("default")
    check("export bundle format + count", b["format"] == "nexus-ti-bundle/1" and b["count"] >= 2)
    imp = mgr.ti_import_bundle(b, "default")
    check("reimport bundle idempoten", imp.get("ok") and imp.get("updated", 0) >= 2)
    check("bundle invalid ditolak", mgr.ti_import_bundle({"x": 1}, "default")["ok"] is False)

    print("\nSEMUA TES WAVE 2 LULUS." if not _fail else f"\n{_fail} TES WAVE 2 GAGAL.")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())

# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# tests/test_comply.py
"""Uji Nexus Comply: pemetaan UU PDP + ISO 27001 dengan skor cakupan yang
mencerminkan keadaan NYATA (deterministik, tanpa AI)."""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "fleet"))
os.environ["NEXUS_FLEET_DB"] = os.path.join(tempfile.mkdtemp(), "comply.db")
os.environ.pop("NEXUS_MASTER_KEY", None)

from nexus_manager import server as mgr            # noqa: E402
from nexus_secops import comply, threatintel as ti, soar   # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        _fail += 1


def main():
    mgr.init_db()

    fws = mgr.comply_frameworks()
    check("dua framework (uu-pdp, iso27001)",
          {f["id"] for f in fws["frameworks"]} == {"uu-pdp", "iso27001"})

    base = mgr.comply_report("uu-pdp")
    check("laporan punya summary + controls + gaps",
          all(k in base for k in ("summary", "controls", "gaps")))
    s0 = base["summary"]
    check("baseline punya gap & kontrol manual", s0["gap"] > 0 and s0["manual"] >= 1)
    check("gap menyertakan rekomendasi",
          all(g["recommendation"] for g in base["gaps"]))

    # Aktifkan kontrol NYATA → cakupan harus naik
    os.environ["NEXUS_MASTER_KEY"] = "x" * 32
    ti.add_iocs([{"type": "ip", "value": "203.0.113.9"}], "manual", "default")
    mgr.canary_mint("url", "umpan")
    mgr.add_notify_channel({"type": "telegram", "bot_token": "1:2", "chat_id": "-1"})
    soar.save_playbook({"id": "PB-X", "name": "x", "trigger": {"on": "alert"},
                        "steps": [{"action": "notify"}], "enabled": True}, "default")

    after = mgr.comply_report("uu-pdp")["summary"]
    check("cakupan naik setelah fitur diaktifkan", after["covered"] > s0["covered"])
    check("threat_intel/deception/breach/incident kini covered", after["coverage_percent"] >= 60)

    iso = mgr.comply_report("iso27001")
    check("iso27001 >=10 kontrol", iso["summary"]["total"] >= 10)
    check("iso27001 punya tema teknologi",
          any(c["theme"] == "Technological" for c in iso["controls"]))

    bad = comply.report("entah-apa", {})
    check("framework tak dikenal ditolak", bad["ok"] is False)

    print("\nSEMUA TES COMPLY LULUS." if not _fail else f"\n{_fail} TES COMPLY GAGAL.")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())

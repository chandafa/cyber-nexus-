#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.ueba — baseline perilaku + skor anomali dari event NYATA.

Membangun baseline dari riwayat sungguhan, lalu memverifikasi sinyal anomali
(lonjakan volume, luar jam, tipe baru, eskalasi severity, outlier peer), emisi
event behavior_anomaly → alert NEXUS-UEBA-001, rantai UEBA→XDR, dan kontrol
negatif (entitas normal tak ditandai).
"""
import os
import sys
import tempfile
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)
sys.path.insert(0, os.path.join(PYDIR, "fleet"))

_tmp = tempfile.mkdtemp(prefix="nexus_ueba_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_common import protocol as fc        # noqa: E402
from nexus_common import schema                # noqa: E402
from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import ueba                  # noqa: E402
from nexus_secops import correlate as xdr      # noqa: E402

FAILED = []
NOW = fc.now()
CUR_HOUR = time.localtime(NOW).tm_hour


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def ts_at(days_ago, hour):
    lt = time.localtime(NOW)
    base = (lt.tm_year, lt.tm_mon, lt.tm_mday, hour % 24, 0, 0, 0, 0, -1)
    return int(time.mktime(base) - days_ago * 86400)


def ev(agent, etype, sev, ts):
    e = schema.normalize_event({"type": etype + "_t", "event_type": etype, "severity": sev,
                                "title": etype, "ts": ts})
    e = schema.enrich_event(e, agent_id=agent, tenant_id="default", host={})
    c = mgr._conn(); mgr._insert_event(c, e, agent, "default", {}); c.commit(); c.close()


def alert(agent, rule_id, event_type, level, ts):
    rule = {"id": rule_id, "name": rule_id, "level": level, "mitre": []}
    e = schema.normalize_event({"type": event_type, "event_type": event_type,
                                "severity": "high", "title": event_type, "ts": ts})
    e = schema.enrich_event(e, agent_id=agent, tenant_id="default", host={})
    al = schema.make_alert(agent, rule, e, "default", ts=ts)
    c = mgr._conn(); mgr._insert_alert(c, al); c.commit(); c.close()


def main():
    mgr.init_db()

    # Baseline: agt_norm aktif di jam (cur+8..+10) — JAUH dari jam sekarang, supaya
    # aktivitas "sekarang" terhitung di-luar-jam. agt_quiet aktif termasuk jam sekarang.
    norm_hours = [(CUR_HOUR + 8) % 24, (CUR_HOUR + 9) % 24, (CUR_HOUR + 10) % 24]
    quiet_hours = [CUR_HOUR, (CUR_HOUR + 1) % 24, (CUR_HOUR + 2) % 24]
    print("== Seed riwayat 14 hari (baseline NYATA) ==")
    for d in range(1, 15):
        for h in norm_hours:
            for _ in range(5):
                ev("agt_norm", "user_login", "low", ts_at(d, h))
        for h in quiet_hours:
            for _ in range(5):
                ev("agt_quiet", "user_login", "low", ts_at(d, h))

    print("== Train baseline ==")
    tr = ueba.train(lookback=20 * 86400)
    check("baseline terlatih utk 2 entitas", tr["trained"] == 2)
    bl = ueba.list_baselines()["baselines"]
    nb = [b for b in bl if b["entity"] == "agt_norm"]
    check("agt_norm punya baseline", len(nb) == 1)
    check("jam aktif baseline tak termasuk jam sekarang",
          nb and CUR_HOUR not in nb[0]["active_hours"])

    # Anomali agt_norm SEKARANG (setelah train, jadi tak mengotori baseline):
    # 60 login (lonjakan volume + luar jam) + 6 proses ransomware kritikal (tipe baru + severity).
    print("== Suntik perilaku anomali (setelah train) ==")
    for i in range(60):
        ev("agt_norm", "user_login", "low", NOW - 60 - i)
    for i in range(6):
        ev("agt_norm", "ransomware_exec", "critical", NOW - 30 - i)
    # agt_quiet: aktivitas normal sekarang (jam aktif, tipe dikenal, volume kecil)
    for i in range(4):
        ev("agt_quiet", "user_login", "low", NOW - 50 - i)

    print("== Skor anomali ==")
    sc = ueba.score(window=86400)
    ents = {e["entity"]: e for e in sc["entities"]}
    check("agt_norm terdeteksi anomali", "agt_norm" in ents)
    check("agt_norm band high", ents.get("agt_norm", {}).get("band") == "high")
    signals = {r["signal"] for r in ents.get("agt_norm", {}).get("reasons", [])}
    check("sinyal lonjakan volume", "volume_spike" in signals)
    check("sinyal aktivitas luar jam", "off_hours" in signals)
    check("sinyal tipe aktivitas baru", "new_activity" in signals)
    check("sinyal eskalasi severity", "severity_escalation" in signals)
    check("agt_quiet (normal) TIDAK ditandai", "agt_quiet" not in ents)

    print("== Emit anomali → alert NEXUS-UEBA-001 (via manager, NYATA) ==")
    es = mgr.ueba_scan(window=86400, emit=True)
    check("anomali high di-emit", es["emitted"] >= 1)
    alerts = mgr.list_alerts(500)["alerts"]
    ua = [a for a in alerts if a["rule_id"] == "NEXUS-UEBA-001" and a["agent_id"] == "agt_norm"]
    check("alert NEXUS-UEBA-001 terbuat utk agt_norm", len(ua) >= 1)

    print("== Rantai UEBA → XDR ==")
    alert("agt_norm", "NEXUS-PROC-001", "suspicious_process", 12, NOW - 100)
    xdr.correlate(lookback=7200)
    incs = xdr.list_incidents()["incidents"]
    c2 = [i for i in incs if i["rule_id"] == "XDR-UEBA-001" and i["entity"] == "agt_norm"]
    check("insiden XDR-UEBA-001 (anomali + proses) terbentuk", len(c2) == 1)

    print("== Analisis peer-group (outlier gagal-login) ==")
    for i in range(2):
        ev("agt_p1", "failed_login", "medium", NOW - 200 - i)
    ev("agt_p2", "failed_login", "medium", NOW - 210)
    ev("agt_p3", "failed_login", "medium", NOW - 220)
    for i in range(25):
        ev("agt_evil", "failed_login", "high", NOW - 100 - i)
    peers = ueba.peer_analysis(window=86400)
    check("agt_evil terdeteksi outlier peer", "agt_evil" in peers["outliers"])
    check("entitas normal bukan outlier", "agt_p1" not in peers["outliers"])

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES UEBA LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

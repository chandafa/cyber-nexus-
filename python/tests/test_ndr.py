#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.ndr — deteksi ancaman jaringan dari telemetri koneksi NYATA.

Memverifikasi: deteksi beaconing (periodisitas/jitter rendah), port scan,
koneksi ke IOC (integrasi Threat Intel), kontrol negatif (lalu lintas tak teratur),
dan jalur end-to-end manager (network_snapshot → alert NEXUS-NDR-001 → XDR).
"""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)
sys.path.insert(0, os.path.join(PYDIR, "fleet"))

_tmp = tempfile.mkdtemp(prefix="nexus_ndr_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_common import protocol as fc        # noqa: E402
from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import ndr                   # noqa: E402
from nexus_secops import threatintel as ti     # noqa: E402
from nexus_secops import correlate as xdr      # noqa: E402

FAILED = []
NOW = fc.now()


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def seed_flows(agent, rows):
    """rows: list (dst, dport, ts) → insert observasi koneksi langsung."""
    c = mgr._conn()
    ndr.ensure_tables(c)
    for dst, dport, ts in rows:
        c.execute("INSERT INTO ndr_flows(agent_id,tenant_id,ts,src,dst,dport,proto,bytes) "
                  "VALUES(?,?,?,?,?,?,?,?)", (agent, "default", ts, "10.0.0.5", dst, dport, "tcp", 0))
    c.commit(); c.close()


def main():
    mgr.init_db()

    print("== Deteksi beaconing C2 (koneksi periodik, jitter rendah) ==")
    # Beacon ke 203.0.113.10:443 tiap ~60 dtk dgn jitter kecil (8 kali).
    beacon = [("203.0.113.10", 443, NOW - 480 + i * 60 + (i % 2)) for i in range(8)]
    seed_flows("agt_x", beacon)
    f = {x["kind"]: x for x in ndr.detect("agt_x", 3600)}
    check("beaconing terdeteksi", "beaconing" in f)
    check("interval beacon ~60s", "beaconing" in f and 55 <= f["beaconing"]["evidence"]["interval_s"] <= 65)
    check("tujuan beacon benar", "beaconing" in f and f["beaconing"]["dst"] == "203.0.113.10")

    print("== Kontrol negatif: lalu lintas tak teratur bukan beacon ==")
    irregular = [("198.51.100.20", 443, NOW - 500 + d) for d in (0, 7, 90, 130, 400, 600)]
    seed_flows("agt_y", irregular)
    fy = {x["kind"]: x for x in ndr.detect("agt_y", 3600)}
    check("lalu lintas acak TIDAK ditandai beacon",
          "beaconing" not in fy or fy.get("beaconing", {}).get("dst") != "198.51.100.20")

    print("== Deteksi port scan (banyak port tujuan) ==")
    scan = [("203.0.113.50", 1000 + p, NOW - 200 + p) for p in range(20)]
    seed_flows("agt_scan", scan)
    fs = {x["kind"]: x for x in ndr.detect("agt_scan", 3600)}
    check("port scan terdeteksi", "port_scan" in fs)
    check("scan menghitung port berbeda", "port_scan" in fs and fs["port_scan"]["evidence"]["distinct_ports"] >= 15)

    print("== Koneksi ke IOC (integrasi Threat Intel) ==")
    ti.add_iocs([{"value": "203.0.113.66", "threat": "cobalt-strike"}], source="test")
    seed_flows("agt_c2", [("203.0.113.66", 8080, NOW - 100)])
    fc2 = {x["kind"]: x for x in ndr.detect("agt_c2", 3600)}
    check("koneksi ke IOC dikenal → c2_known (kritis)",
          "c2_known" in fc2 and fc2["c2_known"]["severity"] == "critical")
    check("c2 menyebut ancaman dari TI", "c2_known" in fc2 and "cobalt" in fc2["c2_known"]["detail"].lower())

    print("== IP privat tak dianggap beacon eksternal ==")
    internal = [("192.168.1.10", 445, NOW - 480 + i * 60) for i in range(8)]
    seed_flows("agt_int", internal)
    fi = {x["kind"]: x for x in ndr.detect("agt_int", 3600)}
    check("beacon ke IP privat diabaikan", "beaconing" not in fi)

    print("== End-to-end manager: network_snapshot → alert NEXUS-NDR-001 ==")
    # Beacon bersih 16 titik berakhir di NOW-60 (cadence 60s); flow yg di-ingest di
    # ~NOW melanjutkan cadence → tetap terdeteksi beacon (jitter rendah).
    seed_flows("agt_e2e", [("203.0.113.99", 443, NOW - 60 * (16 - i)) for i in range(16)])
    ruleset = mgr.get_rules()
    c = mgr._conn()
    ev = {"event_type": "network_snapshot", "event_id": "evt_net1",
          "data": {"flows": [{"src": "10.0.0.9", "dst": "203.0.113.99", "dport": 443}]}}
    n_ev, n_al = mgr._run_ndr(c, ev, ruleset, "agt_e2e", "default", {})
    c.commit(); c.close()
    check("event network_threat dibuat", n_ev >= 1)
    alerts = mgr.list_alerts(500)["alerts"]
    nd_alerts = [a for a in alerts if a["rule_id"] == "NEXUS-NDR-001" and a["agent_id"] == "agt_e2e"]
    check("alert NEXUS-NDR-001 terbuat", len(nd_alerts) >= 1)

    print("== Regресi: deteksi IOC saat ingest manager (anti cross-connection lock) ==")
    # dst flow cocok IOC; dijalankan lewat _run_ndr (transaksi ingest terbuka) — dulu
    # ti.match_value membuka koneksi kedua → 'database is locked' & C2 hilang diam-diam.
    ti.add_iocs([{"value": "203.0.113.200", "threat": "emotet"}], source="feed")
    c = mgr._conn()
    ev2 = {"event_type": "network_snapshot", "event_id": "evt_c2",
           "data": {"flows": [{"src": "10.0.0.3", "dst": "203.0.113.200", "dport": 8443}]}}
    n_ev2, n_al2 = mgr._run_ndr(c, ev2, mgr.get_rules(), "agt_ioc", "default", {})
    c.commit(); c.close()
    al2 = [a for a in mgr.list_alerts(500)["alerts"]
           if a["rule_id"] == "NEXUS-NDR-001" and a["agent_id"] == "agt_ioc"]
    check("koneksi ke IOC terdeteksi saat ingest (tanpa lock)", len(al2) >= 1)
    check("alert C2 menyebut ancaman dari TI",
          any("emotet" in (a.get("title", "") + str(a.get("evidence", {}))).lower() for a in al2))

    print("== Top talkers & stats ==")
    tt = ndr.top_talkers(3600)["talkers"]
    check("top talkers hanya tujuan eksternal", all(t["external"] for t in tt))
    check("stats melaporkan observasi", ndr.stats()["observations"] > 0)

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES NDR LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

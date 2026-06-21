#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.threatintel — IOC store + pencocokan ke telemetri NYATA.

Memverifikasi: deteksi tipe, penolakan IP privat, ekstraksi observable dari event
asli, retro-hunt membuat alert ioc_match (mengalir ke rule NEXUS-TI-001), dedup,
rantai TI→XDR(C2)→SOAR, dan import_feed NYATA (urllib file://).
"""
import os
import pathlib
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

_tmp = tempfile.mkdtemp(prefix="nexus_ti_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_common import protocol as fc        # noqa: E402
from nexus_common import schema                # noqa: E402
from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import threatintel as ti     # noqa: E402
from nexus_secops import correlate as xdr      # noqa: E402
from nexus_secops import soar                  # noqa: E402

FAILED = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def _event(agent_id, etype, title, detail, ts, evidence=None, target=None):
    ev = schema.normalize_event({"type": etype, "event_type": etype, "severity": "medium",
                                 "title": title, "detail": detail, "ts": ts,
                                 "evidence": evidence or {}, "target": target or {}})
    ev = schema.enrich_event(ev, agent_id=agent_id, tenant_id="default", host={})
    c = mgr._conn(); mgr._insert_event(c, ev, agent_id, "default", {}); c.commit(); c.close()
    return ev["event_id"]


def _alert(agent_id, rule_id, event_type, level, ts):
    rule = {"id": rule_id, "name": rule_id, "level": level, "mitre": []}
    ev = schema.normalize_event({"type": event_type, "event_type": event_type,
                                 "severity": "high", "title": event_type, "ts": ts})
    ev = schema.enrich_event(ev, agent_id=agent_id, tenant_id="default", host={})
    al = schema.make_alert(agent_id, rule, ev, "default", ts=ts)
    c = mgr._conn(); mgr._insert_alert(c, al); c.commit(); c.close()


def main():
    mgr.init_db()
    now = fc.now()

    print("== Deteksi tipe IOC ==")
    check("IP terdeteksi", ti.detect_type("203.0.113.66") == "ip")
    check("domain terdeteksi", ti.detect_type("evil-c2.example") == "domain")
    check("URL terdeteksi", ti.detect_type("http://bad.test/x") == "url")
    check("sha256 terdeteksi", ti.detect_type("a" * 64) == "sha256")
    check("md5 terdeteksi", ti.detect_type("b" * 32) == "md5")
    check("sampah bukan IOC", ti.detect_type("bukan ioc") is None)

    print("== Tambah IOC (auto-deteksi, tolak IP privat & sampah) ==")
    r = ti.add_iocs([
        "203.0.113.66",                              # IP jahat
        {"value": "evil-c2.example", "threat": "cobalt-strike", "severity": "critical"},
        "c" * 64,                                    # sha256 malware
        "192.168.1.5",                               # IP privat -> DITOLAK
        "halo dunia",                                # sampah -> DITOLAK
    ], source="unit-test")
    check("3 IOC ditambah", r["added"] == 3)
    check("2 ditolak (privat + sampah)", r["skipped"] == 2)

    s = ti.stats()
    check("stats total_iocs=3", s["total_iocs"] == 3)
    check("stats by_type ip=1, domain=1, sha256=1",
          s["by_type"]["ip"] == 1 and s["by_type"]["domain"] == 1 and s["by_type"]["sha256"] == 1)

    print("== match_event: ekstrak observable dari event NYATA ==")
    test_ev = {"title": "Koneksi keluar", "detail": "menghubungi evil-c2.example",
               "evidence": {"src_ip": "203.0.113.66"}, "target": {}, "data": {},
               "event_id": "evt_probe", "agent_id": "agt_x"}
    hits = ti.match_event(test_ev, record=False)
    vals = {h["value"] for h in hits}
    check("cocok IP penyerang", "203.0.113.66" in vals)
    check("cocok domain C2", "evil-c2.example" in vals)

    print("== Retro-hunt: alert ioc_match dari event yang sudah tersimpan ==")
    _event("agt_x", "network", "Outbound conn", "host menghubungi 203.0.113.66", now - 200,
           evidence={"src_ip": "203.0.113.66"})
    _event("agt_y", "log", "DNS query", "kueri ke evil-c2.example dari proses tak dikenal",
           now - 150)
    _event("agt_z", "log", "Bersih", "tak ada indikator di baris ini", now - 100)
    scan = mgr.threatintel_scan(lookback=3600)
    check("scan menemukan kecocokan", scan["ti_alerts"] >= 2)
    alerts = mgr.list_alerts(500)["alerts"]
    ti_alerts = [a for a in alerts if a["rule_id"] == "NEXUS-TI-001"]
    check("alert NEXUS-TI-001 terbuat", len(ti_alerts) >= 2)
    check("alert TI menyebut ancaman nyata",
          any("cobalt-strike" in (a.get("description", "") + a.get("title", "")).lower()
              or "evil-c2" in a.get("title", "").lower() for a in ti_alerts))

    matches = ti.list_matches()["matches"]
    check("ti_matches tercatat untuk audit", len(matches) >= 2)

    print("== Dedup: scan ulang tak membuat alert ganda ==")
    scan2 = mgr.threatintel_scan(lookback=3600)
    check("retro-hunt kedua: 0 alert baru (dedup)", scan2["ti_alerts"] == 0)

    print("== Rantai TI → XDR (C2) → SOAR ==")
    _alert("agt_x", "NEXUS-PROC-001", "suspicious_process", 12, now - 180)
    xdr.correlate(lookback=3600)
    incs = xdr.list_incidents()["incidents"]
    c2 = [i for i in incs if i["rule_id"] == "XDR-C2-001" and i["entity"] == "agt_x"]
    check("insiden XDR-C2-001 (IOC + proses) terbentuk", len(c2) == 1)

    soar.init_db()
    soar.process(lookback=3600)
    runs = soar.list_runs()["runs"]
    tib = [r for r in runs if r["playbook_id"] == "PB-TI-BLOCK" and r["entity"] == "agt_x"]
    check("playbook PB-TI-BLOCK terpicu oleh alert ioc_match", len(tib) >= 1)
    block = [s for s in tib[0]["steps"] if s["action"] == "block_ip"] if tib else []
    check("block_ip menyebut IP IOC nyata (dry_run)",
          block and "203.0.113.66" in block[0]["detail"])

    print("== import_feed NYATA via urllib (file://) ==")
    feed = pathlib.Path(_tmp) / "feodo.txt"
    feed.write_text("# Feodo Tracker botnet C2 IPs\n; comment\n198.51.100.7\n198.51.100.8 443\n",
                    encoding="utf-8")
    imp = ti.import_feed(feed.as_uri(), fmt="text", threat="feodo", severity="high")
    check("feed terunduh & diparse", imp["ok"] and imp["fetched"] == 2)
    check("2 IOC feed ditambah", imp["added"] == 2)
    got = ti.list_iocs(q="198.51.100.7")["iocs"]
    check("IOC feed tersimpan & dpt dicari", any(i["value"] == "198.51.100.7" for i in got))

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES THREAT INTEL LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

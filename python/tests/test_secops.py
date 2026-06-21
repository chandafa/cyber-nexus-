#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops: SIEM (NQL search/stats) + XDR (korelasi kill-chain).

Beroperasi atas store NYATA manager (tabel events/alerts SQLite, DB terisolasi)
— bukan demo. Membangun alert sungguhan via schema.make_alert lalu memverifikasi
mesin korelasi menggabungkannya jadi insiden.
"""
import os
import sys
import tempfile

# Windows: paksa stdout UTF-8 agar karakter non-ASCII (panah, dsb.) tak crash cp1252.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)
sys.path.insert(0, os.path.join(PYDIR, "fleet"))

_tmp = tempfile.mkdtemp(prefix="nexus_secops_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_common import protocol as fc        # noqa: E402
from nexus_common import schema                # noqa: E402
from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import siem                  # noqa: E402
from nexus_secops import correlate as xdr      # noqa: E402

FAILED = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def _insert_event(agent_id, etype, severity, title, ts, target=None, data=None):
    ev = schema.normalize_event({"type": etype, "event_type": etype, "severity": severity,
                                 "title": title, "ts": ts, "target": target or {},
                                 "data": data or {}})
    ev = schema.enrich_event(ev, agent_id=agent_id, tenant_id="default", host={})
    c = mgr._conn()
    mgr._insert_event(c, ev, agent_id, "default", {})
    c.commit(); c.close()


def _insert_alert(agent_id, rule_id, event_type, level, ts, severity="high", target=None):
    rule = {"id": rule_id, "name": rule_id, "level": level, "mitre": ["T1110"]}
    ev = schema.normalize_event({"type": event_type, "event_type": event_type,
                                 "severity": severity, "title": f"{event_type} on {agent_id}",
                                 "ts": ts, "target": target or {}})
    ev = schema.enrich_event(ev, agent_id=agent_id, tenant_id="default", host={})
    al = schema.make_alert(agent_id, rule, ev, "default", ts=ts)
    c = mgr._conn()
    mgr._insert_alert(c, al)
    c.commit(); c.close()
    return al["id"]


def main():
    mgr.init_db()
    now = fc.now()

    # ----------------------------------------------------------------- SIEM
    print("== SIEM: seed events nyata ==")
    _insert_event("agt_web01", "failed_logins", "high", "5 failed SSH logins", now - 100,
                  data={"count": 5})
    _insert_event("agt_web01", "sca", "medium", "SCA: SSH PermitRootLogin yes", now - 90)
    _insert_event("agt_web01", "fim_change", "critical", "/var/www/.env diubah", now - 80,
                  target={"path": "/var/www/app/.env"})
    _insert_event("agt_db01", "disk", "low", "Disk 70% pada /", now - 70)

    print("== SIEM: NQL search ==")
    r = siem.search("events", "severity:high")
    check("equals severity:high → 1", r["ok"] and r["count"] == 1)

    r = siem.search("events", "severity>=high")
    check("severity>=high → 2 (high+critical)", r["ok"] and r["count"] == 2)

    r = siem.search("events", "event_type:failed_logins,sca")
    check("IN (koma) → 2", r["ok"] and r["count"] == 2)

    r = siem.search("events", "agent_id:agt_web01 -severity:critical")
    check("NEGASI -severity:critical → 2 dari web01", r["ok"] and r["count"] == 2)

    r = siem.search("events", "title:*failed*")
    check("wildcard title:*failed* → 1", r["ok"] and r["count"] == 1)

    r = siem.search("events", '"failed SSH"')
    check("frasa bebas → 1", r["ok"] and r["count"] == 1)

    r = siem.search("events", "target.path:*.env")
    check("JSON bertingkat target.path:*.env → 1", r["ok"] and r["count"] == 1)

    r = siem.search("events", "last:1h")
    check("last:1h → 4 (semua < 1 jam)", r["ok"] and r["count"] == 4)

    r = siem.search("events", "last:30s")
    check("last:30s → 0 (tak ada < 30 dtk)", r["ok"] and r["count"] == 0)

    r = siem.search("events", "kolompalsu:x")
    check("kolom tak dikenal → error", not r["ok"])

    bad = siem.explain("last:99x")
    check("explain last invalid → error", not bad["ok"])

    print("== SIEM: agregasi/stats ==")
    s = siem.stats("events", "")
    check("stats total = 4", s["ok"] and s["total"] == 4)
    check("stats by_severity critical=1", s["by_severity"]["critical"] == 1)
    check("stats timeline ada bucket", len(s["timeline"]) >= 1)

    # ----------------------------------------------------------------- XDR
    print("== XDR: kill-chain brute-force → proses mencurigakan ==")
    _insert_alert("agt_web01", "NEXUS-AUTH-001", "failed_logins", 12, now - 600)
    _insert_alert("agt_web01", "NEXUS-PROC-001", "suspicious_process", 12, now - 540)
    out = xdr.correlate(lookback=3600)
    check("korelasi membuat >=1 insiden", out["ok"] and out["created"] >= 1)

    inc = xdr.list_incidents()
    chain = [i for i in inc["incidents"] if i["rule_id"] == "XDR-INTRUSION-001"]
    check("insiden XDR-INTRUSION-001 muncul", len(chain) == 1)
    check("insiden entity = agt_web01", chain and chain[0]["entity"] == "agt_web01")
    check("insiden level 14 (critical)", chain and chain[0]["level"] == 14)
    check("insiden menggabungkan 2 alert", chain and chain[0]["count"] == 2)

    full = xdr.get_incident(chain[0]["id"])
    check("get_incident timeline 2 tahap", full["ok"] and len(full["incident"]["timeline"]) == 2)
    check("timeline terurut waktu",
          full["incident"]["timeline"][0]["ts"] <= full["incident"]["timeline"][1]["ts"])

    print("== XDR: idempoten (jalankan ulang tak duplikasi) ==")
    out2 = xdr.correlate(lookback=3600)
    inc2 = xdr.list_incidents()
    n_intrusion = len([i for i in inc2["incidents"] if i["rule_id"] == "XDR-INTRUSION-001"])
    check("re-run tidak menduplikasi insiden", n_intrusion == 1)
    check("re-run menghitung sebagai 'updated'", out2["updated"] >= 1)

    print("== XDR: ack insiden ==")
    a = xdr.ack_incident(chain[0]["id"], "resolved")
    check("ack resolved ok", a["ok"])
    openinc = xdr.list_incidents(status="open")
    check("insiden resolved hilang dari status=open",
          all(i["id"] != chain[0]["id"] for i in openinc["incidents"]))

    print("== XDR: negatif — sinyal tunggal tak memicu kill-chain ==")
    _insert_alert("agt_lonely", "NEXUS-AUTH-001", "failed_logins", 12, now - 300)
    xdr.correlate(lookback=3600)
    inc3 = xdr.list_incidents()
    check("agent dgn 1 tahap saja → tak ada insiden intrusion",
          all(i["entity"] != "agt_lonely" for i in inc3["incidents"]))

    print("== XDR: negatif — di luar jendela waktu tak memicu ==")
    _insert_alert("agt_slow", "NEXUS-AUTH-001", "failed_logins", 12, now - 9000)
    _insert_alert("agt_slow", "NEXUS-PROC-001", "suspicious_process", 12, now - 100)
    xdr.correlate(lookback=86400)            # keduanya terlihat, tapi jarak > window 1800s
    inc4 = xdr.list_incidents()
    check("dua tahap berjauhan (>window) → tak ada insiden",
          all(i["entity"] != "agt_slow" for i in inc4["incidents"]))

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES SECOPS LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

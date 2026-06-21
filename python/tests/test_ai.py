#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.ai — mesin triase LOKAL (tanpa API/token).

Memverifikasi: Naive Bayes belajar dari disposisi analis (benign vs threat),
triase insiden NYATA (prioritas/skor/ringkasan/rekomendasi), NL→NQL, autostart,
dan kejujuran (model belum terlatih → netral 0.5, bukan menebak).
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

_tmp = tempfile.mkdtemp(prefix="nexus_ai_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_common import protocol as fc        # noqa: E402
from nexus_common import schema                # noqa: E402
from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import ai                    # noqa: E402
from nexus_secops import correlate as xdr      # noqa: E402

FAILED = []
NOW = fc.now()


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def ins_alert(agent, rule_id, etype, level, ts, status="open", mitre=None, sev="high"):
    rule = {"id": rule_id, "name": rule_id, "level": level, "mitre": mitre or []}
    e = schema.normalize_event({"type": etype, "event_type": etype, "severity": sev,
                                "title": etype, "ts": ts})
    e = schema.enrich_event(e, agent_id=agent, tenant_id="default", host={})
    al = schema.make_alert(agent, rule, e, "default", ts=ts)
    al["status"] = status
    c = mgr._conn(); mgr._insert_alert(c, al); c.commit(); c.close()


def main():
    mgr.init_db()

    print("== Kejujuran: model belum terlatih → netral 0.5 (tak menebak) ==")
    ai._MODEL = None
    p = ai.predict_benign({"rule_id": "NEXUS-DISK-001", "severity": "low", "level": 6})
    check("predict netral 0.5 saat untrained", abs(p - 0.5) < 1e-9)
    check("model_status: untrained", not ai.model_status()["trained"])

    print("== Seed riwayat berlabel (disposisi analis NYATA) ==")
    # benign: ditutup analis 'resolved' & level rendah (noise berulang)
    for i in range(12):
        ins_alert(f"h{i}", "NEXUS-DISK-001", "disk_usage", 6, NOW - 5000 - i,
                  status="resolved", sev="low")
    # threat: tereskalasi / level tinggi
    for i in range(10):
        ins_alert(f"t{i}", "NEXUS-VULN-001", "cve_match", 13, NOW - 4000 - i,
                  status="ack", mitre=["T1190"], sev="high")
    # insiden agt_x: brute-force → proses mencurigakan (juga sampel threat)
    ins_alert("agt_x", "NEXUS-AUTH-001", "failed_login", 12, NOW - 600,
              mitre=["T1110"], sev="high")
    ins_alert("agt_x", "NEXUS-PROC-001", "suspicious_process", 12, NOW - 300,
              mitre=["T1059"], sev="high")

    print("== Latih classifier ==")
    tr = ai.train()
    check("model terlatih (cukup sampel)", tr["trained"])
    check("ada sampel kedua kelas", tr["by_class"]["benign"] >= 8 and tr["by_class"]["threat"] >= 8)

    print("== Classifier membedakan benign vs threat ==")
    pb = ai.predict_benign({"rule_id": "NEXUS-DISK-001", "category": "device_inventory",
                            "event_type": "disk_usage", "severity": "low", "level": 6})
    pt = ai.predict_benign({"rule_id": "NEXUS-AUTH-001", "event_type": "failed_login",
                            "severity": "high", "level": 12, "mitre": ["T1110"]})
    check("alert benign → P(benign) tinggi (>0.5)", pb > 0.5)
    check("alert threat → P(benign) rendah (<0.5)", pt < 0.5)

    print("== Triase insiden XDR NYATA ==")
    xdr.correlate(lookback=3600)
    incs = xdr.list_incidents()["incidents"]
    intr = [i for i in incs if i["rule_id"] == "XDR-INTRUSION-001" and i["entity"] == "agt_x"]
    check("insiden intrusi terbentuk utk ditriase", len(intr) == 1)
    t = ai.triage_incident(intr[0]["id"])
    check("triase sukses", t.get("ok"))
    check("prioritas P1 (kompromi aktif + model menilai ancaman)", t["priority"] == "P1")
    check("skor tinggi (>=70)", t["score"] >= 70)
    check("confidence terisi", 0 < t["confidence"] <= 100)
    check("ringkasan menyebut entitas & prioritas",
          "agt_x" in t["summary"] and "Prioritas" in t["summary"])
    check("rekomendasi punya aksi", len(t["recommendations"]["actions"]) >= 1)
    check("menyarankan playbook SOAR (PB-SUSPROC-KILL)",
          "PB-SUSPROC-KILL" in t["recommendations"]["suggested_playbooks"])

    print("== Hasil triase tersimpan & dapat di-list ==")
    lst = ai.list_triage()["triage"]
    check("triase tercatat", any(x["incident_id"] == intr[0]["id"] for x in lst))

    print("== NL → NQL (penerjemah bahasa, lokal) ==")
    q = ai.nl_query("cari gagal login minggu ini dari agt_x")
    check("NL: gagal login → event_type:failed_login", "event_type:failed_login" in q["nql"])
    check("NL: minggu ini → last:7d", "last:7d" in q["nql"])
    check("NL: entity → agent_id:agt_x", "agent_id:agt_x" in q["nql"])
    q2 = ai.nl_query("tampilkan insiden kritis")
    check("NL: insiden → index alerts", q2["index"] == "alerts")
    check("NL: kritis → severity>=critical", "severity>=critical" in q2["nql"])
    q3 = ai.nl_query("zxcvb qwerty")
    check("NL tanpa intent → fallback teks bebas", q3["matched"] == [])

    print("== Autostart (AI hidup saat aplikasi jalan) ==")
    a = ai.autostart()
    check("autostart ok", a["ok"])
    check("autostart melatih & mentriase", a["trained"] and a["triaged"] >= 1)

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES NEXUS AI LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

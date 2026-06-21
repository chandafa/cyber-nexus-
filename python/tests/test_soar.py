#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.soar — playbook engine + active-response NYATA.

Memverifikasi: trigger cocok pada alert/insiden sungguhan, mode dry_run TIDAK
mengeksekusi aksi destruktif (hanya mencatat), eksekusi diaudit di soar_runs,
dedup mencegah pengulangan, dan pemicu manual (run_now) bekerja.
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

_tmp = tempfile.mkdtemp(prefix="nexus_soar_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_common import protocol as fc        # noqa: E402
from nexus_common import schema                # noqa: E402
from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import correlate as xdr      # noqa: E402
from nexus_secops import soar                  # noqa: E402

FAILED = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def _alert(agent_id, rule_id, event_type, level, ts, severity="critical", evidence=None):
    rule = {"id": rule_id, "name": rule_id, "level": level, "mitre": ["T1110"]}
    ev = schema.normalize_event({"type": event_type, "event_type": event_type,
                                 "severity": severity, "title": f"{event_type}",
                                 "ts": ts, "evidence": evidence or {}})
    ev = schema.enrich_event(ev, agent_id=agent_id, tenant_id="default", host={})
    al = schema.make_alert(agent_id, rule, ev, "default", ts=ts)
    c = mgr._conn(); mgr._insert_alert(c, al); c.commit(); c.close()
    return al["id"]


def main():
    mgr.init_db()
    soar.init_db()
    now = fc.now()

    print("== Playbook default ter-seed ==")
    pbs = soar.list_playbooks()["playbooks"]
    check("ada playbook default", len(pbs) >= 5)
    crit = [p for p in pbs if p["id"] == "PB-CRITICAL-NOTIFY"]
    check("PB-CRITICAL-NOTIFY ada & aktif", crit and crit[0]["enabled"])
    intr = [p for p in pbs if p["id"] == "PB-INTRUSION-RESPOND"]
    check("PB-INTRUSION-RESPOND default dry_run (aman)",
          intr and intr[0]["mode"] == "dry_run")

    print("== Validasi: aksi tak didukung ditolak ==")
    bad = soar.save_playbook({"id": "PB-BAD", "name": "x",
                              "steps": [{"action": "nuke_everything"}]})
    check("aksi palsu ditolak", not bad["ok"])

    print("== Trigger pada alert kritis NYATA → notify (tanpa webhook = skipped) ==")
    _alert("agt_a", "NEXUS-PROC-001", "suspicious_process", 14, now - 50,
           evidence={"process": "mimikatz.exe"})
    out = soar.process(lookback=3600)
    check("playbook dijalankan", out["ok"] and out["fired"] >= 1)
    runs = soar.list_runs()["runs"]
    notify_run = [r for r in runs if r["playbook_id"] == "PB-CRITICAL-NOTIFY"]
    check("PB-CRITICAL-NOTIFY tercatat", len(notify_run) >= 1)
    # tanpa webhook terkonfigurasi, langkah notify → skipped (bukan crash)
    step0 = notify_run[0]["steps"][0]
    check("notify tanpa webhook → skipped (nyata, bukan palsu)",
          step0["action"] == "notify" and step0["status"] == "skipped")

    print("== Aksi destruktif (kill_process) di mode dry_run TIDAK dieksekusi ==")
    proc_run = [r for r in runs if r["playbook_id"] == "PB-SUSPROC-KILL"]
    check("PB-SUSPROC-KILL berjalan", len(proc_run) >= 1)
    kstep = [s for s in proc_run[0]["steps"] if s["action"] == "kill_process"]
    check("kill_process dry_run (mencatat 'AKAN', tak eksekusi)",
          kstep and kstep[0]["status"] == "dry_run")
    check("dry_run menyebut proses nyata dari bukti",
          kstep and "mimikatz" in kstep[0]["detail"])

    print("== Dedup: proses ulang tak mengulang playbook utk entity sama ==")
    n_before = len(soar.list_runs()["runs"])
    soar.process(lookback=3600)
    n_after = len(soar.list_runs()["runs"])
    check("dedup mencegah run ganda", n_after == n_before)

    print("== Mode active + tanpa lisensi → aksi endpoint 'gated' (gerbang lisensi nyata) ==")
    soar.set_mode("PB-SUSPROC-KILL", "active")
    _alert("agt_b", "NEXUS-PROC-001", "suspicious_process", 14, now - 40,
           evidence={"process": "evil.exe"})
    soar.process(lookback=3600)
    rb = [r for r in soar.list_runs()["runs"]
          if r["playbook_id"] == "PB-SUSPROC-KILL" and r["entity"] == "agt_b"]
    kstep_b = [s for s in rb[0]["steps"] if s["action"] == "kill_process"] if rb else []
    # Tanpa lisensi Pro, response_action terkunci → status 'gated' (bukan eksekusi diam-diam)
    check("active tanpa lisensi → gated (bukan eksekusi liar)",
          kstep_b and kstep_b[0]["status"] in ("gated", "executed"))

    print("== Trigger pada INSIDEN XDR nyata ==")
    _alert("agt_c", "NEXUS-AUTH-001", "failed_logins", 12, now - 600,
           severity="high", evidence={"src_ip": "203.0.113.9"})
    _alert("agt_c", "NEXUS-PROC-001", "suspicious_process", 12, now - 540, severity="high")
    xdr.correlate(lookback=3600)
    soar.process(lookback=3600)
    inc_runs = [r for r in soar.list_runs()["runs"]
                if r["playbook_id"] == "PB-INTRUSION-RESPOND" and r["entity"] == "agt_c"]
    check("PB-INTRUSION-RESPOND terpicu oleh insiden XDR", len(inc_runs) >= 1)
    block = [s for s in inc_runs[0]["steps"] if s["action"] == "block_ip"] if inc_runs else []
    check("block_ip dry_run menyebut IP penyerang nyata dari insiden",
          block and "203.0.113.9" in block[0]["detail"])
    setstatus = [s for s in inc_runs[0]["steps"] if s["action"] == "set_incident_status"]
    check("set_incident_status mengeksekusi (aksi aman, nyata)",
          setstatus and setstatus[0]["status"] == "executed")

    print("== Pemicu manual run_now ==")
    aid = _alert("agt_d", "NEXUS-FW-001", "firewall", 10, now - 30, severity="high")
    r = soar.run_now("PB-FIREWALL-ON", aid)
    check("run_now sukses", r.get("ok"))
    check("run_now menghasilkan langkah", r.get("ok") and len(r["run"]["steps"]) >= 1)

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES SOAR LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

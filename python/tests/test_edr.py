#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.edr — pohon proses & deteksi garis keturunan (kill-chain).

Memverifikasi: deteksi induk→anak mencurigakan (webshell, office→script, encoded),
penyusunan pohon ancestry dari pid/ppid NYATA, pelacakan kill-chain (ancestry),
dan jalur end-to-end manager (process_snapshot → alert NEXUS-EDR-001).
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

_tmp = tempfile.mkdtemp(prefix="nexus_edr_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import edr                   # noqa: E402

FAILED = []

# Snapshot proses NYATA-bentuk: systemd→nginx→bash→mimikatz (webshell→kredensial),
# winword→powershell (makro), sshd→powershell -enc (obfuscation), + proses normal.
PROCS = [
    {"pid": 1, "ppid": 0, "name": "systemd", "user": "root", "cmdline": "/sbin/init"},
    {"pid": 100, "ppid": 1, "name": "nginx", "user": "www-data", "cmdline": "nginx: worker"},
    {"pid": 200, "ppid": 100, "name": "bash", "user": "www-data", "cmdline": "bash -i"},
    {"pid": 300, "ppid": 200, "name": "mimikatz", "user": "www-data", "cmdline": "mimikatz sekurlsa"},
    {"pid": 400, "ppid": 1, "name": "winword.exe", "user": "user", "cmdline": "WINWORD.EXE doc.docm"},
    {"pid": 500, "ppid": 400, "name": "powershell.exe", "user": "user",
     "cmdline": "powershell.exe -nop -w hidden -enc ZQBjAGgAbwA="},
    {"pid": 600, "ppid": 1, "name": "sshd", "user": "root", "cmdline": "/usr/sbin/sshd"},
    {"pid": 700, "ppid": 600, "name": "powershell.exe", "user": "admin",
     "cmdline": "powershell.exe -EncodedCommand SQBFAFgA"},
    {"pid": 800, "ppid": 600, "name": "vim", "user": "admin", "cmdline": "vim notes.txt"},
]


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def find_node(nodes, name):
    for n in nodes:
        if n["name"] == name:
            return n
        hit = find_node(n["children"], name)
        if hit:
            return hit
    return None


def main():
    mgr.init_db()

    print("== Deteksi garis keturunan mencurigakan ==")
    f = {x["pid"]: x for x in edr.detect_lineage(PROCS)}
    check("webshell: nginx → bash terdeteksi (kritis)",
          200 in f and "web" in f[200]["rule"].lower() and f[200]["severity"] == "critical")
    check("tool jahat: mimikatz terdeteksi (kritis)",
          300 in f and f[300]["severity"] == "critical")
    check("makro: winword → powershell terdeteksi",
          500 in f and "office" in f[500]["rule"].lower())
    check("obfuscation: powershell -enc (sshd) terdeteksi",
          700 in f and "obfus" in f[700]["rule"].lower())
    check("proses normal (vim) TIDAK ditandai", 800 not in f)
    check("temuan menyertakan rantai induk→anak", 200 in f and "→" in f[200]["chain"])

    print("== Ingest snapshot & susun pohon ancestry ==")
    edr.ingest_snapshot("agt_x", PROCS)
    tree = edr.build_tree("agt_x")["tree"]
    root = find_node(tree, "systemd")
    check("akar systemd ada", root is not None)
    ng = find_node(tree, "nginx")
    check("nginx anak systemd", ng is not None and any(c["name"] == "bash" for c in ng["children"]))
    bash = find_node(tree, "bash")
    check("mimikatz anak bash (silsilah benar)",
          bash is not None and any(c["name"] == "mimikatz" for c in bash["children"]))
    mk = find_node(tree, "mimikatz")
    check("node berisiko ditandai utk dashboard", mk is not None and "risk" in mk)

    print("== Kill-chain: ancestry mundur ke akar ==")
    anc = edr.ancestry("agt_x", 300)
    names = [a["name"] for a in anc["ancestry"]]
    check("ancestry: systemd → nginx → bash → mimikatz",
          names == ["systemd", "nginx", "bash", "mimikatz"])
    check("kedalaman kill-chain 4", anc["depth"] == 4)

    print("== Inventori diganti tiap snapshot (bukan menumpuk) ==")
    edr.ingest_snapshot("agt_x", PROCS[:3])
    check("snapshot baru menggantikan lama", edr.list_processes("agt_x")["count"] == 3)
    edr.ingest_snapshot("agt_x", PROCS)         # kembalikan penuh

    print("== End-to-end via manager: process_snapshot → alert NEXUS-EDR-001 ==")
    ruleset = mgr.get_rules()
    c = mgr._conn()
    ev = {"event_type": "process_snapshot", "event_id": "evt_snap1",
          "data": {"processes": PROCS}}
    n_ev, n_al = mgr._run_edr(c, ev, ruleset, "agt_y", "default", {})
    c.commit(); c.close()
    check("event suspicious_lineage dibuat", n_ev >= 3)
    alerts = mgr.list_alerts(500)["alerts"]
    edr_alerts = [a for a in alerts if a["rule_id"] == "NEXUS-EDR-001" and a["agent_id"] == "agt_y"]
    check("alert NEXUS-EDR-001 terbuat (≥3)", len(edr_alerts) >= 3)
    check("alert menyebut rantai proses",
          any("→" in (a.get("title", "") + str(a.get("evidence", {}))) for a in edr_alerts))

    print("== Daftar host EDR ==")
    h = edr.hosts()["hosts"]
    check("agt_x & agt_y punya inventori proses",
          {x["agent_id"] for x in h} >= {"agt_x", "agt_y"})

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES EDR LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

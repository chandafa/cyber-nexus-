# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# tests/test_atlas.py
"""Uji Nexus Atlas (peta aset & attack-path / blast-radius): graf dari data NYATA
(agents + ndr_flows + alerts), BFS jangkauan + guard siklus, ranking paparan,
serta kasus DB kosong. Memakai DB sementara terisolasi, tanpa jaringan/AI."""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "fleet"))
os.environ["NEXUS_FLEET_DB"] = os.path.join(tempfile.mkdtemp(), "atlas_test.db")

from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import ndr                   # noqa: E402
from nexus_secops import atlas                 # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        _fail += 1


def _add_agent(c, agent_id, hostname, ip, os_name="linux"):
    """Sisipkan host ter-enroll ke tabel `agents` NYATA (subset kolom riil)."""
    c.execute(
        "INSERT INTO agents(agent_id,agent_key,name,hostname,os,ip,status,"
        "enrolled_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
        (agent_id, "k", hostname, hostname, os_name, ip, "active", 0, 0))


def _add_alert(c, agent_id, level, severity):
    """Sisipkan alert NYATA (subset kolom riil) untuk menurunkan risk node."""
    import time
    aid = "alt_" + agent_id + "_" + severity + "_" + str(time.time_ns())
    c.execute(
        "INSERT INTO alerts(id,ts,agent_id,tenant_id,level,severity,title) "
        "VALUES(?,?,?,?,?,?,?)",
        (aid, int(time.time()), agent_id, "default", level, severity, "t"))


def main():
    mgr.init_db()

    # ---- Kasus 1: DB kosong → ok dengan 0/0 -------------------------------
    g0 = atlas.build_graph("default")
    check("empty: build_graph ok, 0 node/edge",
          g0["ok"] and g0["node_count"] == 0 and g0["edge_count"] == 0)
    s0 = atlas.stats("default")
    check("empty: stats ok, 0/0", s0["ok"] and s0["nodes"] == 0 and s0["edges"] == 0)
    te0 = atlas.top_exposed("default")
    check("empty: top_exposed ok, kosong", te0["ok"] and te0["hosts"] == [])
    br0 = atlas.blast_radius("nope", "default")
    check("empty: blast_radius node tak ada → found False, score 0",
          br0["ok"] and br0["found"] is False and br0["score"] == 0)

    # ---- Bangun data NYATA -----------------------------------------------
    # Topologi:  A(.10) -> B(.20) -> C(.30) -> A  (siklus!),  B -> D(.40),
    #            A juga -> 8.8.8.8 (eksternal, bukan agent).
    c = mgr._conn()
    _add_agent(c, "agtA", "hostA", "10.0.0.10")
    _add_agent(c, "agtB", "hostB", "10.0.0.20")
    _add_agent(c, "agtC", "hostC", "10.0.0.30")
    _add_agent(c, "agtD", "hostD", "10.0.0.40")
    # Alerts → risk. A paling parah (compromised), B sedang.
    _add_alert(c, "agtA", 12, "critical")
    _add_alert(c, "agtA", 10, "high")
    _add_alert(c, "agtB", 6, "medium")
    c.commit(); c.close()

    # Flows NYATA via fungsi ingest riil ndr.ingest_flows (menulis ndr_flows).
    # Beberapa duplikat agar weight > 1 ter-de-dup.
    ndr.ingest_flows("agtA", [
        {"src": "10.0.0.10", "dst": "10.0.0.20", "dport": 22, "proto": "tcp"},
        {"src": "10.0.0.10", "dst": "10.0.0.20", "dport": 22, "proto": "tcp"},
        {"src": "10.0.0.10", "dst": "8.8.8.8", "dport": 443, "proto": "tcp"},
    ], "default")
    ndr.ingest_flows("agtB", [
        {"src": "10.0.0.20", "dst": "10.0.0.30", "dport": 445, "proto": "tcp"},
        {"src": "10.0.0.20", "dst": "10.0.0.40", "dport": 3389, "proto": "tcp"},
    ], "default")
    # siklus: C -> A
    ndr.ingest_flows("agtC", [
        {"src": "10.0.0.30", "dst": "10.0.0.10", "dport": 22, "proto": "tcp"},
    ], "default")

    # ---- build_graph ------------------------------------------------------
    g = atlas.build_graph("default")
    ids = {n["id"] for n in g["nodes"]}
    check("graph: 4 host enroll + 1 eksternal = 5 node",
          g["node_count"] == 5 and {"agtA", "agtB", "agtC", "agtD"} <= ids
          and "8.8.8.8" in ids)
    ext = [n for n in g["nodes"] if n["id"] == "8.8.8.8"]
    check("graph: node eksternal bertipe 'external'",
          ext and ext[0]["type"] == "external")
    # edges (de-dup): A->B, A->8.8.8.8, B->C, B->D, C->A = 5
    check("graph: 5 edge ter-de-dup", g["edge_count"] == 5)
    ab = [e for e in g["edges"] if e["src"] == "agtA" and e["dst"] == "agtB"]
    check("graph: edge A->B weight 2 (de-dup count)",
          ab and ab[0]["weight"] == 2)
    na = [n for n in g["nodes"] if n["id"] == "agtA"][0]
    check("graph: risk agtA = 12+10 = 22 (agregat alert)",
          na["risk"] == 22 and na["alert_count"] == 2)

    # ---- blast_radius (dengan SIKLUS A<->C) -------------------------------
    br = atlas.blast_radius("agtA", "default")
    # Dari A: B, C, D, 8.8.8.8 terjangkau (A sendiri tak masuk reachable).
    check("blast A: menjangkau {B,C,D,8.8.8.8}, tak hang pada siklus",
          br["found"] and set(br["reachable"]) == {"agtB", "agtC", "agtD", "8.8.8.8"}
          and br["reach_count"] == 4)
    check("blast A: score > 0 (reach + risk)", br["score"] > 4)
    # Dari D: buntu (tak ada edge keluar) → 0 terjangkau.
    brd = atlas.blast_radius("agtD", "default")
    check("blast D: buntu, reach 0", brd["found"] and brd["reach_count"] == 0)

    # ---- top_exposed ------------------------------------------------------
    te = atlas.top_exposed("default", limit=10)
    check("top_exposed: ok dan ada host", te["ok"] and len(te["hosts"]) >= 4)
    top = te["hosts"][0]
    # A = risk tinggi (22) + jangkauan luas (4) → paling exposed.
    check("top_exposed: agtA peringkat 1 (risk tinggi + jangkauan luas)",
          top["id"] == "agtA")
    # urutan exposure menurun
    exps = [h["exposure"] for h in te["hosts"]]
    check("top_exposed: terurut menurun by exposure", exps == sorted(exps, reverse=True))

    # ---- stats ------------------------------------------------------------
    st = atlas.stats("default")
    check("stats: 5 node / 5 edge, riskiest dipimpin agtA",
          st["nodes"] == 5 and st["edges"] == 5 and st["riskiest"]
          and st["riskiest"][0]["id"] == "agtA")

    print("\nSEMUA TES ATLAS LULUS." if not _fail else f"\n{_fail} TES ATLAS GAGAL.")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())

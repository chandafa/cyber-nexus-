# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/atlas.py
"""
Nexus Atlas — peta aset & jalur serangan (attack-path) + blast-radius.

Membangun GRAF armada dari data NYATA yang sudah ada di DB manager:
  • Node  = host/aset. Sumber: tabel `agents` (host ter-enroll) DITAMBAH host/IP
            apa pun yang muncul sebagai endpoint koneksi di tabel `ndr_flows`
            (src/dst) tapi belum ter-enroll (mis. server eksternal, peer).
  • Edge  = koneksi jaringan yang TERAMATI antar-host dari `ndr_flows` dalam
            jendela `window` detik (de-dup; weight = jumlah observasi).
  • risk  = turunan dari severity/level alert terbaru host tsb (dari `alerts`) —
            makin tinggi = makin terkompromi / berisiko.

Di atas graf ini dihitung:
  • blast_radius() — BFS dari satu node: "jika host ini jatuh, apa saja yang bisa
                     dijangkau (lateral movement)?" → reach set + skor paparan.
  • top_exposed()  — host paling berbahaya bila jatuh (risk × jangkauan).
  • stats()        — ringkasan graf untuk dashboard / tampilan Cytoscape.

Murni Python (adjacency dict, BFS iteratif) — tanpa lib graf eksternal, tanpa AI,
tanpa jaringan. Mirror konvensi modul sibling: header copyright, conn= opsional,
best-effort, return JSON-serializable dengan "ok".

Tabel yang DIBACA (tak menulis apa pun):
  agents(agent_id, name, hostname, ip, os, status, last_seen, tenant?)  — node enroll
  ndr_flows(agent_id, tenant_id, ts, src, dst, dport, proto, bytes)     — edge & node
  alerts(agent_id, tenant_id, ts, level, severity)                      — risk per node
"""
import sqlite3

# Bobot risiko per tingkat severity alert (selaras skala level alert NEXUS).
_SEV_WEIGHT = {
    "critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1,
    "warning": 3, "warn": 3, "informational": 1,
}
_MAX_DEPTH = 64          # batas kedalaman BFS (cegah graf patologis)
_FLOW_WINDOW = 604800    # default 7 hari


def _sa_conn():
    """Koneksi mandiri (di luar ingest). Memakai path DB manager yang sama —
    pola sama persis dengan nexus_secops.canary._sa_conn."""
    from nexus_common import protocol as fc
    c = sqlite3.connect(fc.manager_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    return c


def _now():
    try:
        from nexus_common import protocol as fc
        return fc.now()
    except Exception:
        import time
        return int(time.time())


def _table_exists(c, name):
    try:
        r = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                      (name,)).fetchone()
        return r is not None
    except Exception:
        return False


def _columns(c, table):
    try:
        return {row[1] for row in c.execute("PRAGMA table_info(%s)" % table).fetchall()}
    except Exception:
        return set()


def _sev_weight(sev):
    return _SEV_WEIGHT.get(str(sev or "").strip().lower(), 0)


# --------------------------------------------------------------------------- risk
def _risk_by_host(c, tenant):
    """Peta agent_id -> skor risiko, diturunkan dari alert terbaru host.
    risk = max(level, bobot-severity) di-agregat (sum bertumpuk) per agent.
    Robust bila tabel/kolom alerts tak ada → {}."""
    risk, alert_count = {}, {}
    if not _table_exists(c, "alerts"):
        return risk, alert_count
    cols = _columns(c, "alerts")
    if "agent_id" not in cols:
        return risk, alert_count
    sel = ["agent_id"]
    sel.append("level" if "level" in cols else "0 AS level")
    sel.append("severity" if "severity" in cols else "'' AS severity")
    where, params = "", []
    if "tenant_id" in cols:
        where = " WHERE tenant_id=?"
        params.append(tenant)
    try:
        rows = c.execute("SELECT %s FROM alerts%s" % (", ".join(sel), where),
                         params).fetchall()
    except Exception:
        return risk, alert_count
    for r in rows:
        aid = r["agent_id"]
        if not aid:
            continue
        try:
            lvl = int(r["level"] or 0)
        except (TypeError, ValueError):
            lvl = 0
        contrib = max(lvl, _sev_weight(r["severity"]))
        risk[aid] = risk.get(aid, 0) + contrib
        alert_count[aid] = alert_count.get(aid, 0) + 1
    return risk, alert_count


# --------------------------------------------------------------------------- nodes
def _enrolled_nodes(c, tenant):
    """Node dari host ter-enroll (tabel agents). Map id -> {label,type,ip,...}.
    Kunci edge mengacu ke IP host bila ada agar cocok dengan endpoint flow."""
    nodes = {}        # node_id -> attrs
    ip_to_id = {}     # ip -> node_id (untuk memetakan endpoint flow ke host enroll)
    if not _table_exists(c, "agents"):
        return nodes, ip_to_id
    cols = _columns(c, "agents")
    if "agent_id" not in cols:
        return nodes, ip_to_id
    want = ["agent_id", "name", "hostname", "ip", "os", "status"]
    sel = [col for col in want if col in cols]
    where, params = "", []
    if "tenant_id" in cols:
        where = " WHERE tenant_id=?"
        params.append(tenant)
    try:
        rows = c.execute("SELECT %s FROM agents%s" % (", ".join(sel), where),
                         params).fetchall()
    except Exception:
        return nodes, ip_to_id
    for r in rows:
        d = dict(r)
        aid = d.get("agent_id")
        if not aid:
            continue
        label = d.get("hostname") or d.get("name") or aid
        nodes[aid] = {
            "id": aid, "label": label, "type": "host",
            "ip": d.get("ip") or "", "os": d.get("os") or "",
            "status": d.get("status") or "",
        }
        ip = d.get("ip")
        if ip:
            ip_to_id[str(ip)] = aid
    return nodes, ip_to_id


def _resolve(endpoint, ip_to_id):
    """Petakan sebuah endpoint flow (IP/host) ke node_id host enroll bila cocok,
    selain itu endpoint itu sendiri menjadi node 'external'."""
    if not endpoint:
        return None
    ep = str(endpoint).strip()
    if not ep:
        return None
    return ip_to_id.get(ep, ep)


# --------------------------------------------------------------------------- graph
def build_graph(tenant="default", window=_FLOW_WINDOW, conn=None):
    """Bangun graf armada: node = host (enroll + endpoint flow), edge = koneksi
    teramati (de-dup, weight=count) dalam `window` detik. risk per node dari alert.

    -> {ok, nodes:[{id,label,type,risk,alert_count,...}],
        edges:[{src,dst,kind,weight}], node_count, edge_count}
    """
    own = conn is None
    c = conn or _sa_conn()
    try:
        risk, alert_count = _risk_by_host(c, tenant)
        nodes, ip_to_id = _enrolled_nodes(c, tenant)

        edge_w = {}   # (src_id, dst_id) -> weight
        seen_ext = set()
        if _table_exists(c, "ndr_flows"):
            try:
                cutoff = _now() - int(window or 0)
            except (TypeError, ValueError):
                cutoff = 0
            try:
                rows = c.execute(
                    "SELECT src, dst FROM ndr_flows WHERE tenant_id=? AND ts>=?",
                    (tenant, cutoff)).fetchall()
            except Exception:
                rows = []
            for r in rows:
                s = _resolve(r["src"], ip_to_id)
                d = _resolve(r["dst"], ip_to_id)
                if not s or not d or s == d:
                    continue
                # endpoint yang belum jadi node → node 'external'
                for nid in (s, d):
                    if nid not in nodes:
                        nodes[nid] = {"id": nid, "label": nid, "type": "external",
                                      "ip": nid, "os": "", "status": ""}
                        seen_ext.add(nid)
                key = (s, d)
                edge_w[key] = edge_w.get(key, 0) + 1

        # lampirkan risk + alert_count ke setiap node
        out_nodes = []
        for nid, attrs in nodes.items():
            n = dict(attrs)
            n["risk"] = int(risk.get(nid, 0))
            n["alert_count"] = int(alert_count.get(nid, 0))
            out_nodes.append(n)

        out_edges = [{"src": s, "dst": d, "kind": "flow", "weight": w}
                     for (s, d), w in edge_w.items()]

        return {"ok": True, "module": "nexus_secops",
                "nodes": out_nodes, "edges": out_edges,
                "node_count": len(out_nodes), "edge_count": len(out_edges)}
    finally:
        if own:
            c.close()


def _adjacency(graph):
    """adj: node_id -> set(tetangga keluar). Dipakai BFS lateral movement."""
    adj = {n["id"]: set() for n in graph["nodes"]}
    risk = {n["id"]: n.get("risk", 0) for n in graph["nodes"]}
    label = {n["id"]: n.get("label", n["id"]) for n in graph["nodes"]}
    for e in graph["edges"]:
        adj.setdefault(e["src"], set()).add(e["dst"])
        adj.setdefault(e["dst"], set())   # pastikan dst ada sebagai kunci
    return adj, risk, label


def _reachable(adj, origin, max_depth=_MAX_DEPTH):
    """BFS iteratif dari origin; kembalikan set node terjangkau (tanpa origin).
    Guard siklus via visited; cap kedalaman via max_depth."""
    if origin not in adj:
        return set()
    visited = {origin}
    reached = set()
    frontier = [origin]
    depth = 0
    while frontier and depth < max_depth:
        nxt = []
        for node in frontier:
            for neigh in adj.get(node, ()):  # iterable kosong bila tak ada
                if neigh not in visited:
                    visited.add(neigh)
                    reached.add(neigh)
                    nxt.append(neigh)
        frontier = nxt
        depth += 1
    return reached


# --------------------------------------------------------------------------- blast
def blast_radius(node_id, tenant="default", conn=None):
    """Dari node_id: temukan semua yang terjangkau (potensi lateral movement).

    -> {ok, origin, reachable:[node_ids], reach_count, score}
       score = reach_count + jumlah risk node terjangkau + risk origin.
    """
    own = conn is None
    c = conn or _sa_conn()
    try:
        graph = build_graph(tenant=tenant, conn=c)
        adj, risk, _ = _adjacency(graph)
        if node_id not in adj:
            return {"ok": True, "module": "nexus_secops", "origin": node_id,
                    "reachable": [], "reach_count": 0, "score": 0,
                    "found": False}
        reached = _reachable(adj, node_id)
        reach_risk = sum(risk.get(n, 0) for n in reached)
        score = len(reached) + reach_risk + risk.get(node_id, 0)
        return {"ok": True, "module": "nexus_secops", "origin": node_id,
                "reachable": sorted(reached), "reach_count": len(reached),
                "score": int(score), "found": True}
    finally:
        if own:
            c.close()


# --------------------------------------------------------------------------- exposed
def top_exposed(tenant="default", limit=10, conn=None):
    """Host paling berbahaya bila jatuh: gabungan risk node + jangkauan lateral.

    -> {ok, hosts:[{id,label,risk,reach_count,exposure}]}  (desc by exposure)
    """
    own = conn is None
    c = conn or _sa_conn()
    try:
        graph = build_graph(tenant=tenant, conn=c)
        adj, risk, label = _adjacency(graph)
        hosts = []
        for nid in adj:
            reached = _reachable(adj, nid)
            reach_risk = sum(risk.get(n, 0) for n in reached)
            r = risk.get(nid, 0)
            # paparan: bobot risk sendiri + jangkauan + risk yang bisa dijangkau
            exposure = r * 2 + len(reached) + reach_risk
            hosts.append({"id": nid, "label": label.get(nid, nid),
                          "risk": int(r), "reach_count": len(reached),
                          "exposure": int(exposure)})
        hosts.sort(key=lambda h: (h["exposure"], h["risk"], h["reach_count"]),
                   reverse=True)
        try:
            lim = max(0, int(limit))
        except (TypeError, ValueError):
            lim = 10
        return {"ok": True, "module": "nexus_secops", "hosts": hosts[:lim]}
    finally:
        if own:
            c.close()


# --------------------------------------------------------------------------- stats
def stats(tenant="default", conn=None):
    """Ringkasan graf untuk dashboard / tampilan Cytoscape.

    -> {ok, nodes, edges, riskiest:[{id,label,risk,alert_count}]}
    """
    own = conn is None
    c = conn or _sa_conn()
    try:
        graph = build_graph(tenant=tenant, conn=c)
        riskiest = sorted(graph["nodes"], key=lambda n: n.get("risk", 0),
                          reverse=True)
        riskiest = [{"id": n["id"], "label": n.get("label", n["id"]),
                     "risk": n.get("risk", 0),
                     "alert_count": n.get("alert_count", 0)}
                    for n in riskiest if n.get("risk", 0) > 0][:10]
        return {"ok": True, "module": "nexus_secops",
                "nodes": graph["node_count"], "edges": graph["edge_count"],
                "riskiest": riskiest}
    finally:
        if own:
            c.close()

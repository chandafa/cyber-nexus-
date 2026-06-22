# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/edr.py
"""
EDR — Endpoint Detection & Response: pohon proses & rekonstruksi kill-chain.

Fitur inti CrowdStrike Falcon / SentinelOne: bukan sekadar daftar proses, tapi
*silsilah* proses (induk→anak) sehingga analis bisa melihat BAGAIMANA sebuah
proses jahat lahir (mis. nginx → bash → mimikatz = webshell→eksekusi kredensial).

NYATA, bukan demo: agent mengirim snapshot proses ASLI berisi pid/ppid/cmdline
(dari `ps`/CIM OS). Modul ini menyimpannya, menyusun pohon ancestry, dan
mendeteksi *garis keturunan mencurigakan* (parent-child anomaly) — teknik deteksi
perilaku EDR sungguhan, bukan tanda-tangan nama proses semata.

Garis keturunan mencurigakan yang dideteksi:
  • server web/app  → shell    (webshell / RCE)
  • aplikasi office  → script   (makro berbahaya)
  • shell/parent     → LOLBin   (mis. powershell -enc <base64>) = obfuscation
  • parent apa pun   → tool jahat dikenal (mimikatz, cobaltstrike, dst.)

Temuan di-emit sbg event `suspicious_lineage` (lewat manager) → rule NEXUS-EDR-001
→ alert → XDR/SOAR/AI. Pohon proses tersedia utk dashboard via build_tree().

Tabel: edr_processes (inventori proses terkini per host).
"""
import json
import re
import sqlite3

from nexus_common import protocol as fc

# Klasifikasi nama proses (dibandingkan case-insensitive, cocok-substring).
SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "cmd.exe", "cmd", "powershell.exe",
          "powershell", "pwsh", "wscript.exe", "cscript.exe", "mshta.exe", "wscript", "cscript")
SERVERS = ("nginx", "apache", "apache2", "httpd", "php-fpm", "php", "node", "java",
           "w3wp.exe", "w3wp", "tomcat", "caddy", "gunicorn", "uwsgi")
OFFICE = ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "winword", "excel")
KNOWN_BAD = ("mimikatz", "cobaltstrike", "cobalt", "meterpreter", "metasploit", "xmrig",
             "lazagne", "rubeus", "ncat", "netcat", "masscan", "psexec")
MAX_TREE_DEPTH = 200       # batas kedalaman pohon agar aman diserialisasi JSON
# Pola command-line obfuscation / LOLBin (PowerShell encoded, dll.)
_OBFUSCATED = re.compile(
    r"(-enc(odedcommand)?\b|frombase64string|-w\s+hidden|-nop\b|iex\b|"
    r"downloadstring|invoke-expression|certutil\s+-urlcache|bitsadmin)", re.I)


def _conn():
    return fc.connect()


def ensure_tables(c):
    """Buat tabel EDR pada koneksi `c` (tanpa commit)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS edr_processes (
            agent_id TEXT, tenant_id TEXT DEFAULT 'default', pid INTEGER, ppid INTEGER,
            name TEXT, user TEXT, cmdline TEXT, ts INTEGER,
            PRIMARY KEY(agent_id, pid, tenant_id)
        );
        CREATE INDEX IF NOT EXISTS idx_edr_agent ON edr_processes(agent_id);
        CREATE INDEX IF NOT EXISTS idx_edr_ppid ON edr_processes(agent_id, ppid);
        """
    )


def init_db():
    c = _conn()
    ensure_tables(c)
    c.commit(); c.close()


# --------------------------------------------------------------------------- helpers
def _base(name):
    """Nama proses dasar (buang path & argumen)."""
    n = (name or "").strip().strip('"').lower()
    n = n.replace("\\", "/").split("/")[-1]
    return n.split()[0] if n else n


def _is(name, group):
    b = _base(name)
    return any(b == g or b.startswith(g) or g in b for g in group)


# --------------------------------------------------------------------------- lineage detection
def detect_lineage(processes):
    """Deteksi garis keturunan mencurigakan pada satu snapshot proses.
    `processes`: list dict {pid, ppid, name, user, cmdline}. Mengembalikan temuan."""
    by_pid = {}
    for p in processes:
        try:
            by_pid[int(p.get("pid"))] = p
        except (TypeError, ValueError):
            continue
    findings = []
    for p in processes:
        name = p.get("name", "")
        cmd = p.get("cmdline", "") or ""
        try:
            ppid = int(p.get("ppid"))
        except (TypeError, ValueError):
            ppid = -1
        parent = by_pid.get(ppid, {})
        pname = parent.get("name", "") if parent else ""
        chain = f"{_base(pname) or '?'} → {_base(name)}"
        sev = rule = mitre = None

        if _is(name, KNOWN_BAD):
            sev, rule, mitre = "critical", "Tool ofensif dikenal berjalan", ["T1059"]
        elif pname and _is(pname, SERVERS) and _is(name, SHELLS):
            sev, rule, mitre = "critical", "Server web menelurkan shell (webshell/RCE)", \
                ["T1190", "T1505.003", "T1059"]
        elif pname and _is(pname, OFFICE) and _is(name, SHELLS):
            sev, rule, mitre = "high", "Aplikasi office menelurkan script (makro berbahaya)", \
                ["T1566.001", "T1059.001"]
        elif _is(name, ("powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe")) \
                and _OBFUSCATED.search(cmd):
            sev, rule, mitre = "high", "Command-line ter-obfuscate (LOLBin/encoded)", \
                ["T1059.001", "T1027"]

        if sev:
            findings.append({
                "pid": p.get("pid"), "ppid": ppid, "name": _base(name),
                "parent_name": _base(pname), "rule": rule, "severity": sev,
                "mitre": mitre, "chain": chain, "cmdline": cmd[:300],
                "user": p.get("user", ""),
            })
    return findings


# --------------------------------------------------------------------------- ingest
def ingest_snapshot(agent_id, processes, tenant="default", conn=None):
    """Simpan snapshot proses TERKINI sebuah host (ganti inventori lama) lalu deteksi
    garis keturunan mencurigakan. Pakai koneksi pemanggil bila diberikan (anti-lock)."""
    own = conn is None
    c = conn or _conn()
    if own:
        ensure_tables(c)
    c.execute("DELETE FROM edr_processes WHERE agent_id=? AND tenant_id=?", (agent_id, tenant))
    now = fc.now()
    rows = []
    for p in processes or []:
        try:
            pid = int(p.get("pid"))
        except (TypeError, ValueError):
            continue
        try:
            ppid = int(p.get("ppid"))
        except (TypeError, ValueError):
            ppid = 0
        rows.append((agent_id, tenant, pid, ppid, _base(p.get("name", "")),
                     str(p.get("user", ""))[:64], str(p.get("cmdline", ""))[:500], now))
    if rows:
        c.executemany("INSERT OR REPLACE INTO edr_processes(agent_id,tenant_id,pid,ppid,"
                      "name,user,cmdline,ts) VALUES(?,?,?,?,?,?,?,?)", rows)
    if own:
        c.commit(); c.close()
    return detect_lineage(processes)


# --------------------------------------------------------------------------- tree
def _fetch(agent_id, tenant):
    c = _conn()
    rows = c.execute("SELECT pid, ppid, name, user, cmdline FROM edr_processes "
                     "WHERE agent_id=? AND tenant_id=?", (agent_id, tenant)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def build_tree(agent_id, tenant="default", max_nodes=2000):
    """Susun pohon ancestry proses sebuah host dari inventori NYATA."""
    procs = _fetch(agent_id, tenant)
    if not procs:
        return {"ok": True, "module": "nexus_secops", "agent_id": agent_id, "tree": [],
                "count": 0}
    nodes = {p["pid"]: {"pid": p["pid"], "ppid": p["ppid"], "name": p["name"],
                        "user": p["user"], "cmdline": p["cmdline"], "children": []} for p in procs}
    pids = set(nodes)
    roots = []
    for pid, node in nodes.items():
        parent = nodes.get(node["ppid"])
        if parent and node["ppid"] != pid:
            parent["children"].append(node)
        else:
            roots.append(node)          # induk tak ada di snapshot → akar (mis. ppid 0/1)
    # Tandai node berisiko + batasi kedalaman. Iteratif + `seen` agar AMAN dari pid/ppid
    # bersiklus, dan MAX_DEPTH agar pohon sangat dalam tetap bisa diserialisasi JSON
    # (json.dumps rekursif → RecursionError pada nesting ribuan). Real-world < ~50.
    findings = {f["pid"]: f for f in detect_lineage(procs)}
    seen = set()
    stack = [(r, 0) for r in roots]
    while stack:
        n, depth = stack.pop()
        if n["pid"] in seen:
            continue
        seen.add(n["pid"])
        if n["pid"] in findings:
            n["risk"] = findings[n["pid"]]["rule"]
        if depth >= MAX_TREE_DEPTH:
            if n["children"]:
                n["truncated"] = len(n["children"])
                n["children"] = []
        else:
            stack.extend((ch, depth + 1) for ch in n["children"])
    return {"ok": True, "module": "nexus_secops", "agent_id": agent_id,
            "tree": roots[:max_nodes], "count": len(procs)}


def ancestry(agent_id, pid, tenant="default"):
    """Lacak kill-chain: dari proses target mundur ke akar (siapa menelurkan siapa)."""
    procs = {p["pid"]: p for p in _fetch(agent_id, tenant)}
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "error": "pid tak valid"}
    chain, seen = [], set()
    cur = procs.get(pid)
    while cur and cur["pid"] not in seen:
        seen.add(cur["pid"])
        chain.append({"pid": cur["pid"], "name": cur["name"], "user": cur["user"],
                      "cmdline": cur["cmdline"]})
        cur = procs.get(cur["ppid"])
    chain.reverse()                      # akar → … → target
    return {"ok": True, "module": "nexus_secops", "agent_id": agent_id, "pid": pid,
            "ancestry": chain, "depth": len(chain)}


def list_processes(agent_id, q="", tenant="default", limit=500):
    procs = _fetch(agent_id, tenant)
    if q:
        ql = q.lower()
        procs = [p for p in procs if ql in (p["name"] or "").lower()
                 or ql in (p["cmdline"] or "").lower()]
    return {"ok": True, "module": "nexus_secops", "agent_id": agent_id,
            "processes": procs[:int(limit)], "count": len(procs)}


def hosts(tenant="default"):
    """Daftar host yang punya inventori proses (untuk pemilih di dashboard)."""
    c = _conn()
    rows = c.execute("SELECT agent_id, COUNT(*) n, MAX(ts) ts FROM edr_processes "
                     "WHERE tenant_id=? GROUP BY agent_id ORDER BY ts DESC", (tenant,)).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "hosts": [
        {"agent_id": r["agent_id"], "processes": r["n"], "last_iso": fc.iso(r["ts"])}
        for r in rows]}

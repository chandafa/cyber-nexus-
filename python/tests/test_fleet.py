#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""End-to-end test subsistem Fleet: manager <-> agent (HTTP + HMAC + queue)."""
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)
sys.path.insert(0, os.path.join(PYDIR, "fleet"))  # paket kanonik fleet

# DB terisolasi
_tmp = tempfile.mkdtemp(prefix="nexus_fleet_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")
os.environ["NEXUS_AGENT_DB"] = os.path.join(_tmp, "agt.db")

import json                                    # noqa: E402
from nexus_common import protocol as fc        # noqa: E402
from nexus_common import schema                # noqa: E402
from nexus_common import license as lic        # noqa: E402

# Setup lisensi ENTERPRISE untuk seksi 1-25 (uji fitur premium). Kunci vendor
# disuntik via env sebelum manager dimuat agar entitlements memverifikasinya.
_SEED, _PK = lic.generate_keypair()
os.environ["NEXUS_VENDOR_PUBKEY"] = _PK
os.environ["NEXUS_LICENSE"] = lic.issue(_SEED, "Test Co", tier="enterprise",
                                        days=365, max_agents=999)

from nexus_manager import server as mgr        # noqa: E402
from nexus_manager import rules as ruleengine  # noqa: E402
from nexus_agent import agent as agt           # noqa: E402

PORT = 8799
FAILED = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def main():
    print("== 1. Start manager ==")
    r = mgr.run(host="127.0.0.1", port=str(PORT))
    check("manager running", r.get("status") == "running")
    enroll_key = r["enroll_key"]
    admin_token = r["admin_token"]
    check("enroll key issued", len(enroll_key) > 20)
    time.sleep(0.3)

    print("== 2. Health endpoint ==")
    h = fc.get_admin(fc.manager_url("127.0.0.1", PORT, "/health"))
    check("health ok", h.get("ok") is True)

    print("== 3. Enroll wrong key rejected ==")
    bad = agt.enroll("127.0.0.1", PORT, "salah-key", name="badnode")
    check("bad enroll rejected", bad.get("ok") is False)

    print("== 4. Enroll real agent ==")
    e = agt.enroll("127.0.0.1", PORT, enroll_key, name="test-endpoint")
    check("enroll ok", e.get("ok") is True)
    agent_id = e.get("agent_id", "")
    check("agent_id issued", agent_id.startswith("agt_"))

    print("== 5. Collect telemetry + flush to manager ==")
    evts = agt.collect_all()
    check("collected >=1 event", len(evts) >= 1)
    agt._enqueue(evts)
    sent = agt._flush_queue()
    check("events flushed", sent >= 1)
    check("queue drained", agt._queue_size() == 0)

    print("== 6. Heartbeat updates last_seen / online ==")
    agt._heartbeat()
    agents = mgr.list_agents()["agents"]
    check("1 agent listed", len(agents) == 1)
    check("agent online", agents and agents[0]["status"] == "online")

    print("== 7. Events stored on manager ==")
    me = mgr.list_events(500)["events"]
    check("events stored", len(me) >= 1)
    check("event has severity", all("severity" in x for x in me))

    print("== 8. Tampering rejected (bad signature) ==")
    try:
        fc._request("POST", fc.manager_url("127.0.0.1", PORT, "/events"),
                    fc.canonical({"events": []}),
                    {"X-Agent-Id": agent_id, "X-Signature": "deadbeef"})
        check("tamper rejected", False)
    except fc.HttpError as ex:
        check("tamper rejected", ex.status == 401)

    print("== 9. Policy push: set -> version bump -> agent pulls ==")
    v0 = mgr.get_policy()["policy_version"]
    mgr.set_policy('{"heartbeat_interval": 15, "collect_interval": 45, '
                   '"collectors": ["system","disk"], "min_report_severity": "info"}')
    v1 = mgr.get_policy()["policy_version"]
    check("policy version bumped", v1 == v0 + 1)
    agt._heartbeat()  # should detect new version & pull
    check("agent pulled policy", int(agt._get("policy_version", "0")) == v1)
    check("agent applied collectors", agt._policy().get("collectors") == ["system", "disk"])

    print("== 10. Command queue -> delivered on heartbeat ==")
    mgr.queue_command(agent_id, "collect_now", {})
    # heartbeat returns queued commands
    resp = fc.post_signed(fc.manager_url("127.0.0.1", PORT, "/heartbeat"),
                          {"ip": ""}, agent_id, agt._get("agent_key"))
    cmds = resp.get("commands", [])
    check("command delivered", any(c["command"] == "collect_now" for c in cmds))

    print("== 11. Admin API via token (nexus-cli path) ==")
    a = fc.get_admin(fc.manager_url("127.0.0.1", PORT, "/agents"), admin_token)
    check("admin agents list", len(a.get("agents", [])) == 1)
    try:
        fc.get_admin(fc.manager_url("127.0.0.1", PORT, "/agents"), "wrong-token")
        check("admin token enforced", False)
    except fc.HttpError as ex:
        check("admin token enforced", ex.status == 401)

    print("== 12. Stats ==")
    s = mgr.stats()
    check("stats agents_total=1", s["agents_total"] == 1)
    check("stats events>0", s["events_total"] >= 1)

    akey = agt._get("agent_key")

    def ingest(events):
        return fc.post_signed(fc.manager_url("127.0.0.1", PORT, "/events"),
                              {"events": events}, agent_id, akey)

    print("== 13. Rule engine: firewall-off event -> alert ==")
    r = ingest([{"type": "firewall", "severity": "high", "title": "Firewall NONAKTIF",
                 "data": {"enabled": False}, "origin": "real"}])
    check("event stored", r.get("stored") == 1)
    alerts = mgr.list_alerts(50)["alerts"]
    check("alert(s) exist", len(alerts) >= 1)
    check("NEXUS-FW-001 present", any(a["rule_id"] == "NEXUS-FW-001" for a in alerts))

    print("== 13b. Alert dedup (event sama tidak menggandakan alert) ==")
    n_before = len(mgr.list_alerts(200)["alerts"])
    ingest([{"type": "firewall", "severity": "high", "data": {"enabled": False}, "origin": "real"}])
    n_after = len(mgr.list_alerts(200)["alerts"])
    check("duplicate suppressed", n_after == n_before)

    print("== 14. Real-only: demo event ditolak ==")
    r2 = ingest([{"type": "firewall", "severity": "high", "data": {"enabled": False},
                  "origin": "demo"}])
    check("demo skipped", r2.get("skipped_demo") == 1 and r2.get("stored") == 0)

    print("== 15. FIM .env modified -> alert CRITICAL (NEXUS-FIM-001) ==")
    ingest([{"type": "fim_change", "severity": "high", "event_type": "file_modified",
             "title": "File diubah: .env", "target": {"path": "/var/www/app/.env"},
             "evidence": {"old_hash": "a", "new_hash": "b"}, "origin": "real"}])
    alerts = mgr.list_alerts(50)["alerts"]
    fim = [a for a in alerts if a["rule_id"] == "NEXUS-FIM-001"]
    check("NEXUS-FIM-001 fired", len(fim) == 1)
    check("alert is critical", fim and fim[0]["severity"] == "critical" and fim[0]["level"] == 14)
    check("alert has MITRE", fim and "T1005" in fim[0]["mitre"])
    check("alert has recommendation", fim and len(fim[0]["recommendation"]) > 10)

    print("== 16. Alert ack/resolve ==")
    aid = fim[0]["id"]
    mgr.ack_alert(aid, "resolved")
    got = [a for a in mgr.list_alerts(50)["alerts"] if a["id"] == aid][0]
    check("alert resolved", got["status"] == "resolved")

    print("== 17. Schema normalization ==")
    e = schema.normalize_event({"severity": "weird", "type": "firewall"})
    check("bad severity -> info", e["severity"] == "info")
    check("default origin real", e["origin"] == "real")
    check("category mapped", e["category"] == "config_assessment")
    check("demo clamp", schema.make_event("x", "info", "t", origin="demo")["origin"] == "demo")

    print("== 18. Rules pushable ==")
    before = len(mgr.get_rules())
    mgr.set_rules('[{"id":"T","name":"t","conditions":{"type":"x"},"level":5}]')
    check("rules replaced", len(mgr.get_rules()) == 1)
    mgr.set_rules(json.dumps(ruleengine.DEFAULT_RULES))
    check("rules restored", len(mgr.get_rules()) == before)

    print("== 19. Report schema konsisten ==")
    rep = mgr.report("fleet")
    check("report schema tag", rep.get("schema") == "nexus.report/v1")
    check("report has summary", "by_severity" in rep.get("summary", {}))
    check("report has mitre techniques", "mitre_techniques" in rep.get("summary", {}))

    print("== 20. Audit log ==")
    aud = mgr.list_audit(50)["audit"]
    check("audit recorded enroll+ack", any(a["action"] == "enroll" for a in aud)
          and any(a["action"].startswith("alert:") for a in aud))

    print("== 21. Web/app-aware rule (weak DB password) ==")
    ingest([{"type": "webaudit", "severity": "high", "event_type": "weak_db_password",
             "title": "DB_PASSWORD lemah", "target": {"path": "/srv/app/.env"}, "origin": "real"}])
    web = [a for a in mgr.list_alerts(100)["alerts"] if a["rule_id"] == "NEXUS-WEB-003"]
    check("NEXUS-WEB-003 fired", len(web) == 1)

    print("== 22. Security posture score ==")
    p = mgr.posture()
    check("overall score 0-100", 0 <= p["overall"] <= 100)
    check("has website/server/network scores", set(p["scores"]) ==
          {"network_security", "server_hardening", "website_security"})
    check("website score reduced by web alert", p["scores"]["website_security"] < 100)

    print("== 23. Sigma import -> native rule ==")
    sigma = {"title": "Sensitive env file access", "id": "SIG-ENV-001", "level": "high",
             "tags": ["attack.t1552.001", "attack.credential-access"],
             "logsource": {"category": "file_event"},
             "detection": {"selection": {"TargetFilename|endswith": ".env"},
                           "condition": "selection"}}
    n_before = len(mgr.get_rules())
    r = mgr.import_sigma(json.dumps(sigma))
    check("sigma imported", r.get("ok") and r.get("imported") == 1)
    check("rules grew", len(mgr.get_rules()) == n_before + 1)
    conv = [x for x in mgr.get_rules() if x["id"] == "SIG-ENV-001"][0]
    check("sigma mitre mapped", "T1552.001" in conv["mitre"])
    check("sigma condition mapped", conv["conditions"].get("target.path", {}).get("ends_with") == ".env")

    print("== 24. Active Response (dry-run default) ==")
    qn = agt._queue_size()
    agt._active_response({"action": "block_ip", "ip": "203.0.113.5"})
    check("response event enqueued", agt._queue_size() == qn + 1)
    last = agt._conn().execute("SELECT payload FROM queue ORDER BY id DESC LIMIT 1").fetchone()[0]
    ev = json.loads(last)
    check("dry-run not executed", ev["data"]["executed"] is False)
    check("response event_type", ev["event_type"] == "active_response")

    print("== 25. response_action queues agent command ==")
    rr = mgr.response_action(agent_id, "block_ip", ip="203.0.113.9")
    check("respond command queued", rr.get("ok") is True)

    print("== 25b. Log Monitoring: decoder app (laravel/nginx/auth) + rule ==")
    from nexus_agent import collectors as C
    check("nginx web-attack decoded", C.decode_line(
        '1.2.3.4 - - [t] "GET /?id=1 union select pass from users HTTP/1.1" 200 -',
        "nginx")["event_type"] == "web_attack")
    check("nginx scanner decoded", C.decode_line(
        '1.2.3.4 - - [t] "GET / HTTP/1.1" 200 - "-" "sqlmap/1.5"', "nginx")
        ["event_type"] == "scanner_detected")
    check("laravel exception decoded", C.decode_line(
        "[2026-01-01] production.ERROR: Boom", "laravel")["event_type"] == "app_exception")
    check("auth failed-login decoded", C.decode_line(
        "Failed password for root from 1.2.3.4", "auth")["event_type"] == "log_failed_login")
    ingest([{"type": "log", "source": "logcollector", "severity": "critical",
             "event_type": "web_attack", "title": "SQLi attempt", "origin": "real"}])
    check("NEXUS-LOG-001 fired (web attack)",
          any(a["rule_id"] == "NEXUS-LOG-001" for a in mgr.list_alerts(500)["alerts"]))

    print("== 25c. Vulnerability Detection (inventory software -> CVE) ==")
    ingest([{"type": "software_inventory", "severity": "info", "title": "inv",
             "data": {"packages": [{"name": "OpenSSL", "version": "1.1.1n"},
                                   {"name": "Log4j Core", "version": "2.14.0"},
                                   {"name": "SafeApp", "version": "9.9.9"}]}, "origin": "real"}])
    vulns = [a for a in mgr.list_alerts(500)["alerts"] if a["rule_id"] == "NEXUS-VULN-001"]
    check("NEXUS-VULN-001 fired dari inventory", len(vulns) >= 1)
    check("alert membawa CVE di evidence",
          any(str(a["evidence"].get("cve", "")).startswith("CVE-") for a in vulns))
    check("Log4Shell (CVE-2021-44228) terdeteksi",
          any(a["evidence"].get("cve") == "CVE-2021-44228" for a in vulns))

    print("== 25d. Syscollector (proses/jaringan) + suspicious process ==")
    from nexus_agent import collectors as C2
    pe = C2.c_processes({})
    check("process inventory (process_list)", any(e["event_type"] == "process_list" for e in pe))
    ne = C2.c_network({})
    check("network inventory", ne[0]["event_type"] == "network_inventory")
    ingest([{"type": "processes", "severity": "high", "event_type": "suspicious_process",
             "title": "mimikatz", "target": {"process": "mimikatz.exe"}, "origin": "real"}])
    check("NEXUS-PROC-001 fired (suspicious process)",
          any(a["rule_id"] == "NEXUS-PROC-001" for a in mgr.list_alerts(500)["alerts"]))

    print("== 25e. Anti-replay (timestamp) + validasi IP Active Response ==")
    stale = fc.canonical({"events": [], "_ts": fc.now() - 1000})
    try:
        fc._request("POST", fc.manager_url("127.0.0.1", PORT, "/events"), stale,
                    {"X-Agent-Id": agent_id, "X-Signature": fc.sign(akey, stale)})
        check("stale message rejected (anti-replay)", False)
    except fc.HttpError as ex:
        check("stale message rejected (anti-replay)", ex.status == 401)
    agt._active_response({"action": "block_ip", "ip": "bukan-ip-valid"})
    last = agt._conn().execute("SELECT payload FROM queue ORDER BY id DESC LIMIT 1").fetchone()
    rev = json.loads(last[0]) if last else {}
    check("IP tidak valid ditolak Active Response",
          rev.get("data", {}).get("executed") is False
          and "IP" in str(rev.get("data", {}).get("reason", "")))

    print("== 25f. Auto-remediation actions + notifikasi (best-effort) ==")
    p1, _ = agt._remediation_plan("enable_firewall", "", "")
    check("plan enable_firewall", p1 is not None)
    p2, _ = agt._remediation_plan("harden", "", "")
    check("plan harden (2 langkah)", p2 is not None and len(p2) == 2)
    p3, _ = agt._remediation_plan("kill_process", "", "")
    check("kill_process tanpa nama ditolak", p3 is None)
    agt._active_response({"action": "enable_firewall"})   # dry-run (policy enterprise tak set active_response)
    lastr = json.loads(agt._conn().execute(
        "SELECT payload FROM queue ORDER BY id DESC LIMIT 1").fetchone()[0])
    check("enable_firewall dry-run (tidak dieksekusi)",
          lastr["data"]["executed"] is False and lastr["event_type"] == "active_response")
    check("set_notify config", mgr.set_notify("http://127.0.0.1:9/none", 10).get("min_level") == 10)
    r_robust = ingest([{"type": "webaudit", "severity": "high", "event_type": "git_exposed",
                        "title": "git", "target": {"path": "/z/.git"}, "origin": "real"}])
    check("ingest tetap sukses walau webhook gagal", r_robust.get("ok") is True)
    mgr.set_notify("", 12)

    print("== 25g. Fix: CVE version-from-name + agent watch effective-policy ==")
    from nexus_manager import vulndb as VD
    fnd = VD.match([{"name": "OpenSSL 1.1.1n", "version": ""}])   # versi kosong -> urai dari nama
    check("CVE cocok dari DisplayName (versi diurai)",
          any(str(x["cve"]).startswith("CVE-") for x in fnd))
    import tempfile as _tf
    agt._set("watch_paths", json.dumps([_tf.gettempdir()]))
    ep = agt._effective_policy()
    check("watch -> webaudit_paths terisi & collector aktif",
          len(ep.get("webaudit_paths", [])) >= 1 and "webaudit" in ep.get("collectors", []))
    agt._set("watch_paths", "[]")

    print("== 25h. Audit fixes #1,#2,#3,#6,#9,#10,#11 ==")
    # #1 judul alert spesifik (judul event, bukan nama rule)
    ingest([{"type": "webaudit", "severity": "high", "event_type": "weak_db_password",
             "title": "DB_PASSWORD=root pada /srv/x/.env", "target": {"path": "/srv/x/.env"},
             "origin": "real"}])
    aw = [a for a in mgr.list_alerts(200)["alerts"] if a["rule_id"] == "NEXUS-WEB-003"]
    check("#1 alert title spesifik (judul event)",
          any("DB_PASSWORD=root" in a["title"] for a in aw))
    # #2 word-boundary matching + skip-year
    from nexus_manager import vulndb as VD2
    check("#2 'git' tak cocok 'GitHub Desktop'", VD2._product_in("git", "github desktop") is False)
    check("#2 'git' cocok 'Git for Windows'", VD2._product_in("git", "git for windows") is True)
    check("#2 versi lewati tahun (14.34 dari 'VC++ 2015-2022 14.34')",
          VD2._extract_version("microsoft visual c++ 2015-2022 14.34", "") == "14.34")
    # #3 remove_agent membebaskan seat
    c0 = mgr._conn(); did = fc.new_id("agt")
    c0.execute("INSERT INTO agents(agent_id,agent_key,name,status,enrolled_at,last_seen) "
               "VALUES(?,?,?,?,?,?)", (did, "k", "tmp", "active", fc.now(), 0))
    c0.commit(); c0.close()
    n_before = len(mgr.list_agents()["agents"])
    check("#3 remove_agent ok & seat dibebaskan",
          mgr.remove_agent(did).get("ok") and len(mgr.list_agents()["agents"]) == n_before - 1)
    # #6 active-response: IP terlindungi ditolak
    agt._active_response({"action": "block_ip", "ip": "127.0.0.1"})
    lr = json.loads(agt._conn().execute("SELECT payload FROM queue ORDER BY id DESC LIMIT 1").fetchone()[0])
    check("#6 IP terlindungi (127.0.0.1) ditolak",
          lr["data"]["executed"] is False and "dilindungi" in str(lr["data"].get("reason", "")))
    # #9 enkripsi at-rest (opsional)
    os.environ["NEXUS_MASTER_KEY"] = "uji-master-key-123"
    from nexus_common import cryptobox as CB
    enc = CB.encrypt("rahasia123")
    if CB.enabled():
        check("#9 enkripsi at-rest (enc + dec)", enc.startswith("enc:") and CB.decrypt(enc) == "rahasia123")
    else:
        check("#9 cryptobox passthrough (lib crypto tak ada — opsional)", enc == "rahasia123")
    os.environ.pop("NEXUS_MASTER_KEY", None)
    # #10 RBAC: viewer
    u = mgr.add_user("viewer")
    check("#10 add_user viewer + role", u.get("ok") and mgr._role_of_token(u["token"]) == "viewer")
    # #11 incidents grouping
    inc = mgr.incidents()["incidents"]
    check("#11 incidents dikelompokkan", isinstance(inc, list) and len(inc) >= 1)
    # #5 replay window configurable + reset offset
    fc.set_clock_offset(0)
    check("#5 replay window dapat dikonfigurasi", mgr._replay_window() >= 60)
    # nit: 403 untuk viewer (terautentikasi) menulis, 401 untuk token invalid
    vtok = mgr.add_user("viewer")["token"]
    try:
        fc.post_admin(fc.manager_url("127.0.0.1", PORT, "/command"),
                      {"agent_id": agent_id, "command": "ping"}, vtok)
        check("viewer write -> 403", False)
    except fc.HttpError as ex:
        check("viewer write -> HTTP 403 (terautentikasi, tak berwenang)", ex.status == 403)
    try:
        fc.post_admin(fc.manager_url("127.0.0.1", PORT, "/command"),
                      {"agent_id": agent_id, "command": "ping"}, "token-tak-valid")
        check("token invalid -> 401", False)
    except fc.HttpError as ex:
        check("token invalid -> HTTP 401", ex.status == 401)
    # HA: WAL mode
    check("WAL mode aktif (langkah HA)",
          mgr._conn().execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal")
    # CVE: version range (introduced..fixed)
    check("CVE range: log4j 1.2.17 di bawah introduced -> TIDAK cocok",
          not any(x["cve"] == "CVE-2021-44228" for x in VD2.match([{"name": "log4j", "version": "1.2.17"}])))
    check("CVE range: log4j 2.14.0 dalam rentang -> cocok",
          any(x["cve"] == "CVE-2021-44228" for x in VD2.match([{"name": "log4j", "version": "2.14.0"}])))

    print("== 26. Lisensi valid (enterprise) terverifikasi ==")
    ls = mgr.license_status()
    check("license valid", ls["valid"] and ls["tier"] == "enterprise")
    check("license has features", "sigma" in ls["features"] and "active_response" in ls["features"])

    print("== 27. Gerbang FREE: cabut lisensi -> fitur premium terkunci ==")
    os.environ["NEXUS_LICENSE"] = ""
    mgr.reload_license()
    lf = mgr.license_status()
    check("free tier active", lf["tier"] == "free" and not lf["valid"])
    check("free max_agents=2", lf["max_agents"] == 2)
    check("sigma blocked on free", mgr.import_sigma(json.dumps(sigma)).get("ok") is False)
    try:    # #4 fitur terkunci -> HTTP 403 (bukan 400)
        fc.post_admin(fc.manager_url("127.0.0.1", PORT, "/response/actions"),
                      {"agent_id": agent_id, "action": "block_ip", "ip": "1.2.3.4"}, admin_token)
        check("#4 license-gated -> HTTP 403", False)
    except fc.HttpError as ex:
        check("#4 license-gated -> HTTP 403 (bukan 400)", ex.status == 403)
    check("active_response blocked on free",
          mgr.response_action(agent_id, "block_ip", ip="1.1.1.1").get("ok") is False)
    # rule premium (FIM .env) tidak menghasilkan alert di free
    fim_before = len([a for a in mgr.list_alerts(500)["alerts"] if a["rule_id"] == "NEXUS-FIM-001"])
    ingest([{"type": "fim_change", "severity": "high", "event_type": "file_modified",
             "title": "x", "target": {"path": "/x/free.env"},
             "evidence": {"old_hash": "a", "new_hash": "b"}, "origin": "real"}])
    fim_after = len([a for a in mgr.list_alerts(500)["alerts"] if a["rule_id"] == "NEXUS-FIM-001"])
    check("premium FIM rule filtered on free", fim_after == fim_before)

    print("== 27b. Fix: license HOT-RELOAD (free -> pro tanpa restart manager) ==")
    pro_tok = lic.issue(_SEED, "HotReload", tier="pro", days=365, max_agents=5)
    ra = mgr.apply_license(pro_tok)
    check("apply_license hot-reload -> pro", ra.get("ok") and ra.get("tier") == "pro")
    # Regresi: token PRO seat-based menghormati max_agents (bukan jatuh ke FREE=2).
    pro50 = lic.issue(_SEED, "Seat50", tier="pro", days=365, max_agents=50)
    mgr.apply_license(pro50)
    check("pro seat-based max_agents=50", mgr.license_status()["max_agents"] == 50)
    # Regresi inti bug: token PRO TANPA field max_agents -> default seat PRO (50), bukan 2.
    pro_nomax = lic.issue(_SEED, "NoMax", tier="pro", days=365, max_agents=None)
    en = lic.entitlements(token=pro_nomax)
    check("pro tanpa max_agents -> 50 (bukan 2)", en["max_agents"] == lic.PRO_DEFAULT_SEATS)
    # Regresi: ENTERPRISE = unlimited (None) walau max_agents token = 0.
    ent0 = lic.issue(_SEED, "Ent", tier="enterprise", days=365, max_agents=0)
    check("enterprise -> unlimited (None)", lic.entitlements(token=ent0)["max_agents"] is None)
    mgr.apply_license("")          # kembali ke free utk seksi 28
    check("apply kosong -> free", mgr.license_status()["tier"] == "free")

    print("== 28. Gerbang FREE: batas jumlah agent (seat) ==")
    c = mgr._conn()
    cur = c.execute("SELECT COUNT(*) n FROM agents").fetchone()["n"]
    while cur < 2:
        c.execute("INSERT INTO agents(agent_id,agent_key,name,status,enrolled_at,last_seen) "
                  "VALUES(?,?,?,?,?,?)", (fc.new_id("agt"), "k", "dummy", "active", fc.now(), 0))
        cur += 1
    c.commit(); c.close()
    try:
        fc.post_enroll(fc.manager_url("127.0.0.1", PORT, "/enroll"),
                       {"name": "overflow", "fingerprint": fc.host_fingerprint(), "ip": ""},
                       enroll_key)
        check("free enroll limit enforced", False)
    except fc.HttpError as ex:
        check("free enroll limit enforced", ex.status == 403)

    mgr.stop()
    print()
    if FAILED:
        print(f"FAILED ({len(FAILED)}): {FAILED}")
        return 1
    print("ALL FLEET TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

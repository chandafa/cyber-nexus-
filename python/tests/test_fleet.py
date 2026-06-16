#!/usr/bin/env python3
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

    mgr.stop()
    print()
    if FAILED:
        print(f"FAILED ({len(FAILED)}): {FAILED}")
        return 1
    print("ALL FLEET TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

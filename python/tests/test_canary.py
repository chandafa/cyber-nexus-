# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# tests/test_canary.py
"""Uji Nexus Canary (honeytokens): mint, deteksi via event-match & via URL-trigger,
alert fidelitas tinggi NEXUS-CANARY-001, dan statistik."""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "fleet"))
os.environ["NEXUS_FLEET_DB"] = os.path.join(tempfile.mkdtemp(), "canary_test.db")

from nexus_manager import server as mgr            # noqa: E402
from nexus_secops import canary                    # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        _fail += 1


def main():
    mgr.init_db()

    # 1) mint berbagai tipe
    cred = mgr.canary_mint("credential", "db-svc", base_url="http://mgr:8765")
    url = mgr.canary_mint("url", "web-bug", base_url="http://mgr:8765")
    awsk = mgr.canary_mint("aws_key", "ci-key", base_url="http://mgr:8765")
    check("mint credential ok + username", cred["ok"] and cred["artifact"]["username"])
    check("mint url ok + canary_url", url["ok"] and "/c/" in url["artifact"]["canary_url"])
    check("mint aws_key ok + AKIA", awsk["ok"] and awsk["artifact"]["access_key_id"].startswith("AKIA"))

    user = cred["artifact"]["username"]
    marker = url["marker"]
    akid = awsk["artifact"]["access_key_id"]

    # 2) deteksi via event-match (username umpan muncul di event)
    c = mgr._conn()
    ev = {"event_id": "e1", "type": "auth", "event_type": "failed_login",
          "detail": f"failed login user={user} from 10.0.0.9"}
    n = mgr._run_canary(c, ev, "agt1", "default")
    c.commit()
    check("event-match memicu tepat 1 alert", n == 1)
    arow = c.execute("SELECT level,severity,rule_id FROM alerts "
                     "WHERE rule_id='NEXUS-CANARY-001'").fetchone()
    check("alert level 14 / critical", arow and arow["level"] == 14 and arow["severity"] == "critical")

    # aws key umpan dalam event lain
    ev2 = {"event_id": "e2", "type": "cloudtrail", "detail": f"AccessKeyId={akid} used"}
    n2 = mgr._run_canary(c, ev2, "agt1", "default")
    c.commit(); c.close()
    check("aws_key umpan terdeteksi", n2 == 1)

    # 3) dedup: event identik berulang tak menggandakan alert dalam window
    c = mgr._conn()
    n3 = mgr._run_canary(c, dict(ev), "agt1", "default")
    c.commit(); c.close()
    check("dedup alert berulang (window)", n3 == 0)

    # 4) deteksi via URL hit (/c/<marker>)
    fired = mgr.canary_http_trigger(marker, "http:1.2.3.4 ua=curl")
    check("URL-trigger memicu", fired is True)
    fired_bad = mgr.canary_http_trigger("nxc_tidakada", "http:x")
    check("marker tak dikenal tak memicu", fired_bad is False)

    # 5) stats + list + delete
    st = canary.stats("default")
    check("stats: 3 token, >=3 trigger", st["tokens"] == 3 and st["total_triggers"] >= 3)
    lst = canary.list_tokens("default")
    check("list mengembalikan token + canary_url", len(lst["tokens"]) == 3 and
          all(t.get("canary_url") for t in lst["tokens"]))
    d = canary.delete_token(url["id"])
    check("delete token", d["ok"] and canary.stats("default")["tokens"] == 2)

    print("\nSEMUA TES CANARY LULUS." if not _fail else f"\n{_fail} TES CANARY GAGAL.")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())

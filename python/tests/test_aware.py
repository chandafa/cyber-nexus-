#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""Uji Nexus Aware (simulasi phishing / security-awareness): template Indonesia,
buat kampanye + token unik, render email ber-{{name}}/{{link}}, pelacakan
open/click/report (click ⇒ open), skor + rate + per-user, token tak dikenal, hapus."""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "fleet"))
os.environ["NEXUS_FLEET_DB"] = os.path.join(tempfile.mkdtemp(), "aware_test.db")

from nexus_secops import aware                       # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        _fail += 1


def main():
    # 1) template katalog
    tpls = aware.list_templates()
    check("list_templates ok & >=6 template", tpls["ok"] and len(tpls["templates"]) >= 6)
    check("template tanpa body penuh", all("body" not in t for t in tpls["templates"]))
    check("difficulty valid (mudah/sedang/sulit)",
          all(t["difficulty"] in ("mudah", "sedang", "sulit") for t in tpls["templates"]))

    # 2) buat kampanye + token unik
    targets = [
        {"name": "Budi Santoso", "email": "budi@contoh.co.id"},
        {"name": "Siti Aminah", "email": "siti@contoh.co.id"},
        {"name": "Andi Wijaya", "email": "andi@contoh.co.id"},
    ]
    camp = aware.create_campaign("Latihan Q2", "otp_bank", targets)
    check("create_campaign ok + 3 target", camp["ok"] and camp["count"] == 3)
    toks = [t["token"] for t in camp["targets"]]
    check("token unik per target", len(set(toks)) == 3 and all(toks))
    check("link_path = /aw/<token>",
          all(t["link_path"] == f"/aw/{t['token']}" for t in camp["targets"]))

    bad = aware.create_campaign("X", "template_palsu", targets)
    check("template tak dikenal ditolak", not bad["ok"])

    cid = camp["campaign_id"]

    # 3) render email — {{name}} & {{link}} terisi
    rend = aware.render_emails(cid, base_url="https://mgr.contoh.co.id")
    check("render_emails ok + 3 email", rend["ok"] and len(rend["emails"]) == 3)
    e0 = rend["emails"][0]
    tok0 = camp["targets"][0]["token"]
    check("email[0] ke target benar", e0["to"] == "budi@contoh.co.id")
    check("{{name}} terisi", "Budi Santoso" in e0["body"])
    check("{{link}} terisi base_url+/aw/<token>",
          f"https://mgr.contoh.co.id/aw/{tok0}" in e0["body"])
    check("tidak ada placeholder tersisa",
          "{{name}}" not in e0["body"] and "{{link}}" not in e0["body"])

    # 4) pelacakan: open / click(⇒open) / report
    r_open = aware.record(toks[0], "open")
    check("record open ok + campaign_id", r_open["ok"] and r_open["campaign_id"] == cid)
    r_click = aware.record(toks[1], "click")
    check("record click ok", r_click["ok"])
    r_rep = aware.record(toks[2], "report")
    check("record report ok", r_rep["ok"])

    gc = aware.get_campaign(cid)["campaign"]
    by_tok = {t["token"]: t for t in gc["targets"]}
    check("open → opened=1, clicked=0", by_tok[toks[0]]["opened"] and not by_tok[toks[0]]["clicked"])
    check("click ⇒ opened=1 & clicked=1",
          by_tok[toks[1]]["opened"] and by_tok[toks[1]]["clicked"])
    check("report → reported=1", by_tok[toks[2]]["reported"])
    check("last_event_ts terisi", all(by_tok[t]["last_event_ts"] for t in toks))

    # 5) token tak dikenal ditolak
    rj = aware.record("token_tidak_ada_000", "open")
    check("token tak dikenal → ok:False", rj["ok"] is False)
    check("kind tak dikenal → ok:False", aware.record(toks[0], "tendang")["ok"] is False)

    # 6) skor + rate + per_user
    sc = aware.score(cid)
    check("score: sent=3", sc["sent"] == 3)
    check("score: opened=2 (open+click)", sc["opened"] == 2)
    check("score: clicked=1", sc["clicked"] == 1)
    check("score: reported=1", sc["reported"] == 1)
    check("click_rate=1/3", abs(sc["click_rate"] - round(1 / 3, 4)) < 1e-9)
    check("report_rate=1/3", abs(sc["report_rate"] - round(1 / 3, 4)) < 1e-9)
    check("per_user 3 entri", len(sc["per_user"]) == 3)
    pu = {p["email"]: p for p in sc["per_user"]}
    check("per_user click target benar", pu["siti@contoh.co.id"]["clicked"] is True)
    check("per_user report target benar", pu["andi@contoh.co.id"]["reported"] is True)

    # 7) list + agregat tenant
    lst = aware.list_campaigns()
    check("list_campaigns memuat kampanye", any(c["id"] == cid for c in lst["campaigns"]))
    agg = aware.score()  # tanpa campaign_id → agregat tenant
    check("agregat tenant: sent>=3", agg["sent"] >= 3)

    # 8) hapus kampanye
    d = aware.delete_campaign(cid)
    check("delete_campaign ok + 3 target dihapus", d["ok"] and d["deleted_targets"] == 3)
    check("kampanye hilang setelah delete", not aware.get_campaign(cid)["ok"])
    check("token mati setelah delete", aware.record(toks[0], "open")["ok"] is False)

    print("\nSEMUA TES AWARE LULUS." if not _fail else f"\n{_fail} TES AWARE GAGAL.")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())

# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_cli/__main__.py
"""
nexus-cli — console keamanan & admin Nexus Fleet.

Interaktif (menu jaringan & website, ala-Wazuh):
    python -m nexus_cli                     # buka menu
    python -m nexus_cli menu

Non-interaktif (scripting/admin):
    python -m nexus_cli agents      --token <ADMIN_TOKEN>
    python -m nexus_cli events      --token <ADMIN_TOKEN> --limit 50
    python -m nexus_cli stats       --token <ADMIN_TOKEN>
    python -m nexus_cli policy-get
    python -m nexus_cli policy-set  --token <ADMIN_TOKEN> --file policy.json
    python -m nexus_cli command      --token <ADMIN_TOKEN> --agent agt_xxx --cmd collect_now

Opsi global: --host (default 127.0.0.1) --port (8765) --token (atau env NEXUS_ADMIN_TOKEN)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_common import protocol as fc  # noqa: E402
from nexus_common import __version__  # noqa: E402
from nexus_cli import admin, menu  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-cli", description="Console keamanan & admin Nexus Fleet")
    p.add_argument("-V", "--version", action="version", version=f"nexus-cli {__version__}")
    p.add_argument("--host", default=fc.DEFAULT_MANAGER_HOST)
    p.add_argument("--port", default=str(fc.DEFAULT_MANAGER_PORT))
    p.add_argument("--token", default=os.environ.get("NEXUS_ADMIN_TOKEN", ""))
    p.add_argument("--tls", action="store_true", help="hubungi manager via HTTPS")
    p.add_argument("--cacert", default="", help="CA/cert untuk verifikasi TLS")
    p.add_argument("--insecure", action="store_true", help="HTTPS tanpa verifikasi cert (uji saja)")
    sub = p.add_subparsers(dest="action")

    sub.add_parser("menu")
    sub.add_parser("agents")
    e = sub.add_parser("events"); e.add_argument("--limit", type=int, default=100)
    al = sub.add_parser("alerts")
    al.add_argument("--limit", type=int, default=100); al.add_argument("--status", default="")
    ak = sub.add_parser("ack")
    ak.add_argument("--id", required=True); ak.add_argument("--status", default="ack")
    rp = sub.add_parser("report"); rp.add_argument("--scope", default="fleet")
    sub.add_parser("stats")
    sub.add_parser("health")
    sub.add_parser("policy-get")
    ps = sub.add_parser("policy-set"); ps.add_argument("--file"); ps.add_argument("--json")
    cm = sub.add_parser("command")
    cm.add_argument("--agent", required=True); cm.add_argument("--cmd", required=True)
    cm.add_argument("--args", default="")
    apl = sub.add_parser("apply-license", help="pasang lisensi ke manager (hot-reload)")
    apl.add_argument("--file"); apl.add_argument("--token", dest="lic")
    rma = sub.add_parser("remove-agent", help="hapus pendaftaran agent (bebaskan seat)")
    rma.add_argument("--agent", required=True); rma.add_argument("--purge", action="store_true")
    inc = sub.add_parser("incidents", help="alert dikelompokkan jadi insiden")
    inc.add_argument("--status", default="open")
    au = sub.add_parser("add-user", help="buat token RBAC (admin|viewer)")
    au.add_argument("--role", default="viewer", choices=["admin", "viewer"])
    sub.add_parser("users", help="daftar pengguna/token RBAC")
    sub.add_parser("rules-get", help="daftar rule deteksi")
    rs = sub.add_parser("rules-set", help="ganti ruleset dari file JSON"); rs.add_argument("--file", required=True)
    rsg = sub.add_parser("rules-sigma", help="impor rule Sigma dari file"); rsg.add_argument("--file", required=True)
    nt = sub.add_parser("notify", help="set webhook untuk alert severity tinggi")
    nt.add_argument("--webhook", required=True); nt.add_argument("--min-level", type=int, default=12)
    aud = sub.add_parser("audit", help="log audit"); aud.add_argument("--limit", type=int, default=200)
    sub.add_parser("audit-verify", help="verifikasi integritas rantai-hash audit")
    sub.add_parser("notify-list", help="daftar channel notifikasi")
    nad = sub.add_parser("notify-add", help="tambah channel notifikasi dari file JSON"); nad.add_argument("--file", required=True)
    ndel = sub.add_parser("notify-del", help="hapus channel notifikasi"); ndel.add_argument("--id", required=True)
    nts = sub.add_parser("notify-test", help="uji kirim ke channel (--id tersimpan atau --file)")
    nts.add_argument("--id", default=""); nts.add_argument("--file", default="")
    cmint = sub.add_parser("canary-mint", help="buat honeytoken (canary)")
    cmint.add_argument("--type", default="url",
                       choices=["credential", "aws_key", "url", "dns", "file", "env"])
    cmint.add_argument("--label", default=""); cmint.add_argument("--base-url", default="")
    sub.add_parser("canary-list", help="daftar honeytoken")
    cdel = sub.add_parser("canary-del", help="hapus honeytoken"); cdel.add_argument("--id", required=True)
    sub.add_parser("canary-stats", help="statistik trigger canary")
    rep = sub.add_parser("replay", help="time-travel: putar ulang event+alert (forensik)")
    rep.add_argument("--agent", default=""); rep.add_argument("--incident", default="")
    rep.add_argument("--from", dest="from_ts", type=int, default=0)
    rep.add_argument("--to", dest="to_ts", type=int, default=0)
    rep.add_argument("--limit", type=int, default=2000)
    ag = sub.add_parser("airgap", help="mode air-gapped (tanpa internet)")
    ag.add_argument("--on", action="store_true"); ag.add_argument("--off", action="store_true")
    tex = sub.add_parser("ti-export", help="ekspor IOC jadi bundle offline"); tex.add_argument("--file", default="")
    tib = sub.add_parser("ti-import-bundle", help="impor bundle IOC offline"); tib.add_argument("--file", required=True)
    # --- Nexus Aware (phishing-sim) ---
    sub.add_parser("aware-templates", help="daftar template phishing-sim (ID)")
    sub.add_parser("aware-campaigns", help="daftar kampanye Aware")
    asc = sub.add_parser("aware-score", help="skor kampanye"); asc.add_argument("--campaign", default="")
    anew = sub.add_parser("aware-new", help="buat kampanye dari file target JSON [{name,email}]")
    anew.add_argument("--name", required=True); anew.add_argument("--template", required=True)
    anew.add_argument("--file", required=True)
    asnd = sub.add_parser("aware-send", help="kirim email kampanye (via channel email hub)")
    asnd.add_argument("--id", required=True); asnd.add_argument("--base-url", default="")
    adel = sub.add_parser("aware-del", help="hapus kampanye"); adel.add_argument("--id", required=True)
    # --- Nexus Atlas (attack-path graph) ---
    sub.add_parser("atlas-graph", help="graph aset + koneksi")
    abl = sub.add_parser("atlas-blast", help="blast-radius dari sebuah node"); abl.add_argument("--node", required=True)
    aex = sub.add_parser("atlas-exposed", help="host paling terekspos"); aex.add_argument("--limit", type=int, default=10)
    sub.add_parser("atlas-stats", help="statistik graph")
    # --- Nexus Hub (content packs) ---
    sub.add_parser("pack-catalog", help="katalog pack bawaan")
    pex = sub.add_parser("pack-export", help="ekspor konten (rules+IOC+playbook) jadi pack"); pex.add_argument("--file", default="")
    pim = sub.add_parser("pack-import", help="impor pack dari file JSON"); pim.add_argument("--file", required=True)
    pins = sub.add_parser("pack-install", help="install pack dari katalog"); pins.add_argument("--id", required=True)
    # --- Nexus Edge (ingest syslog agentless) ---
    syi = sub.add_parser("syslog-ingest", help="ingest baris syslog dari file (router/IoT)")
    syi.add_argument("--file", required=True)
    syi.add_argument("--device", dest="device_host", default="", help="host/IP perangkat sumber")
    # --- Nexus Comply (UU PDP / ISO 27001) ---
    sub.add_parser("comply-frameworks", help="daftar framework compliance")
    crep = sub.add_parser("comply-report", help="laporan cakupan compliance")
    crep.add_argument("--framework", default="uu-pdp", choices=["uu-pdp", "iso27001"])
    sub.add_parser("vulndb-get", help="lihat database kerentanan (CVE)")
    vdb = sub.add_parser("vulndb-import", help="impor database CVE dari file JSON"); vdb.add_argument("--file", required=True)
    ra = sub.add_parser("response", help="active response: block-ip / kill-process / dll")
    ra.add_argument("--agent", required=True)
    ra.add_argument("--action", dest="resp_action", required=True, help="mis. block_ip, kill_process")
    ra.add_argument("--ip", default=""); ra.add_argument("--target", default=""); ra.add_argument("--process", default="")
    # --- SecOps (Pro) — lapisan analitik SOC ---
    se = sub.add_parser("search", help="SIEM: cari event/alert (NQL)")
    se.add_argument("--index", default="events", choices=["events", "alerts"])
    se.add_argument("--q", default=""); se.add_argument("--limit", type=int, default=200)
    xd = sub.add_parser("xdr", help="XDR: insiden terkorelasi"); xd.add_argument("--status", default="")
    sub.add_parser("ueba", help="UEBA: skor risiko entitas")
    sub.add_parser("ti", help="Threat Intel: daftar IOC")
    sub.add_parser("ndr", help="NDR: top talker jaringan")
    sub.add_parser("cloud", help="Cloud CSPM: temuan misconfig")
    sub.add_parser("triage", help="AI: hasil triase insiden")
    sub.add_parser("soar", help="SOAR: daftar playbook")

    # --- SecOps (lanjutan): baca-detail + aksi tulis tiap pilar (paritas penuh dgn GUI) ---
    ss = sub.add_parser("siem-stats", help="SIEM: agregasi/statistik")
    ss.add_argument("--index", default="events", choices=["events", "alerts"])
    ss.add_argument("--q", default=""); ss.add_argument("--field", default="event_type")
    ss.add_argument("--top", type=int, default=10); ss.add_argument("--buckets", type=int, default=24)

    xg = sub.add_parser("xdr-get", help="XDR: detail insiden"); xg.add_argument("--id", required=True)
    xa = sub.add_parser("xdr-ack", help="XDR: tandai insiden")
    xa.add_argument("--id", required=True); xa.add_argument("--status", default="ack")
    xc = sub.add_parser("xdr-correlate", help="XDR: jalankan korelasi sekarang")
    xc.add_argument("--lookback", type=int, default=86400)

    sub.add_parser("edr-hosts", help="EDR: host dengan data proses")
    et = sub.add_parser("edr-tree", help="EDR: pohon proses"); et.add_argument("--agent", required=True)
    ep = sub.add_parser("edr-processes", help="EDR: cari proses")
    ep.add_argument("--agent", required=True); ep.add_argument("--q", default="")
    ea = sub.add_parser("edr-ancestry", help="EDR: silsilah proses")
    ea.add_argument("--agent", required=True); ea.add_argument("--pid", required=True)

    tm = sub.add_parser("ti-matches", help="TI: kecocokan IOC pada event"); tm.add_argument("--limit", type=int, default=200)
    sub.add_parser("ti-stats", help="TI: statistik IOC")
    ta = sub.add_parser("ti-add", help="TI: tambah satu IOC")
    ta.add_argument("--type", required=True); ta.add_argument("--value", required=True)
    ta.add_argument("--threat", default="manual"); ta.add_argument("--severity", default="high")
    ta.add_argument("--source", default="manual")
    ti_ = sub.add_parser("ti-import", help="TI: impor feed IOC (URL/file)")
    ti_.add_argument("--url", required=True); ti_.add_argument("--fmt", default="text")
    ti_.add_argument("--source", default=""); ti_.add_argument("--threat", default="feed")
    ti_.add_argument("--severity", default="high"); ti_.add_argument("--col", type=int, default=0)
    td = sub.add_parser("ti-delete", help="TI: hapus IOC"); td.add_argument("--id", required=True)
    tsc = sub.add_parser("ti-scan", help="TI: retro-hunt event vs IOC"); tsc.add_argument("--lookback", type=int, default=604800)

    sub.add_parser("ueba-baselines", help="UEBA: baseline perilaku")
    up_ = sub.add_parser("ueba-peers", help="UEBA: analisis peer-group"); up_.add_argument("--window", type=int, default=86400)
    ut = sub.add_parser("ueba-train", help="UEBA: latih baseline"); ut.add_argument("--lookback", type=int, default=1209600)
    us = sub.add_parser("ueba-scan", help="UEBA: skor anomali & emit event")
    us.add_argument("--window", type=int, default=86400); us.add_argument("--no-emit", action="store_true")

    aii = sub.add_parser("ai-incident", help="AI: detail triase insiden"); aii.add_argument("--id", required=True)
    sub.add_parser("ai-model", help="AI: status model")
    an = sub.add_parser("ai-nl", help="AI: kueri bahasa natural"); an.add_argument("--q", required=True)
    sub.add_parser("ai-train", help="AI: latih/retrain model")
    ar = sub.add_parser("ai-run", help="AI: jalankan triase")
    ar.add_argument("--id", default=""); ar.add_argument("--status", default="open")

    sub.add_parser("cloud-posture", help="Cloud: skor postur")
    sub.add_parser("cloud-stats", help="Cloud: statistik temuan")
    cs = sub.add_parser("cloud-scan", help="Cloud: pindai resource/impor Prowler")
    cs.add_argument("--file", help="JSON resources atau output Prowler")
    cs.add_argument("--prowler", action="store_true", help="perlakukan --file sebagai output Prowler")
    cs.add_argument("--provider", default="aws"); cs.add_argument("--account", default="default")

    nf = sub.add_parser("ndr-flows", help="NDR: daftar flow jaringan")
    nf.add_argument("--agent", default=""); nf.add_argument("--limit", type=int, default=500)
    sub.add_parser("ndr-stats", help="NDR: statistik jaringan")

    sr = sub.add_parser("soar-runs", help="SOAR: riwayat eksekusi"); sr.add_argument("--limit", type=int, default=200)
    sv = sub.add_parser("soar-save", help="SOAR: simpan playbook dari file JSON"); sv.add_argument("--file", required=True)
    sen = sub.add_parser("soar-enable", help="SOAR: aktif/nonaktifkan playbook")
    sen.add_argument("--id", required=True); sen.add_argument("--off", action="store_true")
    sm = sub.add_parser("soar-mode", help="SOAR: set mode playbook")
    sm.add_argument("--id", required=True); sm.add_argument("--mode", default="dry_run", choices=["dry_run", "execute"])
    sd = sub.add_parser("soar-delete", help="SOAR: hapus playbook"); sd.add_argument("--id", required=True)
    sru = sub.add_parser("soar-run", help="SOAR: jalankan playbook manual")
    sru.add_argument("--id", required=True); sru.add_argument("--ref", default="")
    args = p.parse_args(argv)

    # Konfigurasi TLS untuk transport admin (Fix: TLS untuk CLI/dashboard).
    if args.tls or args.insecure:
        admin.set_scheme("https")
        fc.set_client_tls(cafile=args.cacert, insecure=args.insecure or not args.cacert)

    # default / 'menu' -> interaktif
    if args.action in (None, "menu"):
        return menu.run(args.host, args.port, args.token)

    try:
        if args.action == "agents":
            out = admin.agents(args.host, args.port, args.token)
        elif args.action == "events":
            out = admin.events(args.host, args.port, args.token, args.limit)
        elif args.action == "alerts":
            out = admin.alerts(args.host, args.port, args.token, args.limit, args.status)
        elif args.action == "ack":
            out = admin.ack(args.host, args.port, args.token, args.id, args.status)
        elif args.action == "report":
            out = admin.report(args.host, args.port, args.token, args.scope)
        elif args.action == "stats":
            out = admin.stats(args.host, args.port, args.token)
        elif args.action == "health":
            out = admin.health(args.host, args.port)
        elif args.action == "policy-get":
            out = admin.policy_get(args.host, args.port)
        elif args.action == "policy-set":
            if args.file:
                with open(args.file, encoding="utf-8") as f:
                    pol = json.load(f)
            elif args.json:
                pol = json.loads(args.json)
            else:
                raise SystemExit("policy-set butuh --file atau --json")
            out = admin.policy_set(args.host, args.port, args.token, pol)
        elif args.action == "command":
            out = admin.command(args.host, args.port, args.token, args.agent, args.cmd,
                                json.loads(args.args) if args.args else {})
        elif args.action == "apply-license":
            lic = args.lic or ""
            if args.file:
                with open(args.file, encoding="utf-8") as f:
                    lic = f.read().strip()
            out = admin.apply_license(args.host, args.port, args.token, lic)
        elif args.action == "remove-agent":
            out = admin.remove_agent(args.host, args.port, args.token, args.agent, args.purge)
        elif args.action == "incidents":
            out = admin.incidents(args.host, args.port, args.token, args.status)
        elif args.action == "add-user":
            out = admin.add_user(args.host, args.port, args.token, args.role)
        elif args.action == "users":
            out = admin.list_users(args.host, args.port, args.token)
        elif args.action == "rules-get":
            out = admin.rules_get(args.host, args.port, args.token)
        elif args.action == "rules-set":
            with open(args.file, encoding="utf-8") as f:
                rules = json.load(f)
            out = admin.rules_set(args.host, args.port, args.token, rules)
        elif args.action == "rules-sigma":
            with open(args.file, encoding="utf-8") as f:
                sigma = json.load(f)
            out = admin.rules_sigma(args.host, args.port, args.token, sigma)
        elif args.action == "notify":
            out = admin.notify_set(args.host, args.port, args.token, args.webhook, args.min_level)
        elif args.action == "audit":
            out = admin.audit(args.host, args.port, args.token, args.limit)
        elif args.action == "audit-verify":
            out = admin.audit_verify(args.host, args.port, args.token)
        elif args.action == "notify-list":
            out = admin.notify_list(args.host, args.port, args.token)
        elif args.action == "notify-add":
            with open(args.file, encoding="utf-8") as f:
                ch = json.load(f)
            out = admin.notify_channel_add(args.host, args.port, args.token, ch)
        elif args.action == "notify-del":
            out = admin.notify_channel_del(args.host, args.port, args.token, args.id)
        elif args.action == "notify-test":
            ch = None
            if args.file:
                with open(args.file, encoding="utf-8") as f:
                    ch = json.load(f)
            out = admin.notify_test(args.host, args.port, args.token, args.id, ch)
        elif args.action == "canary-mint":
            out = admin.canary_mint(args.host, args.port, args.token, args.type,
                                    args.label, args.base_url)
        elif args.action == "canary-list":
            out = admin.canary_tokens(args.host, args.port, args.token)
        elif args.action == "canary-del":
            out = admin.canary_delete(args.host, args.port, args.token, args.id)
        elif args.action == "canary-stats":
            out = admin.canary_stats(args.host, args.port, args.token)
        elif args.action == "replay":
            out = admin.replay(args.host, args.port, args.token, args.agent,
                               args.from_ts, args.to_ts, args.incident, args.limit)
        elif args.action == "airgap":
            if args.on or args.off:
                out = admin.airgap_set(args.host, args.port, args.token, args.on)
            else:
                out = admin.airgap_status(args.host, args.port, args.token)
        elif args.action == "ti-export":
            out = admin.ti_export(args.host, args.port, args.token)
            if args.file and isinstance(out, dict):
                with open(args.file, "w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, indent=2)
                out = {"ok": out.get("ok"), "written": args.file, "count": out.get("count")}
        elif args.action == "ti-import-bundle":
            with open(args.file, encoding="utf-8") as f:
                bundle = json.load(f)
            out = admin.ti_import_bundle(args.host, args.port, args.token, bundle)
        # --- Nexus Aware ---
        elif args.action == "aware-templates":
            out = admin.aware_templates(args.host, args.port, args.token)
        elif args.action == "aware-campaigns":
            out = admin.aware_campaigns(args.host, args.port, args.token)
        elif args.action == "aware-score":
            out = admin.aware_score(args.host, args.port, args.token, args.campaign)
        elif args.action == "aware-new":
            with open(args.file, encoding="utf-8") as f:
                targets = json.load(f)
            out = admin.aware_campaign(args.host, args.port, args.token, args.name,
                                       args.template, targets)
        elif args.action == "aware-send":
            out = admin.aware_send(args.host, args.port, args.token, args.id, args.base_url)
        elif args.action == "aware-del":
            out = admin.aware_delete(args.host, args.port, args.token, args.id)
        # --- Nexus Atlas ---
        elif args.action == "atlas-graph":
            out = admin.atlas_graph(args.host, args.port, args.token)
        elif args.action == "atlas-blast":
            out = admin.atlas_blast(args.host, args.port, args.token, args.node)
        elif args.action == "atlas-exposed":
            out = admin.atlas_exposed(args.host, args.port, args.token, args.limit)
        elif args.action == "atlas-stats":
            out = admin.atlas_stats(args.host, args.port, args.token)
        # --- Nexus Hub ---
        elif args.action == "pack-catalog":
            out = admin.pack_catalog(args.host, args.port, args.token)
        elif args.action == "pack-export":
            out = admin.pack_export(args.host, args.port, args.token)
            if args.file and isinstance(out, dict):
                with open(args.file, "w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, indent=2)
                out = {"ok": True, "written": args.file}
        elif args.action == "pack-import":
            with open(args.file, encoding="utf-8") as f:
                pack = json.load(f)
            out = admin.pack_import(args.host, args.port, args.token, pack)
        elif args.action == "pack-install":
            out = admin.pack_install(args.host, args.port, args.token, args.id)
        # --- Nexus Edge ---
        elif args.action == "syslog-ingest":
            with open(args.file, encoding="utf-8") as f:
                lines = f.read().splitlines()
            out = admin.syslog_ingest(args.host, args.port, args.token, lines, args.device_host)
        # --- Nexus Comply ---
        elif args.action == "comply-frameworks":
            out = admin.comply_frameworks(args.host, args.port, args.token)
        elif args.action == "comply-report":
            out = admin.comply_report(args.host, args.port, args.token, args.framework)
        elif args.action == "vulndb-get":
            out = admin.vulndb_get(args.host, args.port, args.token)
        elif args.action == "vulndb-import":
            with open(args.file, encoding="utf-8") as f:
                vdb = json.load(f)
            out = admin.vulndb_set(args.host, args.port, args.token, vdb)
        elif args.action == "response":
            out = admin.response_action(args.host, args.port, args.token, args.agent,
                                        args.resp_action, args.ip, args.target, args.process)
        # --- SecOps (Pro) — manager membalas 403 bila lisensi bukan Pro/Enterprise ---
        elif args.action == "search":
            out = admin.search(args.host, args.port, args.token, args.index, args.q, args.limit)
        elif args.action == "xdr":
            out = admin.xdr(args.host, args.port, args.token, args.status)
        elif args.action == "ueba":
            out = admin.ueba(args.host, args.port, args.token)
        elif args.action == "ti":
            out = admin.ti(args.host, args.port, args.token)
        elif args.action == "ndr":
            out = admin.ndr(args.host, args.port, args.token)
        elif args.action == "cloud":
            out = admin.cloud(args.host, args.port, args.token)
        elif args.action == "triage":
            out = admin.triage(args.host, args.port, args.token)
        elif args.action == "soar":
            out = admin.soar(args.host, args.port, args.token)
        # --- SecOps (lanjutan) ---
        elif args.action == "siem-stats":
            out = admin.siem_stats(args.host, args.port, args.token, args.index, args.q,
                                   args.field, args.top, args.buckets)
        elif args.action == "xdr-get":
            out = admin.xdr_get(args.host, args.port, args.token, args.id)
        elif args.action == "xdr-ack":
            out = admin.xdr_ack(args.host, args.port, args.token, args.id, args.status)
        elif args.action == "xdr-correlate":
            out = admin.xdr_correlate(args.host, args.port, args.token, args.lookback)
        elif args.action == "edr-hosts":
            out = admin.edr_hosts(args.host, args.port, args.token)
        elif args.action == "edr-tree":
            out = admin.edr_tree(args.host, args.port, args.token, args.agent)
        elif args.action == "edr-processes":
            out = admin.edr_processes(args.host, args.port, args.token, args.agent, args.q)
        elif args.action == "edr-ancestry":
            out = admin.edr_ancestry(args.host, args.port, args.token, args.agent, args.pid)
        elif args.action == "ti-matches":
            out = admin.ti_matches(args.host, args.port, args.token, args.limit)
        elif args.action == "ti-stats":
            out = admin.ti_stats(args.host, args.port, args.token)
        elif args.action == "ti-add":
            ioc = {"type": args.type, "value": args.value,
                   "threat": args.threat, "severity": args.severity}
            out = admin.ti_add(args.host, args.port, args.token, [ioc], args.source)
        elif args.action == "ti-import":
            out = admin.ti_import(args.host, args.port, args.token, args.url, args.fmt,
                                  args.source or None, args.threat, args.severity, args.col)
        elif args.action == "ti-delete":
            out = admin.ti_delete(args.host, args.port, args.token, args.id)
        elif args.action == "ti-scan":
            out = admin.ti_scan(args.host, args.port, args.token, args.lookback)
        elif args.action == "ueba-baselines":
            out = admin.ueba_baselines(args.host, args.port, args.token)
        elif args.action == "ueba-peers":
            out = admin.ueba_peers(args.host, args.port, args.token, args.window)
        elif args.action == "ueba-train":
            out = admin.ueba_train(args.host, args.port, args.token, args.lookback)
        elif args.action == "ueba-scan":
            out = admin.ueba_scan(args.host, args.port, args.token, args.window, not args.no_emit)
        elif args.action == "ai-incident":
            out = admin.ai_incident(args.host, args.port, args.token, args.id)
        elif args.action == "ai-model":
            out = admin.ai_model(args.host, args.port, args.token)
        elif args.action == "ai-nl":
            out = admin.ai_nl(args.host, args.port, args.token, args.q)
        elif args.action == "ai-train":
            out = admin.ai_train(args.host, args.port, args.token)
        elif args.action == "ai-run":
            out = admin.ai_run(args.host, args.port, args.token, args.id, args.status)
        elif args.action == "cloud-posture":
            out = admin.cloud_posture(args.host, args.port, args.token)
        elif args.action == "cloud-stats":
            out = admin.cloud_stats(args.host, args.port, args.token)
        elif args.action == "cloud-scan":
            data = None
            if args.file:
                with open(args.file, encoding="utf-8") as f:
                    data = json.load(f)
            if args.prowler:
                out = admin.cloud_scan(args.host, args.port, args.token, prowler=data,
                                       provider=args.provider, account=args.account)
            else:
                out = admin.cloud_scan(args.host, args.port, args.token, resources=data,
                                       provider=args.provider, account=args.account)
        elif args.action == "ndr-flows":
            out = admin.ndr_flows(args.host, args.port, args.token, args.agent, args.limit)
        elif args.action == "ndr-stats":
            out = admin.ndr_stats(args.host, args.port, args.token)
        elif args.action == "soar-runs":
            out = admin.soar_runs(args.host, args.port, args.token, args.limit)
        elif args.action == "soar-save":
            with open(args.file, encoding="utf-8") as f:
                pb = json.load(f)
            out = admin.soar_save(args.host, args.port, args.token, pb)
        elif args.action == "soar-enable":
            out = admin.soar_enable(args.host, args.port, args.token, args.id, not args.off)
        elif args.action == "soar-mode":
            out = admin.soar_mode(args.host, args.port, args.token, args.id, args.mode)
        elif args.action == "soar-delete":
            out = admin.soar_delete(args.host, args.port, args.token, args.id)
        elif args.action == "soar-run":
            out = admin.soar_run(args.host, args.port, args.token, args.id, args.ref)
        else:
            raise SystemExit(f"aksi tidak dikenal: {args.action}")
    except fc.HttpError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

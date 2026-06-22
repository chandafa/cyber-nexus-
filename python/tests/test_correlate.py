#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.correlate — mesin XDR (korelasi kill-chain).

Beroperasi atas store NYATA manager (tabel alerts SQLite, DB terisolasi) — bukan
demo. Memverifikasi: pembentukan insiden dari alert terkorelasi, timeline kill-
chain + MITRE, upsert idempoten per (rule,entity,tenant), reopen-on-new-signal,
serta perbedaan mode sequence vs set.

Termasuk PROBE untuk isu laten yang diketahui (_cover set-mode, correlate.py:145):
SATU alert bisa memuaskan BANYAK tahap set-mode. Test mendokumentasikan perilaku
SAAT INI (tanpa mengubah kode produk).
"""
import os
import sys
import tempfile

# Windows: paksa stdout UTF-8 agar karakter non-ASCII (panah, dsb.) tak crash cp1252.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)
sys.path.insert(0, os.path.join(PYDIR, "fleet"))

_tmp = tempfile.mkdtemp(prefix="nexus_correlate_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_common import protocol as fc        # noqa: E402
from nexus_common import schema                # noqa: E402
from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import correlate as xdr      # noqa: E402

FAILED = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def _insert_alert(agent_id, rule_id, event_type, level, ts, severity="high",
                  mitre=None, target=None):
    rule = {"id": rule_id, "name": rule_id, "level": level,
            "mitre": mitre if mitre is not None else ["T1110"]}
    ev = schema.normalize_event({"type": event_type, "event_type": event_type,
                                 "severity": severity, "title": f"{event_type} on {agent_id}",
                                 "ts": ts, "target": target or {}})
    ev = schema.enrich_event(ev, agent_id=agent_id, tenant_id="default", host={})
    al = schema.make_alert(agent_id, rule, ev, "default", ts=ts)
    c = mgr._conn()
    mgr._insert_alert(c, al)
    c.commit(); c.close()
    return al["id"]


# Rule sequence sederhana untuk uji terisolasi (tak bergantung default).
SEQ_RULE = [{
    "id": "T-SEQ", "name": "Seq test", "group_by": "agent_id",
    "mode": "sequence", "window": 1800, "level": 14, "mitre": ["TX"],
    "stages": [
        {"rule_id": ["NEXUS-AUTH-001"]},
        {"rule_id": ["NEXUS-PROC-001"]},
    ],
}]

# Rule set-mode normal: dua tahap dgn rule_id BERBEDA (perlu 2 alert berbeda).
SET_RULE = [{
    "id": "T-SET", "name": "Set test", "group_by": "agent_id",
    "mode": "set", "window": 3600, "level": 13, "mitre": ["TY"],
    "stages": [
        {"rule_id": ["NEXUS-NET-001"]},
        {"rule_id": ["NEXUS-AUTH-001"]},
    ],
}]

# Rule PROBE: kedua tahap set-mode cocok ke rule_id YANG SAMA → satu alert bisa
# menutupi dua tahap (isu laten _cover set-mode di correlate.py:145).
PROBE_RULE = [{
    "id": "T-PROBE", "name": "Probe single-alert-multi-stage", "group_by": "agent_id",
    "mode": "set", "window": 3600, "level": 10, "mitre": ["TZ"],
    "stages": [
        {"rule_id": ["NEXUS-AUTH-001"]},
        {"rule_id": ["NEXUS-AUTH-001"]},
    ],
}]


def main():
    mgr.init_db()
    now = fc.now()

    # ------------------------------------------------------------- sequence
    print("== Pembentukan insiden dari alert terkorelasi (sequence) ==")
    _insert_alert("agt_seq", "NEXUS-AUTH-001", "failed_logins", 12, now - 600,
                  mitre=["T1110"])
    _insert_alert("agt_seq", "NEXUS-PROC-001", "suspicious_process", 12, now - 540,
                  mitre=["T1059"])
    out = xdr.correlate(lookback=3600, rules=SEQ_RULE)
    check("sequence: insiden dibuat", out["ok"] and out["created"] == 1)
    incs = xdr.list_incidents()["incidents"]
    seq = [i for i in incs if i["rule_id"] == "T-SEQ"]
    check("sequence: tepat 1 insiden T-SEQ", len(seq) == 1)
    check("sequence: entity = agt_seq", seq and seq[0]["entity"] == "agt_seq")
    check("sequence: gabung 2 alert (count=2)", seq and seq[0]["count"] == 2)
    check("sequence: level naik ke 14 (max rule/alert)", seq and seq[0]["level"] == 14)

    print("== Timeline kill-chain + MITRE ==")
    full = xdr.get_incident(seq[0]["id"])["incident"]
    tl = full["timeline"]
    check("timeline punya 2 tahap", len(tl) == 2)
    check("timeline terurut waktu naik", tl[0]["ts"] <= tl[1]["ts"])
    check("timeline tahap 0 = brute-force (AUTH)",
          tl[0]["rule_id"] == "NEXUS-AUTH-001" and tl[0]["stage"] == 0)
    check("timeline tahap 1 = proses (PROC)",
          tl[1]["rule_id"] == "NEXUS-PROC-001" and tl[1]["stage"] == 1)
    check("MITRE gabungan dari alert + rule (T1110,T1059,TX)",
          set(full["mitre"]) >= {"T1110", "T1059", "TX"})

    print("== Sequence: URUTAN salah tak memicu ==")
    # Proses dulu BARU brute-force → tahap sequence tak terpenuhi berurutan.
    _insert_alert("agt_order", "NEXUS-PROC-001", "suspicious_process", 12, now - 600)
    _insert_alert("agt_order", "NEXUS-AUTH-001", "failed_logins", 12, now - 500)
    xdr.correlate(lookback=3600, rules=SEQ_RULE)
    incs = xdr.list_incidents()["incidents"]
    check("sequence: urutan terbalik → tak ada insiden utk agt_order",
          all(i["entity"] != "agt_order" for i in incs))

    # ------------------------------------------------------------- idempotent
    print("== Upsert idempoten per (rule,entity,tenant) ==")
    before_id = seq[0]["id"]
    out2 = xdr.correlate(lookback=3600, rules=SEQ_RULE)
    incs = xdr.list_incidents()["incidents"]
    seq2 = [i for i in incs if i["rule_id"] == "T-SEQ" and i["entity"] == "agt_seq"]
    check("re-run: tetap 1 insiden (tak duplikasi)", len(seq2) == 1)
    check("re-run: id insiden dipertahankan", seq2 and seq2[0]["id"] == before_id)
    check("re-run: dihitung sebagai 'updated', bukan 'created'",
          out2["created"] == 0 and out2["updated"] >= 1)

    # ------------------------------------------------------------- reopen
    print("== Reopen: insiden resolved + sinyal baru → dibuka kembali ==")
    ack = xdr.ack_incident(before_id, "resolved")
    check("ack resolved ok", ack["ok"])
    openinc = xdr.list_incidents(status="open")["incidents"]
    check("setelah resolve: hilang dari status=open",
          all(i["id"] != before_id for i in openinc))
    # Sinyal baru pada entity yang sama → upsert harus reopen ke 'open'.
    _insert_alert("agt_seq", "NEXUS-PROC-001", "suspicious_process", 12, now - 300)
    xdr.correlate(lookback=3600, rules=SEQ_RULE)
    reopened = xdr.get_incident(before_id)["incident"]
    check("sinyal baru → status dibuka kembali (open)", reopened["status"] == "open")
    check("reopen: id sama dipertahankan", reopened["id"] == before_id)

    # ------------------------------------------------------------- set mode
    print("== Set-mode: tahap urutan bebas (rule_id berbeda) ==")
    # Sisipkan AUTH dulu lalu NET (urutan terbalik dari deklarasi stages); set-mode
    # harus tetap cocok karena urutan bebas.
    _insert_alert("agt_set", "NEXUS-AUTH-001", "failed_logins", 12, now - 400)
    _insert_alert("agt_set", "NEXUS-NET-001", "exposed_service", 10, now - 500)
    xdr.correlate(lookback=3600, rules=SET_RULE)
    incs = xdr.list_incidents()["incidents"]
    setinc = [i for i in incs if i["rule_id"] == "T-SET" and i["entity"] == "agt_set"]
    check("set-mode: insiden terbentuk meski urutan bebas", len(setinc) == 1)
    check("set-mode: gabung 2 alert berbeda (count=2)", setinc and setinc[0]["count"] == 2)

    print("== Set-mode: tahap kurang → tak memicu ==")
    # Hanya NET-001, tanpa AUTH → tahap kedua tak terpenuhi.
    _insert_alert("agt_half", "NEXUS-NET-001", "exposed_service", 10, now - 450)
    xdr.correlate(lookback=3600, rules=SET_RULE)
    incs = xdr.list_incidents()["incidents"]
    check("set-mode: satu tahap saja → tak ada insiden",
          all(i["entity"] != "agt_half" for i in incs))

    # ------------------------------------------------------------- PROBE
    print("== PROBE: SATU alert memuaskan BANYAK tahap set-mode (isu laten) ==")
    # Satu alert AUTH-001 saja; kedua tahap PROBE_RULE cocok ke AUTH-001.
    _insert_alert("agt_probe", "NEXUS-AUTH-001", "failed_logins", 12, now - 200)
    probe_out = xdr.correlate(lookback=3600, rules=PROBE_RULE)
    incs = xdr.list_incidents()["incidents"]
    probe = [i for i in incs if i["rule_id"] == "T-PROBE" and i["entity"] == "agt_probe"]
    fabricated = len(probe) == 1
    # DOKUMENTASIKAN perilaku SAAT INI (bukan menegaskan benar/salah produk):
    # _cover set-mode memilih alert yang sama untuk tiap tahap → insiden palsu
    # dari SATU sinyal. Test ini PASS dengan mengonfirmasi perilaku terkini agar
    # regresi (perbaikan di masa depan) terdeteksi.
    check("PROBE: set-mode MEMBENTUK insiden dari 1 alert (perilaku laten saat ini)",
          fabricated)
    if fabricated:
        full = xdr.get_incident(probe[0]["id"])["incident"]
        # Kontributor menduplikasi alert yang sama di kedua tahap.
        dup_count = probe[0]["count"]
        same_alert = len(set(full["alert_ids"])) == 1
        check("PROBE: kontributor mereferensikan alert yang SAMA dua kali "
              "(count={}, distinct_alert_ids=1)".format(dup_count),
              same_alert)
        print("  [INFO] BUG LATEN DIKONFIRMASI: _cover set-mode (correlate.py:145) "
              "mengizinkan satu alert menutupi banyak tahap → insiden palsu.")

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES CORRELATE LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

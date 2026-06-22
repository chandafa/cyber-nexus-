# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/packs.py
"""
Nexus Hub — content pack (paket konten) untuk berbagi/distribusi deteksi.

Sebuah "pack" membungkus konten SecOps yang bisa dipindah antar-deployment:
IOC threat-intel, playbook SOAR, dan (opsional) ruleset deteksi. Mirip
Splunkbase/Sigma-HQ tapi portabel & offline (cocok dengan mode air-gapped).

Modul ini MURNI DATA + helper (tanpa dependensi manager) agar tak ada impor
melingkar — orkestrasi export/import dilakukan manager (server.py) yang punya
akses get_rules/set_rules + threatintel + soar.

Format bundle: "nexus-pack/1".
"""

PACK_FORMAT = "nexus-pack/1"


# --------------------------------------------------------------------------- katalog seed
# Katalog bawaan: konten kurasi yang langsung bisa di-install. IOC contoh memakai
# rentang dokumentasi/test (RFC5737/contoh) agar aman; operator menambah feed nyata.
CATALOG = [
    {
        "id": "id-fintech-baseline",
        "name": "Indonesia Fintech — Baseline",
        "description": "IOC & playbook awal untuk fintech/bank digital ID: blok C2 "
                       "umum + respons brute-force kredensial.",
        "iocs": [
            {"type": "ip", "value": "198.51.100.23", "threat": "c2", "severity": "high"},
            {"type": "domain", "value": "login-verify-bank.example", "threat": "phishing",
             "severity": "high"},
        ],
        "playbooks": [
            {"id": "PB-PACK-BRUTE", "name": "Respons brute-force login",
             "trigger": {"on": "alert", "rule_id": "NEXUS-AUTH-001"},
             "steps": [{"action": "notify"}, {"action": "block_ip"}],
             "mode": "dry_run", "enabled": True},
        ],
    },
    {
        "id": "web-app-starter",
        "name": "Web App — Starter",
        "description": "Konten awal untuk aplikasi web: IOC scanner umum + playbook "
                       "isolasi saat web-shell terdeteksi.",
        "iocs": [
            {"type": "ip", "value": "203.0.113.77", "threat": "scanner", "severity": "medium"},
        ],
        "playbooks": [
            {"id": "PB-PACK-WEBSHELL", "name": "Isolasi web-shell",
             "trigger": {"on": "alert", "rule_id": "NEXUS-EDR-001"},
             "steps": [{"action": "notify"}, {"action": "enable_firewall"}],
             "mode": "dry_run", "enabled": True},
        ],
    },
    {
        "id": "ransomware-response",
        "name": "Ransomware — Respons Cepat",
        "description": "Playbook respons ransomware (isolasi host + notifikasi P1) "
                       "siap pakai, mode dry-run default.",
        "iocs": [],
        "playbooks": [
            {"id": "PB-PACK-RANSOM", "name": "Isolasi & eskalasi ransomware",
             "trigger": {"on": "incident", "min_severity": "critical"},
             "steps": [{"action": "notify"}, {"action": "enable_firewall"},
                       {"action": "kill_process"}],
             "mode": "dry_run", "enabled": True},
        ],
    },
]

_BY_ID = {p["id"]: p for p in CATALOG}


def get_catalog() -> dict:
    """Daftar pack bawaan (ringkasan)."""
    return {"ok": True, "format": PACK_FORMAT, "packs": [
        {"id": p["id"], "name": p["name"], "description": p["description"],
         "iocs": len(p.get("iocs", [])), "playbooks": len(p.get("playbooks", []))}
        for p in CATALOG]}


def get_pack(pack_id):
    """Ambil isi penuh satu pack katalog (atau None)."""
    return _BY_ID.get(pack_id)


def validate_pack(pack) -> bool:
    """Bundle valid bila dict dengan minimal salah satu dari iocs/playbooks/rules."""
    return isinstance(pack, dict) and any(
        isinstance(pack.get(k), list) for k in ("iocs", "playbooks", "rules"))


def make_bundle(name, rules=None, iocs=None, playbooks=None, now_ts=0) -> dict:
    """Bentuk bundle pack standar dari komponen yang diberikan."""
    return {"format": PACK_FORMAT, "name": name or "nexus-pack",
            "exported_at": int(now_ts) or None,
            "rules": rules or [], "iocs": iocs or [], "playbooks": playbooks or []}

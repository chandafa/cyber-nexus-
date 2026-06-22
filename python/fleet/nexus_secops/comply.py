# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/comply.py
"""
Nexus Comply — pemetaan kontrol compliance ke kapabilitas Nexus + skor cakupan.

Memetakan kewajiban regulasi ke fitur Nexus yang membuktikannya, lalu menilai
cakupan berdasarkan KEADAAN NYATA deployment (sinyal dari manager) — bukan tebakan
dan tanpa AI. Tujuan: bukti audit-ready untuk auditor & DPO.

Framework awal:
  • UU PDP — UU No. 27 Tahun 2022 (Pelindungan Data Pribadi, Indonesia)
  • ISO/IEC 27001:2022 — Annex A (subset teknologi yang bisa dibuktikan Nexus)

Modul ini MURNI DATA + logika (tanpa dependensi manager). Manager (server.py)
mengumpulkan `signals` (keadaan nyata) lalu memanggil report()/assess().

Status kontrol:
  covered — sinyal pendukung aktif/terpenuhi.
  gap     — fitur ada tapi belum aktif/terkonfigurasi → rekomendasi diberikan.
  manual  — kontrol organisasi/proses (di luar cakupan teknis Nexus).
"""

# Tiap kontrol: id, ref (pasal/klausa), title, theme, nexus (fitur pembukti),
# signal (kunci di dict signals; None = manual), why (rekomendasi bila gap).
_UU_PDP = [
    {"id": "pdp-35-keamanan", "ref": "Pasal 35", "title": "Keamanan data pribadi (pencegahan akses tidak sah)",
     "nexus": ["SIEM", "XDR", "deteksi rule"], "signal": "monitoring",
     "why": "Aktifkan ingest event + ruleset agar pemantauan keamanan berjalan."},
    {"id": "pdp-35-enkripsi", "ref": "Pasal 35", "title": "Perlindungan teknis / enkripsi data",
     "nexus": ["enkripsi at-rest (cryptobox)"], "signal": "encryption",
     "why": "Set NEXUS_MASTER_KEY agar rahasia tersimpan terenkripsi at-rest."},
    {"id": "pdp-36-akses", "ref": "Pasal 36", "title": "Kontrol & pembatasan akses",
     "nexus": ["RBAC admin/viewer", "admin token"], "signal": "rbac",
     "why": "Buat token RBAC (add-user) & lindungi admin token."},
    {"id": "pdp-audit", "ref": "Pasal 35", "title": "Pencatatan aktivitas (audit log)",
     "nexus": ["audit log"], "signal": "audit_present",
     "why": "Audit log akan terisi otomatis saat operasi admin berjalan."},
    {"id": "pdp-integritas-log", "ref": "Pasal 35", "title": "Integritas log (anti-rusak)",
     "nexus": ["audit hash-chain"], "signal": "audit_ok",
     "why": "Verifikasi rantai audit (audit-verify) untuk bukti tak-termodifikasi."},
    {"id": "pdp-46-notifikasi", "ref": "Pasal 46", "title": "Notifikasi pelanggaran data (3x24 jam)",
     "nexus": ["hub notifikasi", "Canary"], "signal": "breach_alerting",
     "why": "Konfigurasi channel notifikasi (notify-add) untuk peringatan cepat."},
    {"id": "pdp-insiden", "ref": "Pasal 46", "title": "Deteksi & penanganan insiden",
     "nexus": ["SOAR", "XDR"], "signal": "incident_response",
     "why": "Aktifkan playbook SOAR untuk respons terotomasi."},
    {"id": "pdp-pemantauan-akun", "ref": "Pasal 35", "title": "Pemantauan perilaku akun/anomali",
     "nexus": ["UEBA"], "signal": "ueba",
     "why": "Latih baseline UEBA (ueba-train) untuk deteksi anomali."},
    {"id": "pdp-deteksi-breach", "ref": "Pasal 46", "title": "Deteksi dini kompromi (deception)",
     "nexus": ["Nexus Canary"], "signal": "deception",
     "why": "Sebar honeytoken (canary-mint) untuk sinyal breach fidelitas tinggi."},
    {"id": "pdp-53-dpo", "ref": "Pasal 53", "title": "Penunjukan Pejabat Pelindungan Data (DPO)",
     "nexus": [], "signal": None, "why": ""},
    {"id": "pdp-rekaman", "ref": "Pasal 31", "title": "Rekaman kegiatan pemrosesan (RoPA)",
     "nexus": [], "signal": None, "why": ""},
]

_ISO_27001 = [
    {"id": "iso-a5.7", "ref": "A.5.7", "title": "Threat intelligence", "theme": "Organizational",
     "nexus": ["Threat Intel"], "signal": "threat_intel",
     "why": "Impor feed IOC (ti-import) atau bundle offline."},
    {"id": "iso-a5.24", "ref": "A.5.24-26", "title": "Manajemen insiden keamanan informasi", "theme": "Organizational",
     "nexus": ["SOAR", "XDR"], "signal": "incident_response",
     "why": "Definisikan playbook SOAR & alur insiden XDR."},
    {"id": "iso-a8.15", "ref": "A.8.15", "title": "Logging", "theme": "Technological",
     "nexus": ["audit log"], "signal": "audit_present",
     "why": "Audit log aktif otomatis; pastikan retensi."},
    {"id": "iso-a8.16", "ref": "A.8.16", "title": "Monitoring activities", "theme": "Technological",
     "nexus": ["SIEM", "XDR", "NDR"], "signal": "monitoring",
     "why": "Aktifkan ingest + ruleset untuk pemantauan."},
    {"id": "iso-a8.12", "ref": "A.8.12", "title": "Data leakage prevention", "theme": "Technological",
     "nexus": ["Canary", "EDR"], "signal": "deception",
     "why": "Sebar honeytoken & aktifkan EDR untuk indikasi kebocoran."},
    {"id": "iso-a8.7", "ref": "A.8.7", "title": "Protection against malware", "theme": "Technological",
     "nexus": ["EDR", "deteksi rule"], "signal": "malware",
     "why": "Aktifkan ruleset deteksi & snapshot proses EDR."},
    {"id": "iso-a8.8", "ref": "A.8.8", "title": "Management of technical vulnerabilities", "theme": "Technological",
     "nexus": ["SBOM", "vuln DB"], "signal": "vuln_mgmt",
     "why": "Impor vuln DB (vulndb-import) & jalankan SBOM scan."},
    {"id": "iso-a8.5", "ref": "A.8.5", "title": "Secure authentication", "theme": "Technological",
     "nexus": ["HMAC agent", "admin token"], "signal": "auth_security",
     "why": "Jalankan via TLS & lindungi token."},
    {"id": "iso-a8.2", "ref": "A.8.2", "title": "Privileged access rights", "theme": "Technological",
     "nexus": ["RBAC"], "signal": "rbac",
     "why": "Pisahkan peran admin/viewer (add-user)."},
    {"id": "iso-a8.20", "ref": "A.8.20-22", "title": "Networks security / segregation", "theme": "Technological",
     "nexus": ["NDR", "WAF"], "signal": "network_security",
     "why": "Aktifkan NDR (network snapshot) untuk visibilitas jaringan."},
    {"id": "iso-a8.13", "ref": "A.8.13", "title": "Information backup", "theme": "Technological",
     "nexus": [], "signal": None, "why": ""},
    {"id": "iso-a5.30", "ref": "A.5.30", "title": "ICT readiness for business continuity", "theme": "Organizational",
     "nexus": [], "signal": None, "why": ""},
]

FRAMEWORKS = {
    "uu-pdp": {"name": "UU PDP — UU No. 27 Tahun 2022", "controls": _UU_PDP},
    "iso27001": {"name": "ISO/IEC 27001:2022 (Annex A, subset)", "controls": _ISO_27001},
}


def list_frameworks() -> dict:
    return {"ok": True, "frameworks": [
        {"id": k, "name": v["name"], "controls": len(v["controls"])}
        for k, v in FRAMEWORKS.items()]}


def _status(control, signals) -> str:
    sig = control.get("signal")
    if not sig:
        return "manual"
    return "covered" if signals.get(sig) else "gap"


def assess(framework, signals) -> dict:
    fw = FRAMEWORKS.get(framework)
    if not fw:
        return {"ok": False, "error": f"framework tak dikenal: {framework}"}
    rows = []
    for c in fw["controls"]:
        st = _status(c, signals)
        rows.append({"id": c["id"], "ref": c["ref"], "title": c["title"],
                     "theme": c.get("theme", ""), "nexus": c["nexus"], "status": st,
                     "recommendation": c["why"] if st == "gap" else ""})
    return {"ok": True, "framework": framework, "controls": rows}


def report(framework, signals) -> dict:
    a = assess(framework, signals)
    if not a.get("ok"):
        return a
    rows = a["controls"]
    covered = sum(1 for r in rows if r["status"] == "covered")
    gap = sum(1 for r in rows if r["status"] == "gap")
    manual = sum(1 for r in rows if r["status"] == "manual")
    scorable = covered + gap
    coverage = round(100 * covered / scorable) if scorable else 0
    return {"ok": True, "framework": framework,
            "name": FRAMEWORKS[framework]["name"],
            "summary": {"total": len(rows), "covered": covered, "gap": gap,
                        "manual": manual, "coverage_percent": coverage},
            "gaps": [r for r in rows if r["status"] == "gap"],
            "controls": rows}

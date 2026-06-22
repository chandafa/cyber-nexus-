# Nexus — Brand System & Roadmap

> Status: living document · Versi produk saat ini: **2.2.1** · Disusun 2026-06-22

---

## 1. Positioning (jangan lupa ini saat memutuskan apa pun)

**Nexus = SOC self-hosted, developer-first, dengan AI lokal — satu `pip install`, data tak pernah keluar jaringan.**

Celah pasar yang Nexus isi (dan dipertahankan):

| Pesaing | Kelemahan yang Nexus serang |
|---|---|
| Wazuh / Elastic | Tanpa AI, setup ribet, UX berat |
| CrowdStrike / SentinelOne | Cloud-only, mahal per-seat, data keluar, tak paham regulasi lokal |
| Splunk / QRadar | Mahal, kompleks, bukan untuk tim kecil |

**Tiga pilar diferensiasi yang harus dipertajam, bukan diencerkan:**
1. **Self-hosted & privat** — data tetap di jaringan pelanggan (jualan utama untuk fintech/pemerintah/regulated).
2. **AI lokal tanpa token** — "AI yang hidup di mesinmu", bukan panggilan API ke vendor.
3. **Developer-first & ringan** — satu `pip install`, agent stdlib, jalan di mana saja Python jalan.

Tagline kerja: *"Your SOC, self-hosted, with a local AI — for teams who can't send data to a vendor."*

---

## 2. Sistem Brand (satu keluarga di bawah umbrella **Nexus**)

Modul tumbuh organik (Fleet, SecOps, Shield, WAF). Rapikan jadi satu sistem yang konsisten:

| Nama | Apa | Status |
|---|---|---|
| **Nexus Fleet** | Manajemen endpoint (manager · agent · enroll) | ✅ ada |
| **Nexus SecOps** | Otak SOC 9 pilar (SIEM/XDR/EDR/UEBA/SOAR/TI/NDR/Cloud/AI) | ✅ ada |
| **Nexus Shield** | Proteksi runtime: **eBPF + WAF** disatukan di satu nama | ✅ ada (rebrand) |
| **Nexus Recon** | Toolkit pentest/recon desktop (kini tak bernama) | ✅ ada (beri nama) |
| **Nexus Copilot** | Asisten/analis AI lokal — beri nama yang melekat ("Ask Nexus") | 🔜 perdalam |
| **Nexus Comply** | Pack compliance (lokal + global) + laporan | 🆕 rencana |
| **Nexus Connect** | Connector agentless (cloud/SaaS/syslog) | 🆕 rencana |
| **Nexus Mobile** | Aplikasi companion (alert · ack · approve SOAR) | 🆕 rencana |
| **Nexus Cloud** | Manager terkelola (opsional, self-host tetap default) | 🌥️ horizon |

Prinsip penamaan: `Nexus <Kata-benda-jelas>`, satu kata, hindari akronim baru. Beri **nama panggilan** untuk AI lokal supaya marketable (mis. "Ask Nexus" / "Nexus Copilot").

---

## 3. Roadmap berfase

### Fase A — Diferensiasi pasar (PRIORITAS, dipilih user)
- **Nexus Comply** — pemetaan deteksi + template laporan ke:
  - 🇮🇩 **UU PDP, POJK/OJK (fintech), pedoman BSSN** ← pembeda lokal terkuat, vendor global tak garap.
  - 🌐 ISO 27001, SOC 2, PCI-DSS, NIST CSF.
  - Output: laporan compliance terjadwal + "control coverage" per framework.
- **Hub Notifikasi** — keluar dari webhook-only ke **WhatsApp · Telegram · Email (SMTP) · Slack**, dengan routing per-severity/per-rule. (WA/Telegram = sangat relevan untuk SMB Indonesia.)

### Fase B — Surface ekosistem baru (dipilih user)
- **Nexus Mobile** — companion: lihat & ack alert, **approve aksi SOAR**, push notification. "SOC di saku." (Stack saran: React Native/Expo → reuse komponen + panggil REST manager :8765.)

### Fase C — Jadi SIEM penuh
- **Nexus Connect** — connector agentless: AWS CloudTrail/GuardDuty, GCP, Azure, Google Workspace, M365, syslog perangkat jaringan. Perluas cakupan data di luar endpoint.
- Retensi/arsip log + export (syslog/CEF/S3), agent auto-update, multi-tenancy nyata (buka model MSP), RBAC granular.

### Horizon — "Wow / modern / canggih" (diferensiasi jangka menengah)
1. **Nexus Copilot** — analis SOC AI lokal: investigasi bahasa natural, auto-triage, respons *agentic* sekali-klik (tanpa token). **Fitur unggulan masa depan.**
2. **Continuous Detection Validation + MITRE ATT&CK heatmap** — jalankan Atomic Red Team terjadwal, ukur deteksi menyala, peta cakupan ATT&CK hidup (kategori "BAS").
3. **Attack-path / blast-radius graph** — pakai Cytoscape: simulasi pivot attacker lintas fleet.
4. **ChatOps** — kendalikan Nexus dari WA/Telegram/Slack ("@nexus blokir 1.2.3.4").
5. **ITDR** — deteksi ancaman identitas (login berisiko, abuse OAuth/token) → ke UEBA.
6. **SBOM + supply-chain risk** — scan dependensi repo/image, ikat CVE ke aset hidup.
7. **Nexus Shield eBPF nyata** — proteksi runtime tingkat-kernel (jadikan simulasi → sungguhan; butuh bytecode `.bpf.c`).

---

## 4. Utang teknis menuju "kelas-enterprise" (dari audit 2026-06-22)
Pertahankan kualitas saat menambah fitur — item ini menutup jarak ke "sempurna":
retensi/arsip log · export SIEM · agent auto-update · multi-tenancy & RBAC granular · HA/clustering · rate-limiting · OpenAPI docs · backup/restore DB · logging berlevel + rotasi · transfer lisensi + grace expiry · i18n docs/blog/GUI · eBPF datapath nyata · guard XDR set-mode. (Detail di audit & memory.)

---

## 5. Monetisasi tambahan
Tier baru yang muncul dari roadmap: **Nexus Comply** (add-on compliance), **MSP/reseller** (dari multi-tenancy), **Nexus Cloud** (hosted, recurring), **support SLA**.

---

## 6. Rekomendasi urutan eksekusi
1. **Nexus Comply (pack Indonesia) + Hub Notifikasi WA/Telegram** → pembeda lokal, langsung sellable.
2. **Nexus Copilot (perdalam AI lokal)** → fitur "wow" yang on-brand & relatif murah (aset sudah ada).
3. **Nexus Mobile** → surface baru, nilai jual tinggi.
4. **Nexus Connect** → lengkapi sebagai SIEM penuh.

*(Rapikan penamaan modul = quick win yang bisa jalan paralel.)*

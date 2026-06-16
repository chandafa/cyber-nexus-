<div align="center">

# 🛡️ NEXUS — AI Security Agent Desktop

**Antarmuka desktop terpadu untuk berbagai tools keamanan jaringan**
Scanning · Vulnerability Assessment · Analysis · Defense · Reporting — dalam satu aplikasi.

`Tauri 2 (Rust)` · `React 18 + TypeScript` · `Python 3` · Windows / macOS / Linux

</div>

> ⚠️ **Penggunaan Etis** — Nexus dibuat **hanya** untuk pembelajaran ethical hacking, penetration
> testing **dengan izin**, dan security research pribadi. Menggunakan tools ini terhadap sistem yang
> bukan milik Anda atau tanpa izin tertulis adalah **ilegal**. Pengguna bertanggung jawab penuh atas
> seluruh aktivitasnya.

---

## ✨ Fitur

**20+ modul keamanan** dengan **demo fallback** — setiap modul tetap berjalan & menampilkan contoh
output realistis walau tool eksternalnya belum terpasang, jadi seluruh alur bisa dicoba tanpa instalasi apa pun.

| Kategori | Modul |
|----------|-------|
| **Recon & Scan** | Port Scanner (Nmap) · Network Scanner (tshark) · Network Mapper · Asset Inventory |
| **Web & API** | Vulnerability Scanner (Nikto/Gobuster/Nuclei) · SSL/TLS Auditor (sslyze) · API Tester (ffuf) |
| **Offensive** | Password Auditor (Hydra/Hashcat) · Exploit Lookup (searchsploit) · Attack Simulation (+ Scope Guard) · Wireless Auditor (aircrack-ng) |
| **Cloud & Container** | Container Scanner (Trivy) · Cloud Config Checker (Prowler) |
| **Analisis** | Log Analyzer (anomaly detection) · Scan Diff / Compare |
| **Defense & Laporan** | Defense Monitor · Defense Suite (firewall auto-rule, patch advisory, mitigasi) · Report Generator (PDF/HTML) |
| **Fleet / SOC** | **Nexus Manager** (server pusat) · **Nexus Agent** (daemon endpoint) · **nexus-cli** (admin) — arsitektur agent↔manager ala-Wazuh |
| **Sistem** | History · Scheduler (cron) · Wordlist Manager (SecLists) · Settings |

**Lainnya:** Security Score Dashboard · Terminal live (xterm.js) · 8 tema (Dark/Light/Blue/Red/Black/Green/Purple/Nord) ·
sidebar collapse · export CSV ke folder pilihan · **installer tool 1-klik tanpa-admin**.

---

## 🧱 Arsitektur

```
┌───────────────────────────────────────────────────────────┐
│  UI Layer       React 18 + TypeScript + xterm.js          │  src/
│  Bridge Layer   Tauri IPC (invoke + event system)         │  src/lib/tauri.ts
│  Executor       Rust (Tauri) → Python subprocess runner   │  src-tauri/ + python/runner.py
│  Tools Layer    Nmap, tshark, Nikto, Nuclei, sslyze, ...   │  (eksternal, opsional)
└───────────────────────────────────────────────────────────┘
```
Database: **SQLite** (rusqlite) · Report: **Python Jinja2 + WeasyPrint** (fallback HTML).

### Mode Fleet / SOC (agent ↔ manager, ala-Wazuh)

Selain mode desktop "klik-scan", Nexus punya arsitektur **fleet terdistribusi** untuk memantau banyak
endpoint dari satu titik — komponen klasik Wazuh (agent + manager + dashboard + CLI):

```
   Endpoint A ─┐                                  ┌─ Dashboard (Fleet Manager page)
   nexus-agent │   heartbeat + event (HTTP/HMAC)  │
   Endpoint B ─┼────────────────────────────────► Nexus Manager ──► SQLite (agents, events, policy)
   nexus-agent │   ◄── policy & perintah ──────── (server :8765)    ▲
   Endpoint C ─┘                                                    └─ nexus-cli (admin via token)
```

**1 platform, 4 komponen** (monorepo) — kode kanonik stdlib-only di `python/fleet/`, dipakai ulang
oleh desktop app (adapter tipis di `python/modules/fleet_*.py`) **dan** bisa jalan mandiri:

| Komponen | Paket | Peran |
|----------|-------|-------|
| **nexus-manager** | `python/fleet/nexus_manager` | API server pusat: enrollment, heartbeat, ingest+normalisasi event, **rule engine + alert engine**, policy, audit, retention, report. |
| **nexus-agent** | `python/fleet/nexus_agent` | Daemon endpoint ringan: heartbeat, **FIM**, SCA, software inventory, port/user/disk/firewall, **web-app audit (Laravel/.env)**, event queue store-and-forward. |
| **nexus-cli** | `python/fleet/nexus_cli` | Console interaktif (menu Network & Website security) **+** admin: `agents/events/alerts/ack/report/policy/command`. |
| **nexus-dashboard** | `python/fleet/nexus_dashboard` | UI web monitoring (alerts, agents, events, risk score) — disajikan manager di `/`. |
| *shared* | `python/fleet/nexus_common` | Protokol HMAC + **skema baku event/alert/report** (OCSF-leaning, `origin: real\|demo`). |

**Engine produk (deepening):**
- **Rule engine** (`nexus_manager/rules.py`) — rule native ber-level 0–15 + **MITRE ATT&CK** + rekomendasi + response; pushable. Contoh: `NEXUS-FIM-001` (.env diubah → critical), `NEXUS-WEB-001` (Laravel APP_DEBUG), `NEXUS-AUTH-001` (brute-force).
- **Alert engine** — event cocok rule → alert (severity/level), **dedup** anti-fatigue, ack/resolve, retensi.
- **Real findings only** — setiap event ber-`origin`; manager **menolak `demo`** secara default (`accept_demo=0`).
- **Skema konsisten** — `event_id/category/event_type/severity/host/target/evidence/rule.mitre`; report `nexus.report/v1`.

**Keamanan transport:** pesan agent ditandatangani **HMAC-SHA256** per-agent; enrollment butuh **enrollment key**;
API admin butuh **admin token**; CORS untuk dashboard. HTTP di LAN — **tidak ada data ke internet**.

**Jalankan mandiri** (Python 3.8+, tanpa desktop app — `cd python/fleet`, atau `pip install .` / `npm i -g`):
```bash
python -m nexus_manager run --host 0.0.0.0 --port 8765    # server pusat + dashboard di :8765/
python -m nexus_agent  enroll --host <mgr> --port 8765 --key <ENROLL_KEY> --labels prod,web
python -m nexus_agent  start                              # daemon: FIM/SCA/inventory/webaudit
python -m nexus_cli                                       # console interaktif (network & web)
python -m nexus_cli --token <ADMIN_TOKEN> alerts          # admin: lihat alert
python -m nexus_cli --token <ADMIN_TOKEN> report          # report konsisten + MITRE
```
Endpoint API: `POST /api/v1/agents/enroll · /agents/heartbeat · /events/batch`,
`GET /api/v1/agents · /alerts · /events · /policies · /rules · /audit · /report`, `POST /alerts/ack`.

Uji headless (21 seksi, semua lulus): `python python/tests/test_fleet.py`.

> **Status & roadmap.** Yang ada sekarang = MVP fungsional & teruji dari fondasi ala-Wazuh
> (FIM, SCA, inventory, rule/alert engine, MITRE, real-only, schema, agent↔manager↔cli↔dashboard).
> **Belum** (roadmap menuju "standar industri penuh"): agent Go/Rust, OpenSearch/ClickHouse + Postgres,
> mTLS/gRPC, import **Sigma**, **YARA**, Active Response eksekusi, OCSF penuh, AI remediation, RBAC multi-tenant.
> Pembeda yang dikejar: **developer-first / app-aware** (audit Laravel/React/Next, parser log aplikasi, posture score).

---

## 📋 Requirements

### Wajib (untuk build & menjalankan aplikasi)

| Komponen | Versi | Catatan |
|----------|-------|---------|
| **Node.js** | 18+ | frontend & Tauri CLI |
| **Rust** | stable (rustup) | shell Tauri |
| **Python** | 3.10+ | engine eksekusi tools |
| **Git** | 2.30+ | clone & wordlist/installer |

**Per OS (toolchain native Tauri):**
- **Windows** — [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  (workload *"Desktop development with C++"*) + **WebView2 Runtime** (biasanya sudah ada di Win 10/11).
- **macOS** — `xcode-select --install`.
- **Linux** — `webkit2gtk`, `libgtk-3-dev`, `librsvg2-dev`, `build-essential`, `libssl-dev`
  (Debian/Ubuntu: `sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libgtk-3-dev librsvg2-dev`).

### Opsional (security tools — bisa dipasang dari dalam aplikasi)

Nmap, tshark/Wireshark, Nikto, Gobuster, Nuclei, ffuf, sslyze, searchsploit, Trivy, Hydra, Hashcat,
Lynis, WhatWeb, aircrack-ng, Suricata, Prowler, dll. **Tidak wajib** — modul jalan demo bila tool absen.
Lihat [Instalasi Tools Keamanan](#-instalasi-tools-keamanan).

---

## 🚀 Instalasi

```bash
# 1. Clone
git clone <repo-url> nexus
cd nexus

# 2. Install dependency frontend
npm install

# 3. (Opsional, untuk PDF report / scapy / dll.) dependency Python
pip install -r requirements.txt
```

### Pasang Rust toolchain (jika belum)

```bash
# Semua OS — install rustup:  https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # macOS/Linux
# Windows: unduh & jalankan rustup-init.exe, lalu pasang VS C++ Build Tools (lihat Requirements)
```

---

## ▶️ Menjalankan

```bash
# Mode pengembangan (hot-reload) — butuh Rust toolchain terpasang
npm run tauri:dev

# Build installer produksi (.exe / .msi / .dmg / .AppImage)
npm run tauri:build
```

> **Build pertama** mengompilasi Rust + SQLite (rusqlite) dari source → 5–15 menit. Build berikutnya cepat (incremental).

Saat pertama dibuka, **Setup Wizard** muncul: disclaimer etis → dependency check → instalasi tool → permission check → selesai.

**Hanya frontend (tanpa Rust, untuk lihat UI saja):**
```bash
npm run dev    # http://localhost:1420 — fungsi scan butuh backend Tauri
```

---

## 🔧 Instalasi Tools Keamanan

Buka **Settings → Status Tools** atau **Setup Wizard**, klik **Install** / **Install Semua**.
Nexus memakai metode **tanpa-admin** lebih dulu, baru package manager:

| OS | Metode |
|----|--------|
| **Semua** | Binary resmi GitHub (Nuclei, ffuf, Gobuster, Trivy, httpx, naabu) → `~/.nexus/tools/bin` · pip (sslyze, prowler di venv terisolasi) · git clone (Nikto, searchsploit). `Lynis` hanya Unix-based / Linux-WSL. |
| **Windows** | **Scoop** (tanpa admin, diutamakan) → **Chocolatey** (UAC). Tool Linux-only / Unix-only (hydra, arp-scan, hping3, lynis) ditandai opsional — pakai **WSL** bila diperlukan. |
| **macOS** | **Homebrew** |
| **Linux** | **apt / dnf / pacman / zypper** (via `pkexec`/`sudo`) |

Instalasi berjalan **streaming & non-blocking** (UI tidak freeze), dengan progres real-time.
Tool yang baru dipasang langsung terdeteksi tanpa restart aplikasi (PATH dibaca ulang dari registry pada Windows).

---

## 📁 Struktur Proyek

```
nexus/
├── src-tauri/          # Backend Rust (Tauri 2)
│   ├── src/
│   │   ├── main.rs · lib.rs
│   │   ├── commands/   # executor, scanner, dependency, report
│   │   ├── db/         # skema + akses SQLite
│   │   └── models/
│   ├── capabilities/ · icons/ · Cargo.toml · tauri.conf.json
├── src/                # Frontend React + TypeScript
│   ├── app/            # App, router, store (Zustand)
│   ├── pages/          # 1 halaman per modul + Dashboard/Setup/Settings/History
│   ├── components/     # Terminal, ScanConsole, ResultTable, Select, Toast, ...
│   └── lib/            # tauri.ts (IPC), output.ts, icons, parser, theme
├── python/             # Engine Python
│   ├── runner.py       # dispatcher CLI dipanggil Rust
│   ├── core/           # dependency_checker, installer, official_installer, sanitizer, scope_guard
│   ├── modules/        # ±20 modul security
│   ├── parsers/ · report/  (Jinja2 templates)
├── wordlists/          # sample wordlist
├── package.json · requirements.txt · vite/ts/tailwind config
```

---

## 🛡️ Keamanan Aplikasi

- **Offline-first** — tidak mengirim data scan ke server eksternal.
- Semua input target/URL/port/file **di-sanitasi** sebelum masuk subprocess (anti command injection).
- Subprocess dijalankan **tanpa** `shell=True`, argumen ter-list.
- **Scope Guard** — modul Attack Simulation hanya jalan untuk target yang sudah Anda tandai *authorized*.
- Disclaimer etis wajib disetujui saat pertama kali.

---

## 🩹 Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `cargo`/`rustc` tidak ditemukan | Pasang Rust via https://rustup.rs lalu buka terminal baru |
| Build gagal di Windows (`link.exe`/`cl.exe`) | Pasang **VS C++ Build Tools** (workload Desktop C++) |
| `npm run tauri:dev` error WebView | Pasang **WebView2 Runtime** (Microsoft) |
| Tool terdeteksi "missing" padahal baru di-install | Klik **Periksa** di Settings (PATH dibaca ulang otomatis) |
| Tool jalan tapi hasil "demo" | Tool gagal runtime (butuh admin/driver/Docker) — fallback demo otomatis; lihat pesan di terminal |
| Tool Linux/Unix-only di Windows (hydra/arp-scan/hping3/lynis) | Opsional — pasang via **WSL** (`wsl sudo apt install ...`) |

---

## 📄 Lisensi & Disclaimer

For Personal / Ethical Hacking Study Only. Gunakan secara bertanggung jawab dan sesuai hukum yang berlaku.

<div align="center">
<sub>Dibangun dengan Tauri · React · Python — Nexus v1.0</sub>
</div>

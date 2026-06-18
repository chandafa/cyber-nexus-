# Nexus Security Platform — Product Brief (materi jualan)

> Platform keamanan **agent–manager** untuk mengamankan **jaringan, server, dan website**
> perusahaan Anda — **data tetap di infrastruktur Anda** (offline-first), bukan di cloud orang lain.

## Untuk siapa
Startup, UMKM digital, agensi, sekolah/kampus, dan tim aplikasi (Laravel/React/Next) yang:
- punya server & website yang harus aman, tapi **belum punya tim SOC**;
- tidak mau data keamanannya dikirim ke cloud pihak ketiga;
- butuh sesuatu yang **lebih sederhana & murah** dari SIEM enterprise.

## Masalah yang diselesaikan
- Tidak tahu endpoint/server mana yang rentan (firewall mati, port berbahaya terbuka, disk penuh).
- File sensitif berubah diam-diam (`.env`, config) → bocor rahasia.
- Salah konfigurasi aplikasi web: `APP_DEBUG=true`, `APP_KEY` kosong, password DB lemah, secret `NEXT_PUBLIC_*` bocor ke browser.
- Brute-force login, software usang penuh kerentanan.

## Yang Nexus lakukan
| Kategori | Kemampuan |
|---|---|
| **Jaringan** | Pemindaian port/eksposur, host discovery, DNS recon, saran aturan firewall |
| **Server/Endpoint** | File Integrity Monitoring (FIM), Security Configuration Assessment (SCA), inventori software, deteksi login gagal, monitoring disk |
| **Website (PEMBEDA)** | Audit Laravel/Next.js: `APP_DEBUG`, `APP_KEY`, password DB lemah, secret `NEXT_PUBLIC_*`, `.git` terekspos, source map bocor |
| **Deteksi & respon** | Rule engine + **alert berlevel & MITRE ATT&CK**, rekomendasi perbaikan, Active Response, **security posture score** (skor mudah dipahami) |
| **Manajemen** | Banyak agent dari satu dashboard, policy terpusat, report konsisten, audit log |

## Kenapa Nexus (vs SIEM lain / Wazuh)
- **Developer-first**: paham aplikasi web modern (Laravel/React/Next) — bukan cuma log mentah.
- **Offline-first**: data keamanan tidak keluar dari jaringan Anda.
- **Ringan & mudah**: agent stdlib Python, pasang lewat `pip`/`npm`, tanpa cluster berat.
- **Skor postur** yang bisa dimengerti pemilik bisnis (Website 82/100, Server 74/100).

## Paket & harga (CONTOH — sesuaikan sendiri)
| | **FREE** | **PRO** | **ENTERPRISE** |
|---|---|---|---|
| Jumlah agent | 2 | s/d 50 (seat) | unlimited |
| Rule keamanan | dasar | semua (FIM/web-audit/SCA/vuln) | semua |
| Sigma import & Active Response | — | ✅ | ✅ |
| Web/app audit, report, posture score | terbatas | ✅ | ✅ |
| Dukungan | komunitas | email | prioritas + onboarding |
| **Harga (ide awal)** | Rp 0 | **Rp ___ /bln** atau /thn | **hubungi kami** |

> Saran harga awal: PRO Rp 300–750rb/bln (atau diskon tahunan), Enterprise via penawaran.
> Mulai dari harga rendah untuk 1–3 pelanggan pilot, naikkan setelah ada testimoni.

## Cara beli & pasang (untuk pelanggan)
1. Pelanggan bayar → Anda terbitkan file lisensi.
2. Pasang: `pip install nexus-fleet` (atau `npm i -g nexus-fleet`).
3. Jalankan manager dengan lisensi: `NEXUS_LICENSE=/path/lisensi.license nexus-manager run`.
4. Pasang agent di tiap server/endpoint → pantau dari dashboard.

## Ajakan
Coba **gratis** (FREE, 2 agent) hari ini. Upgrade ke **PRO** saat butuh lebih banyak agent
& deteksi aplikasi web. **Demo/pilot? Hubungi: [email/WA Anda].**

---
*Nexus — for ethical & authorized security use. Data Anda tetap milik Anda.*

<div align="center">

# Nexus License Server — Cloudflare Worker

**Aktivasi kode online sekali-pakai, terkunci-device — GRATIS, tanpa kartu kredit.**

Cloudflare Workers · D1 (SQLite) · WebCrypto Ed25519

</div>

---

Alternatif gratis dari Firebase Blaze. Kode generik (seperti voucher) yang bisa
ditukar **sekali** oleh perangkat pertama yang menukarnya, lalu terkunci ke device
itu selama 30 hari. Token ditandatangani Ed25519 (kompatibel dengan verifier app).

> Sudah **teruji end-to-end secara lokal** (Miniflare + D1): generate → redeem →
> verifikasi token Python → tolak device lain → validate. ✔️

## Endpoint
| Method · Path | Guna |
| --- | --- |
| `POST /admin/generate` `{count,tier,days}` (header `x-admin-token`) | Buat kode di database |
| `POST /admin/revoke` `{code}` (header `x-admin-token`) | Cabut kode |
| `POST /redeem_license` `{code,deviceId}` | Tukar (sekali pakai, kunci device) → token |
| `POST /validate_license` `{code,deviceId}` | Status terkini (revoke/expired) |

## Deploy (sekali, ±5 menit, tanpa kartu)

> Butuh **wrangler v4** (terbaru 2026). `npm install` di bawah sudah memasangnya.

1. **Akun Cloudflare gratis** — daftar di dash.cloudflare.com (tanpa kartu).
2. **Install (wrangler v4) & login:**
   ```bash
   cd cloudflare
   npm install
   npx wrangler login
   ```
3. **Buat database D1:**
   ```bash
   npx wrangler d1 create nexus-license-db
   ```
4. **PENTING — tempel `database_id`** dari output langkah 3 ke `wrangler.toml`
   (ganti nilai `database_id = "..."`). Tanpa ini, langkah 5 error `Invalid uuid`.
5. **Buat tabel di D1:**
   ```bash
   npm run schema:remote
   ```
6. **Set secret:**
   ```bash
   npx wrangler secret put VENDOR_SEED   # tempel isi ~/.nexus/vendor_private.key (hex)
   npx wrangler secret put ADMIN_TOKEN   # token rahasia bebas untuk /admin/*
   ```
7. **Deploy:**
   ```bash
   npm run deploy
   # -> https://nexus-license.<subdomain>.workers.dev
   ```
8. **Arahkan app** — isi `python/core/license_config.py`:
   ```python
   LICENSE_API_BASE = "https://nexus-license.<subdomain>.workers.dev"
   ```
   Build/jalankan app → Settings → Lisensi otomatis memakai alur **kode online**.

## Generate kode (jual)
```bash
python gen.py gen --count 10 --tier pro --days 30 \
  --url https://nexus-license.<subdomain>.workers.dev \
  --admin <ADMIN_TOKEN>
# (atau set env NEXUS_LICENSE_API & NEXUS_ADMIN_TOKEN)
```
Kode langsung tersimpan di database, siap dijual. Pelanggan aktivasi di app:
**Settings → Lisensi → Kode aktivasi**.

## Dev lokal (uji tanpa deploy)
```bash
cp .dev.vars.example .dev.vars   # isi VENDOR_SEED (hex) + ADMIN_TOKEN
npm run schema:local
npm run dev                      # http://127.0.0.1:8787
```

## Free tier Cloudflare
Workers 100.000 request/hari + D1 5 GB — jauh lebih dari cukup untuk lisensi,
**tanpa kartu kredit**.

---

<div align="center"><sub>Bagian dari platform <b>Nexus</b> · proprietary</sub></div>

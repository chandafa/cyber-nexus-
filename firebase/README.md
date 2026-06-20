<div align="center">

# Nexus License Server (Firebase) — DEPRECATED

**Aktivasi lisensi sekali-pakai, terkunci-device, bulanan — di atas Firebase.**

Cloud Functions (Python) · Cloud Firestore · Ed25519

</div>

> ⚠️ **Tidak dipakai lagi.** Server lisensi produksi kini berjalan di **Cloudflare Workers + D1**
> (gratis, tanpa kartu) — lihat [`../cloudflare/`](../cloudflare). Folder ini disimpan sebagai
> referensi desain awal saja: Firebase Cloud Functions memerlukan paket Blaze (billing), sehingga
> ditinggalkan.

---

## Cara kerja singkat

```
Vendor  ── nexus_codes.py gen ─►  Firestore: licenses/{KODE} = {status:"unused"}
Customer ─ masukkan KODE di app ─► Cloud Function redeem_license (TRANSAKSI ATOMIK)
                                    → kunci ke deviceId, set expiresAt +30 hari
                                    → balas entitlement Ed25519 (sekali pakai)
App ── verifikasi lokal tiap start: tanda tangan + device cocok + belum expired
App ── validate_license berkala: deteksi revoke/expired
```

**Keamanan:** signing-key Ed25519 hanya ada sebagai **secret** Cloud Function (tak pernah di app/generator). Firestore rules menolak SEMUA akses klien — hanya function (Admin) yang menyentuh data. Kode 100-bit (CSPRNG), redemption atomik (anti double-spend), entitlement device-bound + anti putar-jam.

---

## Prasyarat (sekali saja)

1. **Node.js 18+** dan Firebase CLI: `npm i -g firebase-tools`
2. **Python 3.11** (runtime Cloud Functions)
3. Project Firebase pada **paket Blaze** (Cloud Functions butuh Blaze; ada free-tier besar)
4. Login: `firebase login`

## 1) Hubungkan project

Edit `.firebaserc` → ganti `GANTI-DENGAN-PROJECT-ID-ANDA` dengan Project ID Firebase Anda.

## 2) Set signing key (VENDOR_SEED)

Secret ini HARUS = seed (hex) yang pasangan public-key-nya ter-bundle di app
(`python/fleet/nexus_common/vendor_public.key`). Anda sudah punya seed di
`~/.nexus/vendor_private.key`.

```bash
# Windows PowerShell
firebase functions:secrets:set VENDOR_SEED
# tempel isi file ~/.nexus/vendor_private.key saat diminta, lalu Enter
```

> Verifikasi pasangan cocok (opsional):
> ```bash
> python -c "import sys; sys.path.insert(0,'../python/fleet'); from nexus_common import _ed25519 as e; \
> seed=open('%USERPROFILE%/.nexus/vendor_private.key').read().strip(); \
> print(e.publickey(bytes.fromhex(seed)).hex())"
> # bandingkan dengan isi python/fleet/nexus_common/vendor_public.key — harus sama
> ```

## 3) Deploy

```bash
cd firebase
firebase deploy --only firestore:rules,functions
```

Catat URL yang muncul, mis.:
```
https://asia-southeast2-NAMAPROJECT.cloudfunctions.net/redeem_license
https://asia-southeast2-NAMAPROJECT.cloudfunctions.net/validate_license
```

## 4) Arahkan app ke server

Isi `python/core/license_config.py`:
```python
LICENSE_API_BASE = "https://asia-southeast2-NAMAPROJECT.cloudfunctions.net"
```
(atau set env `NEXUS_LICENSE_API` untuk dev). Lalu build/jalankan app seperti biasa.

## 5) Generate kode (alat vendor)

Unduh service-account: Firebase Console → Project Settings → Service accounts →
**Generate new private key** → simpan sebagai `firebase/admin/serviceAccount.json`
(JANGAN di-commit; sudah masuk `.gitignore`).

```bash
cd firebase/admin
pip install -r requirements.txt

python nexus_codes.py gen --count 10 --tier pro --days 30   # buat 10 kode Pro 30 hari
python nexus_codes.py list --status unused                   # lihat kode tersedia
python nexus_codes.py info   NEXUS-XXXXX-XXXXX-XXXXX-XXXXX    # detail 1 kode
python nexus_codes.py revoke NEXUS-XXXXX-XXXXX-XXXXX-XXXXX    # cabut (app turun ke Free)
```

Kode yang dibuat langsung tersimpan di Firestore. Jual kode ke pelanggan; mereka
aktifkan di app: **Settings → Lisensi → Kode aktivasi**.

---

## Struktur

```
firebase/
├── firebase.json            konfigurasi deploy (functions + firestore)
├── .firebaserc              project id
├── firestore.rules          tolak semua akses klien (hanya function)
├── firestore.indexes.json   index status+createdAt
├── functions/               Cloud Functions (Python)
│   ├── main.py              redeem_license · validate_license
│   ├── entitlement.py       penerbit entitlement Ed25519 (kanonik = app)
│   ├── _ed25519.py          impl Ed25519 (sama dgn app)
│   └── requirements.txt
└── admin/                   alat vendor (generate/list/revoke kode)
    ├── nexus_codes.py
    └── requirements.txt
```

## Catatan model bisnis

- 1 kode = **sekali pakai**, terkunci ke 1 device, berlaku 30 hari → otomatis turun
  ke Free saat kedaluwarsa. Pelanggan beli kode baru untuk bulan berikutnya.
- Ganti hardware → Device ID berubah → butuh kode baru (atau hapus binding di
  Firestore secara manual).

---

<div align="center"><sub>Bagian dari platform <b>Nexus</b> · lisensi proprietary</sub></div>

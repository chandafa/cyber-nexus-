# Nexus Keygen — alat vendor (offline)

Menerbitkan token lisensi **device-bound** tanpa server / Firebase / Blaze / kartu.
1 token = 1 perangkat, berlaku N hari, otomatis kedaluwarsa. Token tak bisa dipakai
di perangkat lain (terkunci Device ID) dan tak bisa dipalsukan (Ed25519).

## Prasyarat
- Python 3 (Tkinter bawaan).
- Private key vendor ada di `~/.nexus/vendor_private.key` (RAHASIA — jangan dibagikan).

## Pakai

**GUI (tinggal klik):**
```bash
python tools/keygen_app.py
```
Tempel **Device ID** pelanggan → pilih tier + hari → **Generate Token** → **Salin** → kirim ke pelanggan.

**CLI:**
```bash
python tools/keygen_app.py --device <DEVICE_ID> --tier pro --days 30
```

## Alur jualan (pembayaran manual)
1. Pelanggan buka app → **Settings → Lisensi** → salin **Device ID**-nya, kirim ke kamu saat bayar.
2. Kamu jalankan keygen, masukkan Device ID itu → dapat token.
3. Kirim token ke pelanggan → mereka tempel di **Token aktivasi** → **Aktifkan** → Pro 30 hari.
4. Bulan depan: terbitkan token baru.

## Kenapa tanpa server?
Cloud Functions Firebase butuh paket Blaze (kartu). Model device-bound ini mencapai
tujuan yang sama (sekali pakai per perangkat, bulanan) **tanpa biaya & tanpa server**.
Server Firebase opsional (`firebase/`) tetap tersedia bila nanti ingin kode generik
online — aktifkan Blaze lalu deploy.

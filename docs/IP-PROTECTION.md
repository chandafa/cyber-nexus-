# Perlindungan HAKI Nexus — panduan praktis (Indonesia)

> **Penting:** untuk software, yang relevan **bukan PATEN**. Paten untuk invensi teknis
> (mahal, bisa bertahun-tahun, sering ditolak untuk software murni). Yang tepat:

## 1. Hak Cipta — Program Komputer  ✅ (utama, murah, cepat)
Software otomatis dilindungi Hak Cipta sejak diciptakan, tapi **didaftarkan** ke DJKI
memberi **sertifikat** sebagai bukti kepemilikan kuat di pengadilan.

- **Lewat:** https://hakcipta.dgip.go.id (DJKI / e-HakCipta)
- **Jenis ciptaan:** "Program Komputer"
- **Biaya:** ± Rp 200.000–400.000 (UMKM lebih murah; per ciptaan)
- **Waktu:** sering terbit dalam hitungan hari–minggu
- **Yang disiapkan:**
  - Data pencipta & pemegang hak (KTP/NPWP)
  - Judul ciptaan: mis. "Nexus Security Platform (Agent & Manager)"
  - Tanggal & tempat pertama diumumkan
  - **Lampiran kode sumber** (biasanya PDF berisi cuplikan kode + dokumentasi; siapkan
    arsip ZIP dari `python/fleet/` + README + PRODUCT-BRIEF sebagai bukti karya)
  - Surat pernyataan kepemilikan (template tersedia di portal DJKI)
- **Tip:** daftarkan sebagai **satu ciptaan "platform"** atau pisah agent & manager bila mau.

## 2. Merek (Trademark) — nama & logo "Nexus"  ✅ (lindungi brand)
- **Lewat:** https://merek.dgip.go.id
- **Biaya:** ± Rp 500.000–1.800.000 per kelas (UMKM lebih murah)
- **Kelas relevan:** **Kelas 9** (software), **Kelas 42** (jasa TI/SaaS/keamanan)
- ⚠️ **Cek dulu ketersediaan nama** di pangkalan data merek DJKI — "Nexus" **sangat umum**
  & kemungkinan sudah dipakai. Pertimbangkan nama lebih unik (mis. "NexusGuard",
  "CyberNexus", atau nama buatan) agar lolos & aman.

## 3. Lisensi & kontrak (sudah disiapkan)  ✅
- `python/fleet/LICENSE` — **lisensi proprietary** (bukan MIT lagi): FREE terbatas,
  PRO/ENTERPRISE berbayar, dilarang jual ulang / bypass lisensi.
- Untuk pelanggan: buat **EULA / perjanjian langganan** singkat saat menjual (saya bisa bantu draf).

## Catatan jujur
- Versi **1.0.0 & 1.0.1** sempat dipublish sebagai **MIT** — secara hukum, siapa pun yang
  mengunduhnya saat itu memiliki hak MIT atas versi tsb. Mulai versi berikutnya = proprietary.
  Bila ingin "bersih", pertimbangkan **unpublish 1.0.0/1.0.1** (npm bisa <72 jam) lalu rilis
  ulang sebagai proprietary. (Risiko salinan untuk paket sebaru ini sangat kecil.)
- Dokumen ini **bukan nasihat hukum**. Untuk nilai komersial serius, konsultasikan
  **konsultan HAKI**/notaris untuk pendaftaran & perjanjian.

## Langkah Anda
1. Siapkan KTP/NPWP + ZIP kode sumber + judul ciptaan.
2. Daftar **Hak Cipta Program Komputer** di e-HakCipta (paling penting & murah).
3. Cek & daftarkan **Merek** (nama final) kelas 9 & 42.
4. (Opsional) konsultan HAKI untuk mempercepat & EULA pelanggan.

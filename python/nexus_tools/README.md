# nexus-tools — CLI perangkat keamanan desktop

Antarmuka terminal untuk **semua tool** yang ada di GUI desktop Nexus
(recon · web · offensive · cloud · defense · WAF · lisensi). Setiap perintah
memanggil jalur kode yang **sama persis** dengan GUI (`runner.dispatch`), jadi
hasilnya identik — nyata, bukan demo. Gerbang lisensi Pro dan fallback demo
(saat tool eksternal tidak terpasang) berlaku otomatis, sama seperti di GUI.

## Menjalankan

Dari direktori `python/` (memakai runtime Python yang sama dengan aplikasi):

```bash
cd python
python -m nexus_tools --list                       # daftar semua perintah
python -m nexus_tools <perintah> --help            # opsi tiap perintah
```

## Contoh

```bash
# Recon / scan (Free)
python -m nexus_tools port-scan --target 192.168.1.1 --mode full
python -m nexus_tools dns-recon --domain example.com

# Web & API (Pro)
python -m nexus_tools vuln-scan --target https://example.com --tools nikto,nuclei
python -m nexus_tools ssl-audit --target example.com --port 443

# Offensive (Pro)
python -m nexus_tools hash-tool --submode crack --hash <hash> --wordlist rockyou.txt
python -m nexus_tools exploit-lookup --service openssh --version 8.2

# WAF (Pro)
python -m nexus_tools waf --listen-port 8080 --backend 127.0.0.1 --backend-port 8000 --foreground
python -m nexus_tools waf-logs --limit 50

# Lisensi & sistem
python -m nexus_tools license-status
python -m nexus_tools check-deps
python -m nexus_tools privileges
```

## Output & scripting

- **stdout** hanya berisi **JSON hasil akhir** → aman untuk piping.
- **stderr** berisi output live tool (progress, log). Pakai `-q/--quiet` untuk
  menyembunyikannya.

```bash
# ambil hasil sebagai JSON murni
python -m nexus_tools --quiet port-scan --target 10.0.0.1 | jq '.ports'
```

Kode keluar `0` bila sukses, `1` bila tool gagal atau fitur terkunci lisensi.

## Catatan platform

- `wireless-scan`, `ids-monitor` membutuhkan Linux (raw socket / adapter Wi-Fi).
- `network-scan` butuh hak istimewa (sudo/Administrator) untuk capture nyata.
- `listener --submode listen` bersifat interaktif (mengikat port & menunggu);
  untuk pemakaian non-interaktif gunakan `--submode payload`.

## Paritas dengan GUI

Daftar perintah memetakan 1:1 ke command `runner.dispatch` yang dipakai tab-tab
GUI. Argumen dikirim sebagai string — sama seperti GUI (`buildArgs` → Rust →
Python) — sehingga perilaku tool identik di kedua antarmuka.

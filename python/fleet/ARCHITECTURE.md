# Arsitektur Ekosistem Nexus — Hirarki Resmi

> Dokumen ini menetapkan SATU hirarki baku agar ekosistem tidak berantakan/menumpuk.
> Mengikuti standar industri global (Wazuh, Elastic Security, Microsoft Defender XDR,
> Palo Alto Cortex): **satu platform, satu agent, banyak modul kapabilitas.**

## Prinsip (sama seperti vendor besar)

| Vendor | Satu agent? | Struktur |
|--------|-------------|----------|
| Wazuh | ✅ wazuh-agent | manager + indexer + dashboard, fitur = **modul** di dalam manager |
| Elastic Security | ✅ Elastic Agent | Elastic Stack, "Security" = **app** di Kibana |
| Microsoft Defender XDR | ✅ satu sensor | satu portal, Endpoint/Identity/Cloud = **modul** |
| Palo Alto Cortex | ✅ satu agent | platform Cortex, XDR/XSOAR = **modul** |
| **Nexus** | ✅ **satu** Nexus Agent | **Nexus Server**, SIEM/XDR/SOAR = **modul** |

**Aturan emas:** TIDAK membuat agent baru per kapabilitas, TIDAK membuat brand/produk
baru per kapabilitas. Satu agent memberi makan SEMUA modul.

## Hirarki Nexus

```
Nexus  (brand / ekosistem)
│
├── Nexus Desktop ........... aplikasi GUI workstation (Tauri) — analis 1 host
│
└── Nexus Server ........... distribusi `pip install nexus-fleet`  (server pusat)
    │
    ├── nexus_agent ......... SATU agent endpoint (telemetri → manager)
    ├── nexus_manager ....... server pusat + data store (events/alerts) + API
    ├── nexus_secops ........ MODUL analitik SOC (otak) di atas store yang sama:
    │     ├── siem .......... SIEM / log analytics (NQL search + agregasi)
    │     ├── correlate ..... XDR correlation (alert → insiden kill-chain)
    │     ├── soar .......... SOAR (playbook → active-response NYATA)
    │     └── (roadmap) ..... ueba · threatintel · cloud · ai-triage
    ├── nexus_dashboard ..... UI web (Fleet + SecOps dalam satu dashboard, seksi terpisah)
    ├── nexus_cli ........... perintah payung `nexus`
    ├── nexus_license ....... lisensi/seat
    └── nexus_common ........ primitif bersama (schema, protocol, crypto)
```

## Mengapa SecOps di dalam distribusi `nexus-fleet`, bukan paket pip terpisah?

- **Satu install, modul di dalam** = persis model Wazuh/Elastic. Dua paket pip
  (`nexus-fleet` + `nexus-secops`) justru MENUMPUK & membingungkan pengguna.
- SecOps **tidak punya data sendiri**: ia membaca store `events`/`alerts` milik
  manager. Memisah jadi paket lain hanya menambah lapisan tanpa manfaat.
- Nama distribusi tetap `nexus-fleet` (sudah dipublikasikan, dipakai CI tag
  `fleet-v*`, landing page) — "Fleet" = lapisan server/agent Nexus; SecOps = modul
  analitik di atasnya. Mengganti nama distribusi justru menciptakan kekacauan.

## Pemisahan tanggung jawab (agar tidak tumpang-tindih)

- **Fleet (data plane):** mendaftarkan agent, mengumpulkan telemetri, menyimpan
  events/alerts, mendistribusikan policy, mengeksekusi active-response.
- **SecOps (analytics plane):** mencari (SIEM), mengkorelasi (XDR), mengotomasi
  respons (SOAR) — semuanya membaca data Fleet, tidak menduplikasinya.

Satu sumber kebenaran data. Tidak ada agent ganda. Tidak ada brand ganda.

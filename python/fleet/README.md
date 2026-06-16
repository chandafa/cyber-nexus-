# Nexus Fleet — Security Platform (agent · manager · cli · dashboard)

**1 platform, 4 komponen** ala-Wazuh, stdlib-only (Python 3.8+). Amankan **jaringan, server,
dan website** dari satu titik: agent ringan mengirim telemetri keamanan ke manager pusat yang
menjalankan **rule engine → alert** (level 0–15 + MITRE ATT&CK), lalu ditampilkan di dashboard/CLI.

```
 endpoint ──(HMAC/HTTP)──►  nexus-manager  ──► SQLite (events, alerts, audit)
 nexus-agent  FIM·SCA·       rule+alert engine        ▲          ▲
 inventory·webaudit·ports    policy·retention         │          │
                             ◄── policy/perintah ──    nexus-dashboard   nexus-cli
```

## Install

**pip (disarankan):**
```bash
pip install .            # dari folder ini; memasang 4 perintah:
                         # nexus-manager · nexus-agent · nexus-cli · nexus-dashboard
```
**npm (wrapper Node → Python):**
```bash
npm install -g .         # perintah sama; butuh Python 3.8+ di PATH
```
**tanpa install:** `cd python/fleet && python -m nexus_manager run` (dst.).

## Pakai

```bash
# 1) Manager (server pusat + dashboard di http://host:8765/)
nexus-manager run --host 0.0.0.0 --port 8765
nexus-manager info                       # enrollment key + admin token

# 2) Agent di tiap endpoint
nexus-agent enroll --host <manager> --port 8765 --key <ENROLL_KEY> --labels prod,web
nexus-agent start                        # daemon: FIM/SCA/inventory/webaudit/ports/...

# 3) Admin / SOC
nexus-cli                                # console interaktif: menu Network & Website security
nexus-cli --token <ADMIN_TOKEN> alerts   # alert (rule engine + MITRE + rekomendasi)
nexus-cli --token <ADMIN_TOKEN> ack --id <ALERT_ID> --status resolved
nexus-cli --token <ADMIN_TOKEN> report   # report konsisten (schema nexus.report/v1)
nexus-dashboard --port 8080              # (opsional) host dashboard di port terpisah
```

## Service (jalan saat boot)
- **Linux:** `deploy/systemd/nexus-{manager,agent}.service` → `systemctl enable --now`.
- **Windows:** `deploy/windows/install-agent-service.ps1` (Scheduled Task, SYSTEM, AtStartup).

## Konsep kunci
- **Skema baku** (`nexus_common/schema.py`): event/alert/report seragam, condong OCSF, `origin: real|demo`.
- **Real findings only**: manager menolak event `demo` secara default (`accept_demo=0`).
- **Rule engine** (`nexus_manager/rules.py`): rule native + MITRE + rekomendasi + response; bisa di-push.
- **Alert engine**: dedup anti-fatigue, ack/resolve, retensi, audit log.
- **Keamanan**: HMAC per-agent, enrollment key, admin token; HTTP LAN (offline-first).

Uji end-to-end: `python ../tests/test_fleet.py` (21 seksi).

> Roadmap menuju standar industri penuh: agent Go/Rust, OpenSearch/Postgres, mTLS/gRPC,
> import Sigma, YARA, Active Response, OCSF penuh, AI remediation, RBAC multi-tenant.
> Pembeda: developer-first (audit Laravel/React/Next, parser log app, security posture score).

*For Personal / Ethical Hacking Study Only.*

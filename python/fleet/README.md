<div align="center">

# Nexus Fleet

**Lightweight, developer-first security platform for endpoints, servers, and web apps.**
Agent · Manager · CLI · Dashboard — a Wazuh-style architecture you can `pip install`.

[![PyPI](https://img.shields.io/pypi/v/nexus-fleet?logo=pypi&logoColor=white)](https://pypi.org/project/nexus-fleet/)
[![npm](https://img.shields.io/npm/v/nexus-fleet?logo=npm)](https://www.npmjs.com/package/nexus-fleet)
[![Python](https://img.shields.io/pypi/pyversions/nexus-fleet)](https://pypi.org/project/nexus-fleet/)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational)]()
[![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-success)]()

</div>

---

## Overview

**Nexus Fleet** lets a central **Manager** monitor many endpoints through a lightweight **Agent**,
generating prioritized, MITRE ATT&CK–mapped alerts — while your security data **stays inside your
own network** (offline-first). It pairs the proven Wazuh model (FIM, log monitoring, SCA,
vulnerability detection, active response) with **developer-first** detections for modern web stacks
(Laravel, Next.js, Nginx) that traditional SIEMs miss.

The agent is **pure-Python (stdlib only)** — deploy it on any host with Python 3.8+, no heavy runtime.

## Why Nexus Fleet

- **Offline-first** — telemetry never leaves your LAN; ideal for compliance and on-prem.
- **Developer-aware** — detects Laravel `APP_DEBUG`, exposed `.env`, weak DB creds, leaked
  `NEXT_PUBLIC_*` secrets, source-map exposure, and parses Laravel/Nginx/auth logs.
- **Lightweight & simple** — single-command install; no cluster, indexer, or agent runtime to manage.
- **Actionable** — every alert carries a severity level (0–15), MITRE technique, and a remediation step.
- **Founder-friendly** — a 0–100 **security posture score** for network, server, and website.

## Features

| Domain | Capabilities |
| --- | --- |
| **Network** | Port/exposure detection, host discovery, DNS recon, firewall advisor |
| **Server / Endpoint** | File Integrity Monitoring (FIM), Security Configuration Assessment (SCA), software & process & network inventory, failed-login & disk monitoring |
| **Web / App** | Laravel & Next.js config audit, `.env` exposure, secret leakage, source-map checks |
| **Detection** | Rule engine (level 0–15 + MITRE ATT&CK), **Sigma import**, log decoders, **Vulnerability Detection** (inventory ↔ CVE) |
| **Response** | Alert engine with deduplication, ack/resolve, **Active Response** (block IP, dry-run by default), audit log |
| **Operations** | Multi-agent management, central policy, store-and-forward offline buffering, consistent reports, posture score |

## Architecture

```
        ┌──────────────────────┐         ┌──────────────────────┐
        │   nexus-dashboard    │         │      nexus-cli       │
        │  (web monitoring UI) │         │  (admin & SOC menu)  │
        └──────────┬───────────┘         └──────────┬───────────┘
                   │  REST API (admin token)         │
                   ▼                                 ▼
        ┌─────────────────────────────────────────────────────────┐
        │                     nexus-manager                        │
        │  enrollment · rule & alert engine · vuln detection ·     │
        │  policy · licensing · audit · reports   →  SQLite        │
        └──────────────────────────┬──────────────────────────────┘
                 HTTP + HMAC-SHA256 │  (heartbeat · events · policy)
        ┌──────────────────────────┴──────────────────────────────┐
        │                      nexus-agent                         │
        │  FIM · Log Monitoring · SCA · Syscollector · Web Audit · │
        │  Active Response · offline store-and-forward queue       │
        └──────────────────────────────────────────────────────────┘
```

## Installation

**With pip** (recommended):

```bash
pip install nexus-fleet
```

**With npm** (Node wrapper around the Python engine):

```bash
npm install -g nexus-fleet
```

Both install the umbrella command **`nexus`** plus five standalone commands: `nexus-manager`,
`nexus-agent`, `nexus-cli`, `nexus-dashboard`, `nexus-license`. Requires **Python 3.8+** on the host.

```bash
nexus --version       # prints: nexus 1.2.0   (verify the install on any terminal)
nexus --help          # list sub-commands
```

## Quick Start

```bash
# 1. Central server (also serves the dashboard at http://<host>:8765/)
nexus manager run --host 0.0.0.0 --port 8765
nexus manager info                       # prints enrollment key + admin token

# 2. On each endpoint
nexus agent enroll --host <manager> --port 8765 --key <ENROLL_KEY> --labels prod,web
nexus agent start                        # runs as a daemon (see deploy/ for service files)

# 3. Administration
nexus cli                                # interactive SOC console (network & web menus)
nexus cli --token <ADMIN_TOKEN> alerts   # list alerts (rule engine + MITRE)
nexus cli --token <ADMIN_TOKEN> report   # consistent report (schema nexus.report/v1)
```

> Each `nexus <sub>` form maps to the matching standalone command (`nexus manager run`
> ≡ `nexus-manager run`). Use whichever you prefer.

Run as a boot-time service using the units in [`deploy/`](./deploy) (systemd / Windows Task Scheduler).

## Editions

| | **Free** | **Pro** | **Enterprise** |
| --- | --- | --- | --- |
| Agents (seats) | 2 | seat-based (default 50) | Unlimited |
| Detection rules | Core | Full (FIM, web audit, SCA, vuln) | Full |
| Sigma import · Active Response | — | ✓ | ✓ |
| Web/app audit · Reports · Posture score | Limited | ✓ | ✓ |

Licensing is enforced by Ed25519-signed tokens (`nexus-license`). Without a license, the Manager
runs in **Free** mode (2 agents). A **Pro** token is **seat-based** — it allows up to its seat count
(default 50) of agents to enroll; **Enterprise** is unlimited. One token unlocks the desktop GUI, the
CLI, and Fleet on the **same device** (`~/.nexus/desktop_license.txt`). Apply a token to the Manager
with `NEXUS_LICENSE=<token-or-file>` or `nexus cli apply-license`. Contact the vendor for licensing.

## Security Model

| Area | Protection |
| --- | --- |
| **Transport** | HMAC-SHA256 per-agent message signing; optional **TLS / mTLS** for the Manager API |
| **Authentication** | Enrollment key for agents; admin token with **RBAC** roles (admin / analyst / read-only) |
| **At rest** | Sensitive event fields encrypted at rest (Fernet); SQLite in WAL mode |
| **Integrity** | Replay/clock-skew protection on signed messages; tamper-evident audit log |
| **Privacy** | Offline-first — telemetry is stored locally; nothing is sent to the internet |
| **Scope** | For ethical, **authorized** security testing on systems you own or may assess |

## Documentation

- Product brief & pricing — `docs/PRODUCT-BRIEF.md`
- IP & licensing — `docs/IP-PROTECTION.md`
- Validation: `python tests/test_fleet.py`, `pwsh validate.ps1`, `pwsh validate_agent.ps1`

## Support

Licensing, sales, and security reports: **ck271138@gmail.com**

## License

© 2026 chandafa (Nexus Security). **Proprietary** — see [`LICENSE`](./LICENSE).
Not open source; redistribution and resale are prohibited without written permission.

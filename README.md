<div align="center">

# 🛡️ Nexus Security Platform

**A unified, developer-first security platform — desktop toolkit + distributed agent/manager fleet.**

Scanning · Vulnerability Assessment · File Integrity · Log Monitoring · Defense · Reporting

[![PyPI](https://img.shields.io/pypi/v/nexus-fleet?logo=pypi&logoColor=white&label=nexus-fleet)](https://pypi.org/project/nexus-fleet/)
[![npm](https://img.shields.io/npm/v/nexus-fleet?logo=npm)](https://www.npmjs.com/package/nexus-fleet)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational)]()
[![Stack](https://img.shields.io/badge/stack-Tauri%202%20%C2%B7%20React%2018%20%C2%B7%20Python%203-blue)]()
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](#-license)

</div>

> ⚠️ **Ethical use only.** Nexus is intended **exclusively** for learning ethical hacking,
> **authorized** penetration testing, and personal security research. Using these tools against
> systems you do not own or are not permitted to assess is **illegal**. You are solely responsible
> for your actions.

---

## Overview

Nexus has two complementary products in one platform:

| Product | What it is | Use case |
| --- | --- | --- |
| **Nexus Desktop** | A cross-platform desktop app (Tauri + React) that orchestrates 20+ security tools with a clean, VS Code–style UI, live terminal, reporting, and history. | Hands-on assessment & analysis from a single workstation. |
| **Nexus Fleet** | A Wazuh-style distributed platform — **agent · manager · CLI · dashboard** — for continuously monitoring many endpoints. Published as [`nexus-fleet`](https://pypi.org/project/nexus-fleet/) on PyPI & npm. | Continuous monitoring, detection & response across servers and endpoints. |

Both are **offline-first**: your security data stays inside your own network.

## Highlights

- **20+ security modules** with realistic demo fallback (run the full workflow before installing any tool).
- **Developer-aware detections** that traditional SIEMs miss — Laravel `APP_DEBUG`, exposed `.env`,
  weak DB credentials, leaked `NEXT_PUBLIC_*` secrets, Nginx/Laravel log analysis.
- **Wazuh-parity Fleet**: FIM, Log Monitoring, SCA, Software/Process/Network inventory,
  **Vulnerability Detection (inventory ↔ CVE)**, rule & alert engine (MITRE ATT&CK), Active Response.
- **One-line install** for the Fleet: `pip install nexus-fleet` or `npm install -g nexus-fleet`.
- **Security posture score** (0–100) for network, server, and website.

## Desktop modules

| Category | Modules |
| --- | --- |
| **Recon & Scan** | Port Scanner (Nmap) · Network Scanner (tshark) · Network Mapper · DNS/Subdomain Recon · Asset Inventory |
| **Web & API** | Vulnerability Scanner (Nikto/Nuclei/Gobuster) · SSL/TLS Auditor (sslyze) · API Tester (ffuf) · Directory Fuzzer |
| **Offensive** | Password Auditor (Hydra/Hashcat) · Hash Tools · Exploit Lookup (searchsploit) · Attack Simulation (Scope Guard) · Reverse Shell/Listener · Wireless Auditor |
| **Cloud & Container** | Container Scanner (Trivy) · Cloud Config Checker (Prowler) |
| **Analysis** | Log Analyzer · Scan Diff |
| **Defense & Reporting** | Defense Monitor · Defense Suite · Portable WAF · Report Generator (PDF/HTML) |
| **Fleet / SOC** | Fleet Manager · Fleet Agent dashboards |

## Architecture

```
Nexus Desktop                              Nexus Fleet (distributed)
┌──────────────────────────┐              ┌──────────────────────────┐
│ React 18 + TypeScript UI │              │ nexus-dashboard · nexus-cli │
│ Tauri 2 IPC              │              └────────────┬─────────────┘
│ Rust executor            │                  REST API │ (admin token)
│ Python engine (runner.py)│              ┌────────────┴─────────────┐
│ SQLite · Jinja2 reports  │              │      nexus-manager       │
└──────────────────────────┘              │ rules · alerts · vuln    │
External tools: Nmap, Nuclei,             │ policy · license · audit │
sslyze, Trivy, ...                        └────────────┬─────────────┘
                                            HMAC/HTTP   │ heartbeat·events
                                          ┌─────────────┴────────────┐
                                          │        nexus-agent       │
                                          │ FIM · logs · SCA · vuln  │
                                          │ syscollector · response  │
                                          └──────────────────────────┘
```

## Requirements

**Desktop (build & run):**

| Component | Version | Notes |
| --- | --- | --- |
| Node.js | 18+ | frontend & Tauri CLI |
| Rust | stable (rustup) | Tauri shell |
| Python | 3.10+ | tool execution engine |
| Git | 2.30+ | clone, wordlists, installers |

Native toolchain — **Windows:** VS C++ Build Tools + WebView2 · **macOS:** `xcode-select --install` ·
**Linux:** `libwebkit2gtk-4.1-dev build-essential libssl-dev libgtk-3-dev librsvg2-dev`.

**Fleet only:** Python **3.8+** (no other dependencies — the agent is stdlib-only).

## Which edition do I install?

Pick the path that matches how you want to use Nexus — they share **one license** (a single
Pro/Enterprise token unlocks both the desktop app and the CLI on the **same device**).

| You want to… | Install | How |
| --- | --- | --- |
| **Use the desktop app** (GUI) — clickable modules, terminal, reports | **Nexus Desktop** | Run the installer (`Nexus_<ver>_x64-setup.exe`) or build from source. Redeem your Pro code in **Settings → License**. |
| **Run on servers / automate** (CLI + Fleet) — manager, agents, dashboard, scripting | **Nexus Fleet** | `pip install nexus-fleet` (or `npm i -g nexus-fleet`). Apply your token with `NEXUS_LICENSE`. |
| **Both on one machine** | **Both** | Install the Desktop app **and** `pip install nexus-fleet`. Redeem the Pro code **once in the GUI** — the CLI/Fleet automatically reuse the same device-bound license (`~/.nexus/desktop_license.txt`). No second code needed. |

## Quick start

**Nexus Fleet** (no desktop build required):

```bash
pip install nexus-fleet          # or: npm install -g nexus-fleet
nexus --version                  # verify install (prints: nexus 1.2.1)

nexus manager run --host 0.0.0.0 --port 8765   # server + dashboard at :8765/
nexus manager info                              # show enrollment key & admin token
nexus agent enroll --host <manager> --port 8765 --key <ENROLL_KEY>
nexus agent start                               # endpoint daemon
nexus cli                                        # interactive SOC console
```

> `nexus` is the umbrella command; the standalone `nexus-manager` / `nexus-agent` /
> `nexus-cli` / `nexus-dashboard` / `nexus-license` commands work identically.

**Nexus Desktop:**

```bash
git clone https://github.com/chandafa/cyber-nexus-.git nexus && cd nexus
npm install
npm run tauri:dev                # development (hot reload)
npm run tauri:build             # production installer (.exe/.msi/.dmg/.AppImage)
```

> First desktop build compiles Rust + SQLite from source (~5–15 min); subsequent builds are incremental.
> On first launch, the **Setup Wizard** guides you through the ethical-use agreement, dependency
> checks, and one-click tool installation (Scoop/Chocolatey/Homebrew/apt + no-admin binaries).

## Security & ethics

- **Offline-first** — no scan/telemetry data is sent to external servers.
- All target/URL/port/file inputs are **sanitized** before reaching any subprocess (anti command injection).
- Subprocesses run **without** `shell=True`, with explicit argument lists.
- **Scope Guard** — attack-simulation modules run only against targets you have marked *authorized*.
- The Fleet transport is authenticated with **HMAC-SHA256** per-agent signing.
- Mandatory ethical-use agreement on first run.

## Project structure

```
nexus/
├── src-tauri/      # Rust backend (Tauri 2): commands, SQLite, models
├── src/            # React + TypeScript frontend (pages, stores, components)
├── python/
│   ├── runner.py   # CLI dispatcher invoked by Rust
│   ├── core/ · modules/ · report/      # engine + 20+ security modules
│   └── fleet/      # Nexus Fleet packages (nexus_manager/agent/cli/dashboard/common/license)
├── docs/           # PRODUCT-BRIEF.md, IP-PROTECTION.md
└── .github/workflows/   # CI: desktop release + fleet publish (PyPI/npm)
```

## Editions (Fleet)

| | Free | Pro | Enterprise |
| --- | --- | --- | --- |
| Agents | 2 | seat-based | Unlimited |
| Detection rules | Core | Full | Full |
| Sigma · Active Response · Web audit | — | ✓ | ✓ |

Pro/Enterprise features are unlocked by Ed25519-signed license tokens. Contact the vendor for licensing.

## Support

Licensing, sales, and security reports: **ck271138@gmail.com**

## License

© 2026 chandafa (Nexus Security). The **Nexus Fleet** package is **proprietary** —
see [`python/fleet/LICENSE`](./python/fleet/LICENSE). Not open source; redistribution or resale
without written permission is prohibited.

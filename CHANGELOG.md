# Changelog

All notable changes to **Nexus Fleet** (`nexus-fleet`) are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [2.2.0] — 2026-06
### Added
- **Ecosystem expansion** — Notification Hub (Telegram/Email/Slack/Discord/Webhook/WhatsApp),
  tamper-evident hash-chained audit log, shift-left SBOM scanner + CI gate, Nexus Canary
  honeytokens, "Ask Nexus" local AI persona, time-travel incident replay, air-gapped mode +
  offline threat-intel bundle, Nexus Aware (phishing-sim, Indonesian templates), Nexus Atlas
  (attack-path graph + blast radius), Nexus Hub (content packs), Nexus Edge (agentless syslog
  ingestion), and Nexus Comply (UU PDP + ISO 27001 coverage scoring).
- **Desktop & CLI parity** — every new feature is reachable from the GUI (new "Ekosistem" group),
  the `nexus-cli` console, and the desktop runner; all Pro-gated except the read-only audit view.
- **Nexus Mobile** — Expo/React Native companion app (separate repo).
### Fixed (security & correctness hardening)
- Heartbeat command-delivery race, SSRF in threat-intel feed import, non-constant-time admin-token
  comparison, agent TLS fail-open (now TOFU/fail-closed), CSPRNG auth tokens, a WAF request-handler
  NameError, and eBPF status honesty (no false "Live" label). +10 test suites (20/20 green).

## [2.1.0] — 2026-06
### Added
- **SecOps in the desktop GUI & CLI** — the nine SecOps pillars (SIEM, XDR correlation, EDR,
  UEBA, SOAR, Threat Intelligence, NDR, Cloud/CSPM, AI triage) are now surfaced in the desktop
  app and the `nexus` CLI, not only the dashboard.
- **Full GUI ↔ CLI parity** — every SecOps capability reachable from the desktop app is also
  reachable from the command line (and vice-versa), with consistent output.
### Changed
- **Pro-gated SecOps** — SecOps features are gated behind the Pro/Enterprise license in both the
  GUI and CLI, consistent with the rest of the platform.
- Single source of truth for the product version (`nexus_common.__version__`); all components and
  `--version` strings now read **2.1.0**.

## [2.0.0] — 2026-06
### Added
- **Nexus SecOps subsystem** — Nexus grows from a Wazuh-style fleet into a full SOC platform.
  Nine focused security capabilities, de-duplicated from twenty enterprise tools, all shipping
  inside the same `nexus-fleet` package (one install, one agent, modules inside):
  - **SIEM** — log analytics with the **NQL** query language + aggregations (Splunk SPL / Elastic /
    QRadar / Graylog style) over the existing manager event/alert store.
  - **XDR correlation** — fuse alerts across time and source into single kill-chain incidents
    (Microsoft Defender XDR / Cortex XDR style).
  - **EDR** — process-tree (pid/ppid) reconstruction + suspicious-lineage detection.
  - **UEBA** — per-entity behavioral baselines + anomaly scoring.
  - **SOAR** — playbooks (trigger → steps) driving **real** Fleet active-response + webhooks.
  - **Threat Intelligence** — IOC database + matching against real telemetry + feed import.
  - **NDR** — beaconing/C2, port-scan and IOC-connection detection.
  - **Cloud / CSPM** — cloud-config scoring against CIS + Prowler import.
  - **AI triage** — local Naive-Bayes + heuristic + NLG triage engine (no external API/token).
- **Dashboard SecOps views** — each pillar surfaced in the web dashboard.
### Notes
- The 1.3.0 → 2.0.0 line built the SecOps pillars incrementally on the shared Fleet data plane.

## [1.2.1] — 2026-06
### Added
- **`nexus` umbrella CLI** — a single entry point that dispatches to `manager`, `agent`, `cli`,
  `dashboard` and `license`, with a unified `nexus --version`.
### Fixed
- **Seat licensing** — Pro tier now correctly allows **50** seats (was incorrectly capped at 2).
### Changed
- **Dashboard SPA redesign** — refreshed single-page dashboard.

## [1.1.0] — 2026-06
### Changed
- **Publish & copyright prep** — copyright/license headers applied across the codebase and
  packaging metadata aligned for publication (npm / PyPI / landing).

## [1.0.9] — 2026-06
### Fixed / Improved
- **Correct authz status** — authenticated-but-unauthorized (viewer) writes return **403** (not 401).
- **CVE version ranges** — DB entries support `introduced..fixed` ranges (closer to OSV/CPE);
  `nexus-manager vuln-import --file feed.json` loads an offline CVE database.
- **mTLS** — the manager can require agent **client certificates** (`NEXUS_TLS_CLIENT_CA`;
  agent uses `NEXUS_CLIENT_CERT`/`NEXUS_CLIENT_KEY`).
- **Wider at-rest encryption** — per-agent `agent_key` is now encrypted (with config secrets) when
  `NEXUS_MASTER_KEY` is set.
- **Concurrency (HA step)** — SQLite **WAL** mode + busy-timeout. *(True clustering needs an external
  database — roadmap.)*

### Roadmap (not yet)
Full CPE/NVD feed with online auto-update, full-database encryption (SQLCipher), multi-node HA cluster.

## [1.0.8] — 2026-06
### Fixed / Improved (from real-usage audit)
- **Specific alert titles** — alerts now show the event's specific finding (CVE/port/process), not
  just the rule name.
- **More accurate Vulnerability Detection** — word-boundary product matching (no "git"↔"GitHub"
  false positives) and version parsing that ignores year tokens.
- **Agent removal** — `nexus-cli remove-agent --agent <id>` deregisters an agent and frees its seat.
- **Correct HTTP status** — license-gated features return **403** (was 400).
- **Clock-skew tolerance** — agents sync time from the server; replay window is configurable.
- **Granular Active Response** — per-action allowlist + protected-IP list (won't block yourself).
- **Windows failed-login detection** — reads Security Event Log (Event 4625).
- **Dashboard** — admin token stored in `sessionStorage` (not `localStorage`).
- **Optional at-rest encryption** — secrets encrypted with `NEXUS_MASTER_KEY` (`pip install
  nexus-fleet[crypto]`).
- **RBAC** — multiple API tokens with `admin`/`viewer` roles (`nexus-cli add-user`).
- **Incident grouping** — `nexus-cli incidents` groups alerts to reduce fatigue.

## [1.0.7] — 2026-06
### Fixed / Improved
- **License hot-reload** — apply a license to a running manager without restart
  (`POST /api/v1/license/apply`, `nexus-cli apply-license`).
- **TLS for admin tools** — `nexus-cli --tls/--cacert/--insecure` (HTTPS no longer breaks the CLI).
- **Vulnerability Detection across OSes** — version is parsed from Windows DisplayNames; expanded CVE
  set (Node, 7-Zip, PuTTY, Jenkins).
- **One-command onboarding** — `nexus-agent enroll --watch <path>` auto-enables FIM/web-audit/log for
  a project without editing central policy.
- **At-rest hardening** — manager/agent database files are created with `0600` permissions.

## [1.0.6] — 2026-06
### Added
- **TLS transport** for agent ↔ manager (`nexus-manager gencert`, `run --cert/--key`;
  `nexus-agent enroll --tls` with trust-on-first-use certificate pinning).
- **Anti-replay** protection — signed messages carry a timestamp; stale messages are rejected.
- **Auto-remediation** ("Amankan") — agent Active Response actions: `block_ip`, `enable_firewall`,
  `kill_process`, `disable_guest`, `harden` (dry-run by default). One-click **Remediate** button
  in the web dashboard.
- **Alert notifications** — Slack/Discord/HTTP webhook on high/critical alerts.
- IP validation for Active Response.
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and a CI workflow running the fleet test suite.

## [1.0.5] — 2026-06
### Changed
- Professional, enterprise-grade READMEs (GitHub, npm, PyPI) with badges and architecture.

## [1.0.4] — 2026-06
### Added
- Agent **syscollector** parity: process inventory (with suspicious-process detection) and
  network/IP inventory; rule `NEXUS-PROC-001`.
- `validate_agent.ps1` — full live agent validation including offline buffering.

## [1.0.3] — 2026-06
### Added
- **Vulnerability Detection** — manager correlates software inventory against a CVE database
  (Log4Shell, Shellshock, Baron Samedit, etc.); rule `NEXUS-VULN-001`.

## [1.0.2] — 2026-06
### Added
- **Log Monitoring** with app-aware decoders (Laravel, Nginx, auth); rules `NEXUS-LOG-001..006`.
### Changed
- License changed from MIT to **proprietary** (freemium / open-core).

## [1.0.1] — 2026-06
### Added
- **Freemium licensing** (Free / Pro / Enterprise) with Ed25519-signed tokens and the
  `nexus-license` vendor CLI.

## [1.0.0] — 2026-06
### Added
- Initial release: distributed **agent · manager · CLI · dashboard** platform with rule & alert
  engine (MITRE ATT&CK), FIM, SCA, web-app audit, posture score, Sigma import, and consistent
  reporting. Published to PyPI and npm.

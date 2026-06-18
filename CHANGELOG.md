# Changelog

All notable changes to **Nexus Fleet** (`nexus-fleet`) are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

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

# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in Nexus, please report it **privately** — do **not**
open a public issue.

- Email: **surelna.studio@gmail.com** (subject: `SECURITY — Nexus`)
- Include: affected component/version, reproduction steps, and impact.
- We aim to acknowledge within 72 hours and to provide a fix or mitigation timeline after triage.

Please act in good faith: test only against systems you own or are authorized to assess, avoid
data destruction, and give us reasonable time to remediate before any disclosure.

## Supported versions

Security fixes are provided for the **latest released version** of `nexus-fleet`. Older versions
may not receive updates.

## Scope & ethical use

Nexus is intended exclusively for **authorized** security testing and personal research. Misuse
against systems without permission is illegal and out of scope for this policy.

## Hardening recommendations

- Run the Fleet Manager with **TLS** (`nexus-manager gencert` then `run --cert --key`).
- Keep the **enrollment key** and **admin token** secret; rotate them periodically.
- Restrict the manager port to trusted networks / VPN.
- Keep `active_response` in **dry-run** unless you have validated remediation actions.

# Contributing to Nexus

Thanks for your interest in Nexus. **Nexus is proprietary software** (see
[`python/fleet/LICENSE`](./python/fleet/LICENSE)); contributions are accepted **by invitation** or
under a separate agreement with the maintainer.

## Reporting issues

- **Security vulnerabilities:** follow [`SECURITY.md`](./SECURITY.md) — report privately.
- **Bugs / feature requests:** open a GitHub issue with clear reproduction steps, environment
  (OS, Python/Node version), and expected vs actual behavior.

## Development

```bash
# Fleet (Python, stdlib-only)
cd python/fleet
python -m nexus_manager run            # or nexus-agent / nexus-cli

# Run the test suite (must pass before any change is accepted)
python ../tests/test_fleet.py          # 30+ checks
pwsh validate.ps1                      # live component validation
pwsh validate_agent.ps1                # live agent validation
```

## Standards

- **Tests must pass** (`test_fleet.py`) and new behavior must add coverage.
- Keep the **agent stdlib-only** (no third-party runtime dependencies).
- Match existing code style; keep comments concise and in the surrounding language.
- Never commit secrets — `vendor_private.key`, `*.license`, and `*.db` are git-ignored.

## License of contributions

By submitting a contribution you agree it may be incorporated into the proprietary product and that
the maintainer retains all rights to the combined work.

#!/usr/bin/env node
// bin/nexus.js — perintah payung `nexus` (paritas dengan entry-point PyPI
// `nexus = nexus_cli.nexus:main`). Mendelegasikan ke sub-CLI: manager, agent,
// cli, dashboard, license — mis. `nexus manager run`, `nexus --version`.
require("./_spawn")("nexus_cli.nexus");

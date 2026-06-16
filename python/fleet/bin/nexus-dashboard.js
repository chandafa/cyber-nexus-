#!/usr/bin/env node
// nexus-dashboard via npm: jalankan static server bawaan paket.
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");
const root = path.join(__dirname, "..");
const server = path.join(root, "nexus_dashboard", "server.py");
const candidates = process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"];
const env = Object.assign({}, process.env, {
  PYTHONPATH: root + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : ""),
});
for (const py of candidates) {
  const r = spawnSync(py, [server, ...process.argv.slice(2)], { stdio: "inherit", env });
  if (r.error && r.error.code === "ENOENT") continue;
  process.exit(r.status === null ? 1 : r.status);
}
console.error("[nexus-fleet] Python 3.8+ tidak ditemukan di PATH.");
process.exit(127);

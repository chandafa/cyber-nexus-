// bin/_spawn.js — jalankan modul Python fleet dari shim npm.
// Menemukan interpreter Python, set PYTHONPATH ke root paket (berisi nexus_*),
// lalu `python -m <mod> <args>` dengan stdio diteruskan.
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");

module.exports = function run(mod) {
  const root = path.join(__dirname, "..");
  const candidates =
    process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"];
  const args = ["-m", mod, ...process.argv.slice(2)];
  const env = Object.assign({}, process.env, {
    PYTHONPATH: root + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : ""),
  });
  for (const py of candidates) {
    const r = spawnSync(py, args, { stdio: "inherit", env });
    if (r.error && r.error.code === "ENOENT") continue; // python ini tak ada, coba berikutnya
    process.exit(r.status === null ? 1 : r.status);
  }
  console.error(
    "[nexus-fleet] Python 3.8+ tidak ditemukan di PATH.\n" +
      "Pasang Python (https://python.org) lalu jalankan perintah ini lagi."
  );
  process.exit(127);
};

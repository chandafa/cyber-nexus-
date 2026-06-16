#!/usr/bin/env node
// postinstall: ingatkan bila Python tak ada (tidak menggagalkan instalasi).
"use strict";
const { spawnSync } = require("child_process");
const candidates = process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"];
let ok = false;
for (const py of candidates) {
  const r = spawnSync(py, ["--version"], { stdio: "ignore" });
  if (!r.error) { ok = true; break; }
}
if (!ok) {
  console.warn(
    "\n[nexus-fleet] Catatan: Python 3.8+ tidak terdeteksi.\n" +
      "  Komponen menjalankan engine Python — pasang Python lebih dulu:\n" +
      "  https://www.python.org/downloads/\n"
  );
}

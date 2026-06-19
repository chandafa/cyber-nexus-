// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/lib/proModules.ts — daftar rute modul Pro (butuh lisensi).
// Selaras dengan core/desktop_license.py PRO_COMMANDS. Modul Free TIDAK di sini.
export const PRO_ROUTES: string[] = [
  "/vuln-scanner",
  "/ssl-auditor",
  "/api-tester",
  "/dir-fuzzer",
  "/network-mapper",
  "/asset-inventory",
  "/password-auditor",
  "/exploit-lookup",
  "/attack-simulation",
  "/listener",
  "/wireless-auditor",
  "/container-scanner",
  "/cloud-checker",
  "/scan-diff",
  "/defense-monitor",
  "/defense-suite",
  "/waf",
  "/report",
  "/fleet-manager",
  "/fleet-agent",
  "/scheduler",
];

const PRO_SET = new Set(PRO_ROUTES);

/** Apakah rute (mis. "/waf" atau "waf") termasuk modul Pro? */
export function isProRoute(to: string): boolean {
  const norm = to.startsWith("/") ? to : `/${to}`;
  return PRO_SET.has(norm);
}

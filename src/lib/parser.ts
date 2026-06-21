// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/lib/parser.ts
// Utilitas parsing output untuk frontend.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function normalizeSeverity(s?: string): Severity {
  const v = (s || "info").toLowerCase();
  if (SEVERITY_ORDER.includes(v as Severity)) return v as Severity;
  return "info";
}

/** Hitung jumlah per severity dari daftar vuln. */
export function severityCounts(vulns: { severity?: string }[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const v of vulns) counts[normalizeSeverity(v.severity)]++;
  return counts;
}

/** Konversi array of object ke CSV string. */
export function toCSV(rows: Record<string, any>[]): string {
  if (!rows.length) return "";
  const headerSet = new Set<string>();
  for (const r of rows) {
    for (const k of Object.keys(r)) headerSet.add(k);
  }
  const headers = Array.from(headerSet);
  const esc = (val: any) => {
    const s = val === null || val === undefined ? "" : String(val);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.join(",")];
  for (const r of rows) lines.push(headers.map((h) => esc(r[h])).join(","));
  return lines.join("\n");
}

export function downloadCSV(filename: string, rows: Record<string, any>[]) {
  const csv = toCSV(rows);
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Deteksi sentinel hasil dalam baris terminal (jika lolos ke frontend). */
export function extractResult(line: string): any | null {
  const m = line.match(/^__NEXUS_RESULT__\s+(.*)$/);
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch {
    return null;
  }
}

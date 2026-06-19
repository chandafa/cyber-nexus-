// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/lib/license.ts — status & manajemen lisensi desktop (gerbang fitur Pro).
import { runToolJson } from "./tauri";

export interface LicenseStatus {
  tier: "free" | "pro" | "enterprise" | string;
  valid: boolean;
  licensee: string;
  features: string[];
  feature_labels: Record<string, string>;
  max_agents: number | null;
  expires: number; // epoch detik, 0 = tak kedaluwarsa
  days_left?: number | null;
  reason: string;
  activated?: boolean;
  has_file: boolean;
  device_id?: string;
  api_configured?: boolean;
  revoked_reason?: string;
  pro_commands?: Record<string, string>;
}

export interface LicenseApplyResult extends Partial<LicenseStatus> {
  ok: boolean;
  error?: string;
}

/** Fitur Pro yang dikenal + labelnya (untuk UI bila status belum termuat). */
export const PRO_FEATURES: Record<string, string> = {
  report: "Report Generator",
  webaudit: "Web & App Audit",
  sigma: "Sigma Import",
  active_response: "Active Response",
  advanced_rules: "Advanced Rules",
  unlimited_agents: "Unlimited Agents",
};

export const FREE_STATUS: LicenseStatus = {
  tier: "free",
  valid: false,
  licensee: "",
  features: [],
  feature_labels: {},
  max_agents: 2,
  expires: 0,
  days_left: null,
  reason: "no_license",
  activated: false,
  has_file: false,
  device_id: "",
  api_configured: false,
};

export async function getLicenseStatus(): Promise<LicenseStatus> {
  return runToolJson<LicenseStatus>("license_status");
}

/** Tukar kode aktivasi (sekali pakai, terkunci device) lewat server lisensi. */
export async function redeemLicense(code: string): Promise<LicenseApplyResult> {
  return runToolJson<LicenseApplyResult>("license_redeem", ["--code", code.trim()]);
}

/** Validasi ulang ke server (deteksi revoke/expired). */
export async function validateLicense(): Promise<LicenseStatus> {
  return runToolJson<LicenseStatus>("license_validate");
}

/** Terapkan token manual langsung (lisensi enterprise/offline). */
export async function applyLicense(token: string): Promise<LicenseApplyResult> {
  return runToolJson<LicenseApplyResult>("license_apply", ["--token", token]);
}

export async function clearLicense(): Promise<LicenseApplyResult> {
  return runToolJson<LicenseApplyResult>("license_clear");
}

/** Format tanggal kedaluwarsa untuk ditampilkan. */
export function expiryLabel(expires: number): string {
  if (!expires) return "Tanpa kedaluwarsa";
  try {
    return new Date(expires * 1000).toLocaleDateString();
  } catch {
    return "-";
  }
}

// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/app/store/license.store.ts — edisi & hak pakai (entitlements) aplikasi.
import { create } from "zustand";
import {
  getLicenseStatus,
  redeemLicense,
  validateLicense,
  applyLicense,
  clearLicense,
  FREE_STATUS,
  type LicenseStatus,
  type LicenseApplyResult,
} from "../../lib/license";
import { isTauri } from "../../lib/tauri";

interface LicenseState {
  status: LicenseStatus;
  loaded: boolean;
  busy: boolean;
  load: () => Promise<void>;
  /** Aktivasi via kode sekali-pakai (server). */
  redeem: (code: string) => Promise<LicenseApplyResult>;
  /** Validasi ulang ke server (revoke/expired). */
  validate: () => Promise<void>;
  /** Terapkan token manual (enterprise/offline). */
  apply: (token: string) => Promise<LicenseApplyResult>;
  clear: () => Promise<void>;
  /** Apakah edisi sekarang berhak atas sebuah fitur Pro? */
  has: (feature: string) => boolean;
  /** Punya lisensi valid apa pun (Pro/Enterprise)? — gerbang modul Pro umum. */
  isLicensed: () => boolean;
  isFree: () => boolean;
}

export const useLicenseStore = create<LicenseState>((set, get) => ({
  status: FREE_STATUS,
  loaded: false,
  busy: false,

  load: async () => {
    if (!isTauri()) {
      set({ status: FREE_STATUS, loaded: true });
      return;
    }
    try {
      const status = await getLicenseStatus();
      set({ status, loaded: true });
    } catch (e) {
      console.error("license.load", e);
      set({ status: FREE_STATUS, loaded: true });
    }
  },

  redeem: async (code: string) => {
    set({ busy: true });
    try {
      const res = await redeemLicense(code);
      if (res.ok) await get().load();
      return res;
    } catch (e: any) {
      return { ok: false, error: String(e?.message ?? e) };
    } finally {
      set({ busy: false });
    }
  },

  validate: async () => {
    if (!isTauri()) return;
    try {
      const status = await validateLicense();
      set({ status });
    } catch (e) {
      console.error("license.validate", e);
    }
  },

  apply: async (token: string) => {
    set({ busy: true });
    try {
      const res = await applyLicense(token.trim());
      if (res.ok) await get().load();
      return res;
    } catch (e: any) {
      return { ok: false, error: String(e?.message ?? e) };
    } finally {
      set({ busy: false });
    }
  },

  clear: async () => {
    set({ busy: true });
    try {
      await clearLicense();
      await get().load();
    } catch (e) {
      console.error("license.clear", e);
    } finally {
      set({ busy: false });
    }
  },

  has: (feature: string) => {
    const s = get().status;
    return !!s.valid && s.features.includes(feature);
  },

  isLicensed: () => !!get().status.valid,

  isFree: () => {
    const s = get().status;
    return !s.valid || s.tier === "free";
  },
}));

// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/app/store/scan.store.ts
import { create } from "zustand";
import { listSessions, isTauri, type ScanSession } from "../../lib/tauri";

interface ScanState {
  history: ScanSession[];
  lastResults: Record<string, any>; // module -> last result
  loadingHistory: boolean;
  refreshHistory: () => Promise<void>;
  setResult: (module: string, result: any) => void;
}

export const useScanStore = create<ScanState>((set) => ({
  history: [],
  lastResults: {},
  loadingHistory: false,

  refreshHistory: async () => {
    if (!isTauri()) return;
    set({ loadingHistory: true });
    try {
      const history = await listSessions(100);
      set({ history, loadingHistory: false });
    } catch (e) {
      console.error("refreshHistory", e);
      set({ loadingHistory: false });
    }
  },

  setResult: (module, result) =>
    set((s) => ({ lastResults: { ...s.lastResults, [module]: result } })),
}));

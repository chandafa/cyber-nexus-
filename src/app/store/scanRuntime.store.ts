// src/app/store/scanRuntime.store.ts
// State scan global yang BERTAHAN lintas-navigasi: output terminal di-buffer
// per-modul, listener Tauri dipasang sekali (global), sehingga berpindah tab
// tidak menghilangkan output/hasil scan yang sedang/sudah berjalan.
import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { extractResult } from "../../lib/parser";
import { isTauri } from "../../lib/tauri";
import { uuid } from "../../lib/utils";
import { useScanStore } from "./scan.store";

export interface ModuleScan {
  scanId: string;
  module: string;
  running: boolean;
  status: string; // idle | running | completed | failed | stopped
  progress: number | null;
  result: any | null;
  tick: number; // penanda perubahan buffer (memicu render terminal)
  target?: string;
  mode?: string;
}

// Buffer baris terminal (mutable, persist) + peta scanId→module.
const buffers = new Map<string, string[]>();
const idToModule = new Map<string, string>();
let listenersReady = false;

interface RuntimeStore {
  scans: Record<string, ModuleScan>;
  start: (o: {
    module: string;
    command: string;
    args: string[];
    target?: string;
    mode?: string;
  }) => Promise<void>;
  stop: (module: string) => Promise<void>;
  clearTerminal: (module: string) => void;
  getBuffer: (module: string) => string[];
}

export const useScanRuntimeStore = create<RuntimeStore>((set, get) => {
  function bump(mod: string, patch: Partial<ModuleScan>) {
    set((s) => {
      const cur = s.scans[mod];
      if (!cur) return s;
      return { scans: { ...s.scans, [mod]: { ...cur, ...patch, tick: cur.tick + 1 } } };
    });
  }

  async function ensureListeners() {
    if (listenersReady || !isTauri()) return;
    listenersReady = true;

    await listen<{ line: string; scan_id: string }>("scan-output", (e) => {
      const mod = idToModule.get(e.payload.scan_id);
      if (!mod) return;
      // Fallback bila sentinel ikut ter-stream (umumnya tidak).
      const res = extractResult(e.payload.line);
      if (res) {
        bump(mod, { result: res });
        return;
      }
      buffers.get(mod)?.push(e.payload.line);
      bump(mod, {});
    });

    // Hasil terstruktur dikirim Rust sebagai event terpisah (untuk tab Hasil).
    await listen<{ scan_id: string; result: any }>("scan-result", (e) => {
      const mod = idToModule.get(e.payload.scan_id);
      if (!mod) return;
      bump(mod, { result: e.payload.result });
    });

    await listen<{ percent: number }>("scan-progress", (e) => {
      // progress tidak ber-scan_id → terapkan ke semua modul yang running.
      const { scans } = get();
      for (const mod of Object.keys(scans)) {
        if (scans[mod].running) bump(mod, { progress: e.payload.percent });
      }
    });

    await listen<{ scan_id: string; exit_code: number }>("scan-complete", (e) => {
      const mod = idToModule.get(e.payload.scan_id);
      if (!mod) return;
      const ok = e.payload.exit_code === 0;
      if (mod === "waf") {
        buffers
          .get(mod)
          ?.push(ok ? "[*] WAF dihentikan." : `[ERROR] WAF terhenti (exit ${e.payload.exit_code}).`);
      } else {
        buffers
          .get(mod)
          ?.push(ok ? "[*] Scan selesai." : `[ERROR] Scan gagal (exit ${e.payload.exit_code}).`);
      }
      bump(mod, { running: false, progress: null, status: ok ? "completed" : "failed" });
      idToModule.delete(e.payload.scan_id);
      useScanStore.getState().refreshHistory();
    });
  }

  return {
    scans: {},

    start: async ({ module, command, args, target, mode }) => {
      const header = `$ nexus ${command} ${args.join(" ")}`;
      if (!isTauri()) {
        buffers.set(module, [
          header,
          "[ERROR] Backend Tauri tidak aktif. Jalankan via `npm run tauri:dev`.",
        ]);
        set((s) => ({
          scans: {
            ...s.scans,
            [module]: {
              scanId: "",
              module,
              running: false,
              status: "failed",
              progress: null,
              result: null,
              tick: (s.scans[module]?.tick ?? 0) + 1,
            },
          },
        }));
        return;
      }
      await ensureListeners();
      const scanId = uuid();
      idToModule.set(scanId, module);
      buffers.set(module, [header]);
      set((s) => ({
        scans: {
          ...s.scans,
          [module]: {
            scanId,
            module,
            running: true,
            status: "running",
            progress: null,
            result: null,
            tick: (s.scans[module]?.tick ?? 0) + 1,
            target,
            mode,
          },
        },
      }));
      try {
        await invoke("run_scan", {
          scanId,
          command,
          args,
          module,
          target: target ?? null,
          mode: mode ?? null,
        });
      } catch (e: any) {
        buffers.get(module)?.push(`[ERROR] ${e?.message || e}`);
        bump(module, { running: false, status: "failed" });
      }
    },

    stop: async (module) => {
      const sc = get().scans[module];
      if (sc?.scanId) {
        try {
          await invoke("stop_scan", { scanId: sc.scanId });
        } catch {
          /* ignore */
        }
        buffers.get(module)?.push("[WARN] Permintaan berhenti dikirim...");
        bump(module, { status: "stopped" });
      }
    },

    clearTerminal: (module) => {
      buffers.set(module, []);
      bump(module, {});
    },

    getBuffer: (module) => buffers.get(module) ?? [],
  };
});

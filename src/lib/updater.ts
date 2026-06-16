// src/lib/updater.ts
// Auto-update aplikasi dari GitHub Release via Tauri Updater plugin.
// Alur: check() -> downloadAndInstall(progress) -> relaunch().
// Tanda tangan digital diverifikasi otomatis oleh plugin (pubkey di tauri.conf.json).
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { getVersion } from "@tauri-apps/api/app";

export type UpdatePhase =
  | "idle"
  | "checking"
  | "uptodate"
  | "available"
  | "downloading"
  | "installing"
  | "relaunching"
  | "error";

export interface UpdateState {
  phase: UpdatePhase;
  currentVersion?: string;
  version?: string;
  notes?: string;
  date?: string;
  downloaded: number;
  total: number;
  percent: number;
  error?: string;
}

export const initialUpdateState: UpdateState = {
  phase: "idle",
  downloaded: 0,
  total: 0,
  percent: 0,
};

/** Versi aplikasi yang sedang berjalan (dari Cargo/tauri.conf). */
export async function getCurrentVersion(): Promise<string | undefined> {
  return getVersion().catch(() => undefined);
}

/** Cek ketersediaan update TANPA mengunduh. */
export async function checkForUpdate(): Promise<UpdateState> {
  const currentVersion = await getCurrentVersion();
  const update = await check();
  if (!update) {
    return { ...initialUpdateState, phase: "uptodate", currentVersion };
  }
  return {
    ...initialUpdateState,
    phase: "available",
    currentVersion,
    version: update.version,
    notes: update.body,
    date: update.date,
  };
}

/**
 * Unduh + pasang update sambil melaporkan progres ke `onProgress`,
 * lalu restart aplikasi secara otomatis.
 */
export async function downloadInstallRelaunch(
  onProgress: (s: UpdateState) => void,
): Promise<void> {
  const currentVersion = await getCurrentVersion();
  const update = await check();
  if (!update) {
    onProgress({ ...initialUpdateState, phase: "uptodate", currentVersion });
    return;
  }

  const base: UpdateState = {
    ...initialUpdateState,
    currentVersion,
    version: update.version,
    notes: update.body,
    date: update.date,
  };

  let total = 0;
  let downloaded = 0;
  onProgress({ ...base, phase: "downloading" });

  await update.downloadAndInstall((event: any) => {
    switch (event.event) {
      case "Started":
        total = event.data.contentLength ?? 0;
        onProgress({ ...base, phase: "downloading", total, downloaded: 0, percent: 0 });
        break;
      case "Progress":
        downloaded += event.data.chunkLength;
        onProgress({
          ...base,
          phase: "downloading",
          total,
          downloaded,
          percent: total ? Math.min(100, Math.round((downloaded / total) * 100)) : 0,
        });
        break;
      case "Finished":
        onProgress({ ...base, phase: "installing", total, downloaded: total, percent: 100 });
        break;
    }
  });

  // Sampai sini installer sudah dijalankan — restart agar versi baru aktif.
  onProgress({ ...base, phase: "relaunching", total, downloaded: total, percent: 100 });
  await relaunch();
}

/** Format byte ke string ringkas (KB/MB). */
export function formatBytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
}

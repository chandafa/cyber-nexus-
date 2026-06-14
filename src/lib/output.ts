// src/lib/output.ts
// Helper export hasil/laporan: pilih folder sekali (diingat), tulis file lewat
// Rust, lalu toast dengan aksi "Buka folder". Fallback unduhan browser bila
// tidak di Tauri.
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { writeTextFile, revealPath, openPath, isTauri } from "./tauri";
import { useSettingsStore } from "../app/store/settings.store";
import { useToastStore } from "../app/store/toast.store";

const OUTPUT_DIR_KEY = "output_dir";

function joinPath(dir: string, name: string): string {
  return dir.replace(/[\\/]+$/, "") + "/" + name;
}

/** Folder output tersimpan; bila kosong → minta user pilih (sekali), lalu ingat. */
export async function getOutputDir(prompt = true): Promise<string | null> {
  const store = useSettingsStore.getState();
  let dir = store.settings[OUTPUT_DIR_KEY];
  if (!dir && prompt && isTauri()) {
    const picked = await openDialog({
      directory: true,
      title: "Pilih folder untuk menyimpan hasil & laporan",
    });
    if (typeof picked === "string" && picked) {
      dir = picked;
      await store.update(OUTPUT_DIR_KEY, dir);
    }
  }
  return dir || null;
}

/** Ganti folder output secara eksplisit (dipakai di Settings). */
export async function chooseOutputDir(): Promise<string | null> {
  const picked = await openDialog({ directory: true, title: "Pilih folder output" });
  if (typeof picked === "string" && picked) {
    await useSettingsStore.getState().update(OUTPUT_DIR_KEY, picked);
    return picked;
  }
  return null;
}

/** Tulis file teks ke folder output (CSV/JSON). Kembalikan path atau null. */
export async function exportTextFile(name: string, content: string): Promise<string | null> {
  const toast = useToastStore.getState();
  if (!isTauri()) {
    // Fallback browser (preview mode).
    const blob = new Blob([content], { type: "text/plain;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
    return null;
  }
  const dir = await getOutputDir();
  if (!dir) {
    toast.show("Export dibatalkan (folder belum dipilih).", { kind: "info" });
    return null;
  }
  const path = joinPath(dir, name);
  try {
    await writeTextFile(path, content);
    toast.show(`Tersimpan: ${name}`, {
      kind: "success",
      actionLabel: "Buka folder",
      action: () => revealPath(path).catch(() => {}),
    });
    return path;
  } catch (e: any) {
    toast.show(`Gagal menyimpan: ${e?.message || e}`, { kind: "error" });
    return null;
  }
}

/** Beri tahu file (laporan) sudah dibuat + aksi buka. */
export function notifySaved(path: string, opened = false) {
  useToastStore.getState().show(opened ? "Laporan dibuka." : `Tersimpan: ${path}`, {
    kind: "success",
    actionLabel: "Buka file",
    action: () => openPath(path).catch(() => {}),
  });
}

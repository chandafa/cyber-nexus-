// src/lib/tauri.ts
// Pembungkus invoke()/listen() ke Rust backend — SDD bagian 6.3.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface ScanOutput {
  line: string;
  scan_id: string;
}
export interface ScanComplete {
  scan_id: string;
  exit_code: number;
}
export interface ScanProgress {
  percent: number;
  label: string;
}

export interface ScanSession {
  id: string;
  module: string;
  target: string | null;
  mode: string | null;
  status: string;
  started_at: string;
  ended_at: string | null;
  raw_output: string | null;
  notes: string | null;
}

export interface ToolStatus {
  installed: boolean;
  path: string | null;
  version: string | null;
  required: boolean;
  min_ver: string;
  desc: string;
  install: Record<string, string | null>;
}

/** Apakah kita berjalan di dalam shell Tauri (bukan browser biasa)? */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// ----------------------------------------------------------------- scanning

/**
 * Mulai scan streaming. Mengembalikan fungsi cleanup untuk melepas listener.
 */
export async function startScan(opts: {
  scanId: string;
  command: string;
  args: string[];
  module: string;
  target?: string;
  mode?: string;
  onOutput: (line: string) => void;
  onComplete: (exitCode: number) => void;
  onProgress?: (p: ScanProgress) => void;
}): Promise<() => void> {
  const unlisten: UnlistenFn[] = [];

  unlisten.push(
    await listen<ScanOutput>("scan-output", (e) => {
      if (e.payload.scan_id === opts.scanId) opts.onOutput(e.payload.line);
    })
  );
  unlisten.push(
    await listen<ScanComplete>("scan-complete", (e) => {
      if (e.payload.scan_id === opts.scanId) {
        opts.onComplete(e.payload.exit_code);
        unlisten.forEach((u) => u());
      }
    })
  );
  if (opts.onProgress) {
    unlisten.push(
      await listen<ScanProgress>("scan-progress", (e) => opts.onProgress!(e.payload))
    );
  }

  await invoke("run_scan", {
    scanId: opts.scanId,
    command: opts.command,
    args: opts.args,
    module: opts.module,
    target: opts.target ?? null,
    mode: opts.mode ?? null,
  });

  return () => unlisten.forEach((u) => u());
}

export async function stopScan(scanId: string): Promise<void> {
  await invoke("stop_scan", { scanId });
}

// ------------------------------------------------- terminal interaktif (PTY)

export interface PtyOutput {
  id: string;
  data: string;
}

/** Buka sesi terminal interaktif (shell sungguhan) di backend. */
export async function ptyOpen(id: string, cols: number, rows: number, shell?: string) {
  return invoke("pty_open", { id, cols, rows, shell: shell ?? null });
}
/** Kirim ketikan/perintah ke shell. */
export async function ptyWrite(id: string, data: string) {
  return invoke("pty_write", { id, data });
}
/** Sesuaikan ukuran terminal. */
export async function ptyResize(id: string, cols: number, rows: number) {
  return invoke("pty_resize", { id, cols, rows });
}
/** Tutup & matikan sesi terminal. */
export async function ptyClose(id: string) {
  return invoke("pty_close", { id });
}
/** Dengarkan output shell. Kembalikan fungsi unlisten. */
export async function onPtyOutput(id: string, cb: (data: string) => void): Promise<UnlistenFn> {
  return listen<PtyOutput>("pty-output", (e) => {
    if (e.payload.id === id) cb(e.payload.data);
  });
}
/** Dengarkan event shell selesai. Kembalikan fungsi unlisten. */
export async function onPtyExit(id: string, cb: () => void): Promise<UnlistenFn> {
  return listen<{ id: string }>("pty-exit", (e) => {
    if (e.payload.id === id) cb();
  });
}

/** Bangun list argumen `--key value` dari objek. */
export function buildArgs(obj: Record<string, string | number | boolean | undefined>): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === "" || v === false) continue;
    out.push(`--${k}`);
    if (v !== true) out.push(String(v));
  }
  return out;
}

// -------------------------------------------------------------- dependencies

export async function checkDependencies(): Promise<{ results: Record<string, ToolStatus> }> {
  return invoke("check_dependencies");
}
export async function getInstallInfo(missing: string[]) {
  return invoke<any>("get_install_info", { missing });
}
export interface InstallResult {
  pkg_manager: string;
  command: string;
  ran: boolean;
  manual: string[];
  results: Record<string, boolean>;
  output: string;
  error: string | null;
  success: boolean;
}
export async function installTools(tools: string[]) {
  return invoke<InstallResult>("install_tools", { tools });
}
export async function checkPrivileges() {
  return invoke<{ is_admin: boolean; platform: string }>("check_privileges");
}
export async function listInterfaces() {
  return invoke<{ interfaces: string[] }>("list_interfaces");
}

/** Jalankan command python (blocking) & kembalikan JSON — untuk modul manajemen v2. */
export async function runToolJson<T = any>(command: string, args: string[] = []): Promise<T> {
  return invoke<T>("run_tool_json", { command, args });
}

// --------------------------------------------------------------- backend WSL
export type Backend = "auto" | "windows" | "wsl";
export interface WslStatus {
  is_windows: boolean;
  available: boolean;
  distros: string[];
  active_distro: string;
  backend: Backend;
  no_demo: boolean;
  wsl_user: string;
}
/** Status WSL: terdeteksi atau tidak, daftar distro, backend aktif. */
export async function wslStatus(): Promise<WslStatus> {
  return runToolJson<WslStatus>("wsl_status");
}
/** Simpan preferensi backend eksekusi (auto/windows/wsl) + distro pilihan. */
export async function setBackend(backend: Backend, distro = "") {
  return runToolJson("set_backend", ["--backend", backend, ...(distro ? ["--distro", distro] : [])]);
}
/** Aktif/nonaktifkan mode eksekusi nyata (matikan fallback demo). */
export async function setRealMode(noDemo: boolean) {
  return runToolJson("set_backend", ["--no_demo", noDemo ? "true" : "false"]);
}

// ------------------------------------------------------------------ database

export async function listSessions(limit = 100): Promise<ScanSession[]> {
  return invoke("list_sessions", { limit });
}
export async function getSession(sessionId: string): Promise<any> {
  return invoke("get_session", { sessionId });
}
export async function deleteSession(sessionId: string): Promise<void> {
  return invoke("delete_session", { sessionId });
}
export async function getSettings(): Promise<Record<string, string>> {
  return invoke("get_settings");
}
export async function setSetting(key: string, value: string): Promise<void> {
  return invoke("set_setting", { key, value });
}

// -------------------------------------------------------------------- report

export async function generateReport(
  sessionId: string,
  reportType: "executive" | "technical" | "full",
  outputPath?: string
) {
  return invoke<{ output: string; is_pdf: boolean }>("generate_report", {
    sessionId,
    reportType,
    outputPath: outputPath ?? null,
  });
}

export async function generateReportFromData(
  sessionData: any,
  reportType: "executive" | "technical" | "full"
) {
  return invoke<{ output: string; is_pdf: boolean }>("generate_report_from_data", {
    sessionData,
    reportType,
  });
}

/** Buka file/folder dengan aplikasi default OS (lintas-platform). */
export async function openPath(path: string) {
  return invoke("open_path", { path });
}
export async function revealPath(path: string) {
  return invoke("reveal_path", { path });
}
export async function writeTextFile(path: string, content: string) {
  return invoke("write_text_file", { path, content });
}

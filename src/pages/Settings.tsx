// src/pages/Settings.tsx — SDD §11.3 + auto-install tools (§3.3).
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { Select } from "../components/Select";
import { useSettingsStore } from "../app/store/settings.store";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";
import { DependencyCard } from "../components/DependencyCard";
import { chooseOutputDir } from "../lib/output";
import {
  checkForUpdate,
  downloadInstallRelaunch,
  formatBytes,
  getCurrentVersion,
  initialUpdateState,
  type UpdateState,
} from "../lib/updater";

type Field = { key: string; label: string; type?: "text" | "number" | "select"; options?: string[] };

const FIELDS: Field[] = [
  { key: "theme", label: "Tema", type: "select", options: ["dark", "light"] },
  { key: "terminal_font_size", label: "Ukuran Font Terminal", type: "number" },
  { key: "default_wordlist", label: "Wordlist Default" },
  {
    key: "nmap_default_mode",
    label: "Mode Nmap Default",
    type: "select",
    options: ["quick", "standard", "os", "full", "vuln", "stealth", "udp"],
  },
  { key: "max_hydra_threads", label: "Max Thread Hydra", type: "number" },
  { key: "report_output_dir", label: "Folder Output Laporan" },
  { key: "auto_save_pcap", label: "Auto-save PCAP", type: "select", options: ["true", "false"] },
];

// Tool yang realistis hanya jalan di Linux/WSL (selaras dengan backend LINUX_ONLY).
const LINUX_ONLY = ["hydra", "arp-scan", "hping3", "suricata", "aircrack-ng"];
const BACKEND_LABEL: Record<string, string> = {
  auto: "Auto (native Windows; WSL bila perlu)",
  windows: "Selalu Windows native",
  wsl: "Utamakan WSL",
};

export const Settings: React.FC = () => {
  const {
    settings, loadSettings, update, deps, refreshDeps, loading, install, missingAny,
    wsl, wslLoading, refreshWsl, chooseBackend, provisionWsl, setRealMode,
  } = useSettingsStore();
  const installRunning = useScanRuntimeStore((s) => s.scans["install"]?.running ?? false);
  const [draft, setDraft] = useState<Record<string, string>>({});

  // ---- Auto-update aplikasi (Tauri updater + GitHub Release) ----
  const [upd, setUpd] = useState<UpdateState>(initialUpdateState);
  const updBusy = ["checking", "downloading", "installing", "relaunching"].includes(upd.phase);

  const handleCheckUpdate = async () => {
    setUpd({ ...initialUpdateState, currentVersion: upd.currentVersion, phase: "checking" });
    try {
      setUpd(await checkForUpdate());
    } catch (e: any) {
      setUpd((p) => ({ ...p, phase: "error", error: String(e?.message ?? e) }));
    }
  };

  const handleRunUpdate = async () => {
    try {
      await downloadInstallRelaunch((s) => setUpd(s));
    } catch (e: any) {
      setUpd((p) => ({ ...p, phase: "error", error: String(e?.message ?? e) }));
    }
  };

  useEffect(() => {
    loadSettings();
    refreshDeps();
    refreshWsl();
    getCurrentVersion().then((v) => setUpd((p) => ({ ...p, currentVersion: v }))).catch(() => {});
  }, [loadSettings, refreshDeps, refreshWsl]);

  useEffect(() => setDraft(settings), [settings]);

  const missing = missingAny();
  const handleInstall = (tools: string[]) => install(tools);

  // Tool Linux-only yang belum tersedia (native maupun via WSL).
  const linuxMissing = LINUX_ONLY.filter((t) => deps[t] && !deps[t].installed);

  return (
    <div className="mx-auto max-w-5xl animate-fade-in p-6">
      <header className="mb-5 flex items-center gap-3">
        <div className="bg-nexus-accent/15 p-2">
          <Ic.settings className="h-5 w-5 text-nexus-accent" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-nexus-text">Settings</h1>
          <p className="text-xs text-nexus-muted">Preferensi aplikasi, wordlist, dan manajemen tools</p>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Preferensi */}
        <div className="nx-card">
          <h2 className="nx-section mb-4">Preferensi</h2>
          {/* Folder output untuk export hasil & laporan */}
          <div className="mb-3">
            <label className="nx-label">Folder Output (hasil & laporan)</label>
            <div className="flex gap-2">
              <input
                className="nx-input font-mono text-xs"
                readOnly
                value={settings.output_dir || "(belum dipilih — akan ditanya saat export pertama)"}
              />
              <button className="nx-btn-ghost shrink-0 px-3" onClick={() => chooseOutputDir()}>
                <Ic.folder className="h-4 w-4" /> Pilih
              </button>
            </div>
          </div>
          <div className="space-y-3">
            {FIELDS.map((f) => (
              <div key={f.key} className="flex items-end gap-2">
                <div className="flex-1">
                  <label className="nx-label">{f.label}</label>
                  {f.type === "select" ? (
                    <Select
                      value={draft[f.key] ?? ""}
                      onChange={(v) => {
                        setDraft({ ...draft, [f.key]: v });
                        update(f.key, v);
                      }}
                      options={f.options!}
                    />
                  ) : (
                    <input
                      className="nx-input"
                      type={f.type || "text"}
                      value={draft[f.key] ?? ""}
                      onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
                    />
                  )}
                </div>
                {f.type !== "select" && (
                  <button
                    className="nx-btn-ghost px-3 py-1.5"
                    onClick={() => update(f.key, draft[f.key] ?? "")}
                    title="Simpan"
                  >
                    <Ic.save className="h-4 w-4" />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Status & instalasi tools */}
        <div className="nx-card">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="nx-section">Status Tools</h2>
            <div className="flex gap-2">
              {missing.length > 0 && (
                <button
                  className="nx-btn-primary px-2.5 py-1 text-[11px]"
                  onClick={() => handleInstall(missing)}
                  disabled={installRunning}
                >
                  {installRunning ? (
                    <Ic.refresh className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Ic.install className="h-3.5 w-3.5" />
                  )}
                  Install Semua ({missing.length})
                </button>
              )}
              <button
                className="nx-btn-ghost px-2.5 py-1 text-[11px]"
                onClick={refreshDeps}
                disabled={loading}
              >
                <Ic.refresh className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /> Periksa
              </button>
            </div>
          </div>

          <div className="grid max-h-[440px] grid-cols-1 gap-1.5 overflow-auto pr-1">
            {Object.entries(deps).map(([name, tool]) => (
              <DependencyCard
                key={name}
                name={name}
                tool={tool}
                onInstall={(n) => handleInstall([n])}
                installing={installRunning}
              />
            ))}
            {Object.keys(deps).length === 0 && (
              <p className="text-xs text-nexus-muted">Klik "Periksa" untuk memuat status tools.</p>
            )}
          </div>
        </div>
      </div>

      {/* Update Aplikasi — auto-update dari GitHub Release (terverifikasi tanda tangan) */}
      <div className="nx-card mt-5">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="nx-section">Update Aplikasi</h2>
          <button
            className="nx-btn-ghost px-2.5 py-1 text-[11px]"
            onClick={handleCheckUpdate}
            disabled={updBusy}
          >
            <Ic.refresh className={`h-3.5 w-3.5 ${upd.phase === "checking" ? "animate-spin" : ""}`} />
            Periksa Pembaruan
          </button>
        </div>
        <p className="mb-4 text-xs text-nexus-muted">
          Versi terpasang: <b>v{upd.currentVersion ?? "—"}</b>. Pembaruan diunduh otomatis dari
          GitHub Release resmi, diverifikasi tanda tangan digital, lalu aplikasi me-restart sendiri.
        </p>

        {upd.phase === "uptodate" && (
          <div className="flex items-center gap-3 border border-nexus-green/40 bg-nexus-green/10 px-3 py-2.5 text-xs text-nexus-green">
            <span className="h-2 w-2 shrink-0 rounded-full bg-nexus-green" />
            Aplikasi sudah versi terbaru (v{upd.currentVersion}).
          </div>
        )}

        {upd.phase === "error" && (
          <div className="border border-severity-high/40 bg-severity-high/10 px-3 py-2.5 text-xs text-red-200">
            Gagal memeriksa/memasang pembaruan: {upd.error}
          </div>
        )}

        {(upd.phase === "available" ||
          upd.phase === "downloading" ||
          upd.phase === "installing" ||
          upd.phase === "relaunching") && (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-3 border border-nexus-accent/40 bg-nexus-accent/10 px-3 py-2.5">
              <div className="min-w-0 text-xs">
                <span className="font-semibold text-nexus-accent">
                  Versi baru tersedia: v{upd.version}
                </span>
                {upd.date && <span className="ml-2 text-nexus-muted">({upd.date.slice(0, 10)})</span>}
                {upd.notes && (
                  <span className="mt-1 block max-h-20 overflow-auto whitespace-pre-wrap text-nexus-muted">
                    {upd.notes}
                  </span>
                )}
              </div>
              {upd.phase === "available" && (
                <button className="nx-btn-primary shrink-0" onClick={handleRunUpdate}>
                  <Ic.download className="h-4 w-4" /> Update Sekarang
                </button>
              )}
            </div>

            {(upd.phase === "downloading" ||
              upd.phase === "installing" ||
              upd.phase === "relaunching") && (
              <div>
                <div className="mb-1 flex items-center justify-between text-[11px] text-nexus-muted">
                  <span>
                    {upd.phase === "downloading" && "Mengunduh pembaruan..."}
                    {upd.phase === "installing" && "Memasang pembaruan..."}
                    {upd.phase === "relaunching" && "Memulai ulang aplikasi..."}
                  </span>
                  <span>
                    {upd.total
                      ? `${formatBytes(upd.downloaded)} / ${formatBytes(upd.total)} (${upd.percent}%)`
                      : `${upd.percent}%`}
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-nexus-hairline">
                  <div
                    className="h-full bg-nexus-accent transition-all duration-150"
                    style={{
                      width:
                        upd.phase === "installing" || upd.phase === "relaunching"
                          ? "100%"
                          : `${upd.percent}%`,
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Backend Eksekusi (WSL) — untuk tool yang hanya jalan di Linux */}
      {wsl?.is_windows && (
        <div className="nx-card mt-5">
          <div className="mb-1 flex items-center justify-between">
            <h2 className="nx-section">Backend Eksekusi (Tool Linux via WSL)</h2>
            <button
              className="nx-btn-ghost px-2.5 py-1 text-[11px]"
              onClick={refreshWsl}
              disabled={wslLoading}
            >
              <Ic.refresh className={`h-3.5 w-3.5 ${wslLoading ? "animate-spin" : ""}`} /> Periksa
            </button>
          </div>
          <p className="mb-4 text-xs text-nexus-muted">
            Beberapa tool ({LINUX_ONLY.join(", ")}) hanya berjalan di Linux. Nexus dapat
            menjalankannya otomatis lewat <b>WSL</b> di komputer ini — tanpa perlu Anda atur manual.
          </p>

          {/* Status WSL */}
          <div
            className={`mb-4 flex items-center gap-3 border px-3 py-2.5 ${
              wsl.available
                ? "border-nexus-green/40 bg-nexus-green/10"
                : "border-severity-medium/40 bg-severity-medium/10"
            }`}
          >
            <span
              className={`h-2 w-2 shrink-0 rounded-full ${
                wsl.available ? "bg-nexus-green" : "bg-severity-medium"
              }`}
            />
            <div className="min-w-0 flex-1 text-xs">
              {wsl.available ? (
                <span className="text-nexus-green">
                  WSL aktif — distro: <b>{wsl.active_distro}</b>
                  {wsl.distros.length > 1 ? ` (+${wsl.distros.length - 1} lainnya)` : ""}
                </span>
              ) : (
                <span className="text-yellow-200">
                  WSL belum aktif. Klik tombol di bawah untuk memasang & mengonfigurasinya otomatis
                  (akan muncul prompt Administrator).
                </span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {/* Mode backend */}
            <div>
              <label className="nx-label">Mode Eksekusi</label>
              <Select
                value={wsl.backend}
                onChange={(v) => chooseBackend(v as any, wsl.active_distro)}
                options={(["auto", "windows", "wsl"] as const).map((v) => ({
                  value: v,
                  label: BACKEND_LABEL[v],
                }))}
              />
            </div>
            {/* Pilih distro bila ada >1 */}
            {wsl.distros.length > 0 && (
              <div>
                <label className="nx-label">Distro WSL ("Linux lain")</label>
                <Select
                  value={wsl.active_distro}
                  onChange={(v) => chooseBackend(wsl.backend, v)}
                  options={wsl.distros}
                />
              </div>
            )}
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            {!wsl.available ? (
              <button
                className="nx-btn-primary"
                onClick={() => provisionWsl(linuxMissing)}
                disabled={installRunning}
              >
                {installRunning ? (
                  <Ic.refresh className="h-4 w-4 animate-spin" />
                ) : (
                  <Ic.install className="h-4 w-4" />
                )}
                Aktifkan WSL otomatis (1 klik)
              </button>
            ) : (
              <button
                className="nx-btn-primary"
                onClick={() => provisionWsl(linuxMissing)}
                disabled={installRunning || linuxMissing.length === 0}
              >
                {installRunning ? (
                  <Ic.refresh className="h-4 w-4 animate-spin" />
                ) : (
                  <Ic.install className="h-4 w-4" />
                )}
                {linuxMissing.length === 0
                  ? "Semua tool Linux sudah siap"
                  : `Pasang tool Linux ke WSL (${linuxMissing.length})`}
              </button>
            )}
          </div>
          <p className="mt-3 text-[11px] text-nexus-muted">
            Jika WSL baru pertama dipasang, Windows mungkin meminta <b>restart</b>. Setelah restart,
            buka Nexus lagi dan klik tombol ini sekali lagi untuk menyelesaikan setup.
          </p>

          {/* Mode eksekusi nyata (matikan demo) */}
          <label className="mt-4 flex cursor-pointer items-start gap-3 border-t border-nexus-hairline pt-4">
            <input
              type="checkbox"
              className="mt-0.5 accent-nexus-accent"
              checked={wsl.no_demo}
              onChange={(e) => setRealMode(e.target.checked)}
            />
            <span className="text-xs">
              <span className="font-semibold text-nexus-text">Mode Eksekusi Nyata (matikan demo)</span>
              <span className="mt-0.5 block text-nexus-muted">
                Tool dijalankan sungguhan; bila gagal, tampilkan <b>error nyata</b> — bukan data
                demo. Tool privileged (nmap -sS/-O, arp-scan, suricata, hping3) dijalankan sebagai
                root di WSL. Aktifkan saat mengetes infrastruktur nyata.
              </span>
            </span>
          </label>
        </div>
      )}
    </div>
  );
};

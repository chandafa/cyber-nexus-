// src/pages/Settings.tsx — SDD §11.3 + auto-install tools (§3.3).
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { Select } from "../components/Select";
import { useSettingsStore } from "../app/store/settings.store";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";
import { DependencyCard } from "../components/DependencyCard";
import { chooseOutputDir } from "../lib/output";

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

export const Settings: React.FC = () => {
  const { settings, loadSettings, update, deps, refreshDeps, loading, install, missingAny } =
    useSettingsStore();
  const installRunning = useScanRuntimeStore((s) => s.scans["install"]?.running ?? false);
  const [draft, setDraft] = useState<Record<string, string>>({});

  useEffect(() => {
    loadSettings();
    refreshDeps();
  }, [loadSettings, refreshDeps]);

  useEffect(() => setDraft(settings), [settings]);

  const missing = missingAny();
  const handleInstall = (tools: string[]) => install(tools);

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
    </div>
  );
};

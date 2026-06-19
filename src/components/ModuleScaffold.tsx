// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/ModuleScaffold.tsx
// Kerangka dua-panel: form di kiri, terminal + hasil di kanan (tab).
// State scan dibaca dari store global agar bertahan lintas-navigasi.
import React, { useEffect, useState } from "react";
import { ScanConsole, type ScanConsoleHandle } from "./ScanConsole";
import { type IconComp } from "../lib/icons";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";

interface Props {
  title: string;
  description: string;
  icon: IconComp;
  module: string;
  form: React.ReactNode;
  consoleRef: React.RefObject<ScanConsoleHandle>;
  renderResult?: (result: any) => React.ReactNode;
  customTabs?: { id: string; label: string; render: () => React.ReactNode }[];
}

export const ModuleScaffold: React.FC<Props> = ({
  title,
  description,
  icon: Icon,
  module,
  form,
  consoleRef,
  renderResult,
  customTabs,
}) => {
  const [tab, setTab] = useState<string>("terminal");
  const scan = useScanRuntimeStore((s) => s.scans[module]);
  const result = scan?.result ?? null;
  const running = scan?.running ?? false;

  // Pindah otomatis ke tab Hasil saat hasil tersedia.
  useEffect(() => {
    if (result && renderResult) setTab("result");
  }, [result, renderResult]);

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-3.5 border-b border-nexus-hairline px-7 py-5">
        <div className="rounded-xl bg-nexus-accent/15 p-2.5">
          <Icon className="h-6 w-6 text-nexus-accent" />
        </div>
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-nexus-text">{title}</h1>
          <p className="text-xs text-nexus-muted">{description}</p>
        </div>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-0 lg:grid-cols-[400px_1fr]">
        <div className="overflow-auto border-r border-nexus-hairline p-6">{form}</div>

        <div className="flex min-h-0 flex-col">
          <div className="flex gap-1 border-b border-nexus-hairline bg-nexus-surface px-3 pt-2">
            <button
              className={`rounded-t-lg px-4 py-2 text-sm transition-colors ${
                tab === "terminal"
                  ? "border-b-2 border-nexus-accent text-nexus-text"
                  : "text-nexus-muted hover:text-nexus-text"
              }`}
              onClick={() => setTab("terminal")}
            >
              Terminal
            </button>
            {renderResult && (
              <button
                className={`rounded-t-lg px-4 py-2 text-sm transition-colors ${
                  tab === "result"
                    ? "border-b-2 border-nexus-accent text-nexus-text"
                    : "text-nexus-muted hover:text-nexus-text"
                }`}
                onClick={() => setTab("result")}
              >
                Hasil
              </button>
            )}
            {customTabs?.map((t) => (
              <button
                key={t.id}
                className={`rounded-t-lg px-4 py-2 text-sm transition-colors ${
                  tab === t.id
                    ? "border-b-2 border-nexus-accent text-nexus-text"
                    : "text-nexus-muted hover:text-nexus-text"
                }`}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div className="relative min-h-0 flex-1">
            <div className={`absolute inset-0 ${tab === "terminal" ? "" : "hidden"}`}>
              <ScanConsole ref={consoleRef} module={module} />
            </div>
            {renderResult && (
              <div className={`absolute inset-0 overflow-auto p-5 ${tab === "result" ? "" : "hidden"}`}>
                {result ? (
                  renderResult(result)
                ) : (
                  <p className="text-sm text-nexus-muted">
                    {running ? "Scan sedang berjalan..." : "Belum ada hasil. Jalankan scan dulu."}
                  </p>
                )}
              </div>
            )}
            {customTabs?.map((t) => (
              <div key={t.id} className={`absolute inset-0 overflow-auto ${tab === t.id ? "" : "hidden"}`}>
                {t.render()}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

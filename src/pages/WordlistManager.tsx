// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/WordlistManager.tsx — SDD v2 §5.18.
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { ResultTable } from "../components/ResultTable";
import { runToolJson, isTauri } from "../lib/tauri";

export const WordlistManager: React.FC = () => {
  const [local, setLocal] = useState<any[]>([]);
  const [sources, setSources] = useState<string[]>([]);
  const [busy, setBusy] = useState<string>("");
  const [note, setNote] = useState("");

  const load = async () => {
    if (!isTauri()) return;
    try {
      const res = await runToolJson<any>("wordlist", ["--submode", "list"]);
      setLocal(res.local || []);
      setSources(res.sources || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const download = async (name: string) => {
    setBusy(name);
    setNote("");
    try {
      const res = await runToolJson<any>("wordlist", ["--submode", "download", "--name", name]);
      setLocal(res.local || []);
      setNote(res.result?.ok ? `Tersimpan: ${name}.txt` : `Gagal: ${res.result?.error || "?"}`);
    } catch (e: any) {
      setNote("Gagal: " + e);
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="mx-auto max-w-5xl animate-fade-in p-6">
      <header className="mb-5 flex items-center gap-3">
        <div className="bg-nexus-accent/15 p-2">
          <Ic.wordlistMgr className="h-5 w-5 text-nexus-accent" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-nexus-text">Wordlist Manager</h1>
          <p className="text-xs text-nexus-muted">Download & update wordlist resmi dari SecLists</p>
        </div>
      </header>

      {note && (
        <p className="mb-4 border border-nexus-hairline bg-nexus-panel px-3 py-2 text-xs text-nexus-muted">
          {note}
        </p>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="nx-card">
          <h2 className="nx-section mb-3">Sumber (SecLists)</h2>
          <div className="space-y-2">
            {sources.map((s) => (
              <div
                key={s}
                className="flex items-center justify-between border border-nexus-hairline bg-nexus-bg px-3 py-2"
              >
                <span className="font-mono text-xs text-nexus-text">{s}</span>
                <button
                  className="nx-btn-ghost px-2.5 py-1 text-[11px]"
                  onClick={() => download(s)}
                  disabled={!!busy}
                >
                  {busy === s ? (
                    <Ic.refresh className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Ic.download className="h-3.5 w-3.5" />
                  )}
                  Download
                </button>
              </div>
            ))}
            {sources.length === 0 && (
              <p className="text-xs text-nexus-muted">Memuat sumber...</p>
            )}
          </div>
        </div>

        <div>
          <h2 className="nx-section mb-3">Wordlist Lokal</h2>
          <ResultTable
            rows={local}
            csvName="wordlists.csv"
            empty="Belum ada wordlist lokal."
            columns={[
              { key: "name", header: "Nama" },
              { key: "lines", header: "Baris" },
              { key: "size_kb", header: "Ukuran (KB)" },
            ]}
          />
        </div>
      </div>
    </div>
  );
};

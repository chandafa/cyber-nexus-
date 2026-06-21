// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/DirFuzzer.tsx — Directory / Web Fuzzing.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";

const statusColor = (code: number): string => {
  if (code >= 200 && code < 300) return "text-emerald-400";
  if (code >= 300 && code < 400) return "text-sky-400";
  if (code === 401 || code === 403) return "text-amber-400";
  return "text-nexus-muted";
};

export const DirFuzzer: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [url, setUrl] = useState("http://example.com");
  const [wordlist, setWordlist] = useState("");
  const [extensions, setExtensions] = useState("php,txt,html");

  const run = () =>
    consoleRef.current?.start({
      command: "dir_fuzz",
      args: buildArgs({ target: url, wordlist, extensions }),
      module: "dir_fuzz",
      target: url,
    });

  return (
    <ModuleScaffold
      title="Directory / Web Fuzzing"
      description="Temukan direktori & file tersembunyi pada target web"
      icon={Ic.search}
      consoleRef={consoleRef}
      module="dir_fuzz"
      renderResult={(r) => (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2">
            <div className="nx-card text-center">
              <div className="text-xl font-bold">{r.total ?? 0}</div>
              <div className="text-xs text-nexus-muted">Ditemukan</div>
            </div>
            <div className="nx-card text-center">
              <div className="text-xl font-bold">{r.tested ?? 0}</div>
              <div className="text-xs text-nexus-muted">Diuji</div>
            </div>
          </div>
          <ResultTable
            csvName="dirfuzz.csv"
            rows={r.found || []}
            columns={[
              {
                key: "status",
                header: "Status",
                render: (row) => (
                  <span className={`font-mono font-semibold ${statusColor(Number(row.status))}`}>
                    {row.status}
                  </span>
                ),
              },
              { key: "path", header: "Path", render: (row) => <span className="font-mono">{row.path}</span> },
              { key: "length", header: "Length", render: (row) => (row.length ?? "-") },
              { key: "type", header: "Type" },
            ]}
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Target URL</label>
            <input
              className="nx-input font-mono"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://example.com"
            />
          </div>
          <div>
            <label className="nx-label">Wordlist (opsional)</label>
            <input
              className="nx-input font-mono"
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              placeholder="path/ke/wordlist.txt — kosongkan untuk daftar bawaan"
            />
          </div>
          <div>
            <label className="nx-label">Ekstensi</label>
            <input
              className="nx-input font-mono"
              value={extensions}
              onChange={(e) => setExtensions(e.target.value)}
              placeholder="php,txt,html"
            />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Mulai Fuzzing
          </button>
          <p className="text-xs text-nexus-muted">
            Fuzzer pure-Python (urllib) — hasil nyata, tanpa data demo.
          </p>
        </div>
      }
    />
  );
};

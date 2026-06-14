// src/pages/VulnScanner.tsx — SDD bagian 5.3.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { buildArgs } from "../lib/tauri";
import { severityCounts } from "../lib/parser";

const TOOLS = [
  { id: "nikto", label: "Nikto (HTTP vuln)" },
  { id: "gobuster", label: "Gobuster (dir enum)" },
  { id: "nuclei", label: "Nuclei (CVE templates)" },
];

export const VulnScanner: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [target, setTarget] = useState("http://testphp.vulnweb.com");
  const [tools, setTools] = useState<string[]>(["nikto", "gobuster", "nuclei"]);

  const toggle = (id: string) =>
    setTools((t) => (t.includes(id) ? t.filter((x) => x !== id) : [...t, id]));

  const run = () => {
    consoleRef.current?.start({
      command: "vuln_scan",
      args: buildArgs({ target, tools: tools.join(",") }),
      module: "vuln",
      target,
    });
  };

  return (
    <ModuleScaffold
      title="Vulnerability Scanner"
      description="Deteksi kerentanan web, CVE, dan enumerasi direktori"
      icon={Ic.vuln}
      consoleRef={consoleRef}
      module="vuln"
      renderResult={(r) => {
        const counts = severityCounts(r.vulnerabilities || []);
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-5 gap-2">
              {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                <div key={s} className="nx-card text-center">
                  <div className="text-xl font-bold">{counts[s]}</div>
                  <SeverityBadge severity={s} />
                </div>
              ))}
            </div>
            <ResultTable
              csvName={`vulns_${r.target}.csv`}
              rows={r.vulnerabilities || []}
              columns={[
                { key: "severity", header: "Severity", render: (v) => <SeverityBadge severity={v.severity} /> },
                { key: "vuln_id", header: "ID" },
                { key: "title", header: "Judul" },
                { key: "url", header: "URL" },
              ]}
            />
            {(r.directories?.length ?? 0) > 0 && (
              <div>
                <h3 className="mb-2 text-sm font-semibold text-nexus-text">
                  Direktori ditemukan ({r.directories.length})
                </h3>
                <ResultTable
                  rows={(r.directories as string[]).map((d) => ({ path: d }))}
                  columns={[{ key: "path", header: "Path" }]}
                  csvName="directories.csv"
                />
              </div>
            )}
          </div>
        );
      }}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Target URL</label>
            <input
              className="nx-input font-mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="http://example.com"
            />
          </div>
          <div>
            <label className="nx-label">Tools</label>
            <div className="space-y-2">
              {TOOLS.map((t) => (
                <label
                  key={t.id}
                  className="flex cursor-pointer items-center gap-2 rounded-lg border border-nexus-border bg-nexus-bg px-3 py-2 text-sm"
                >
                  <input
                    type="checkbox"
                    checked={tools.includes(t.id)}
                    onChange={() => toggle(t.id)}
                    className="accent-nexus-accent"
                  />
                  {t.label}
                </label>
              ))}
            </div>
          </div>
          <button className="nx-btn-primary w-full" onClick={run} disabled={tools.length === 0}>
            <Ic.play className="h-4 w-4" /> Mulai Scan
          </button>
        </div>
      }
    />
  );
};

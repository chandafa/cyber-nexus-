// src/pages/LogAnalyzer.tsx — SDD bagian 5.5.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { Select } from "../components/Select";
import { open } from "@tauri-apps/plugin-dialog";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { buildArgs, isTauri } from "../lib/tauri";

const TYPES = [
  { value: "auto", label: "Deteksi otomatis" },
  { value: "auth", label: "auth.log (SSH/sudo)" },
  { value: "syslog", label: "syslog" },
  { value: "apache", label: "Apache/Nginx access.log" },
  { value: "firewall", label: "iptables/ufw log" },
];

export const LogAnalyzer: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [logPath, setLogPath] = useState("");
  const [logType, setLogType] = useState("auto");

  const browse = async () => {
    if (!isTauri()) return;
    const selected = await open({ multiple: false, title: "Pilih file log" });
    if (typeof selected === "string") setLogPath(selected);
  };

  const run = () => {
    consoleRef.current?.start({
      command: "log_analyze",
      args: buildArgs({ log_path: logPath, log_type: logType }),
      module: "log",
      target: logPath || "(demo)",
    });
  };

  return (
    <ModuleScaffold
      title="Log Analyzer"
      description="Deteksi anomali & pola serangan dari file log"
      icon={Ic.log}
      consoleRef={consoleRef}
      module="log"
      renderResult={(r) => (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {Object.entries(r.by_severity || {}).map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-2 rounded-lg border border-nexus-border px-3 py-1.5">
                <SeverityBadge severity={sev} />
                <span className="text-sm font-semibold">{count as number}</span>
              </div>
            ))}
          </div>
          <ResultTable
            csvName="anomalies.csv"
            rows={r.anomalies || []}
            columns={[
              { key: "severity", header: "Severity", render: (a) => <SeverityBadge severity={a.severity} /> },
              { key: "attack_type", header: "Tipe Serangan" },
              { key: "source_ip", header: "Source IP" },
              { key: "raw_line", header: "Detail" },
            ]}
            empty="Tidak ada anomali terdeteksi."
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">File Log</label>
            <div className="flex gap-2">
              <input
                className="nx-input font-mono"
                value={logPath}
                onChange={(e) => setLogPath(e.target.value)}
                placeholder="kosongkan untuk mode demo"
              />
              <button className="nx-btn-ghost px-3" onClick={browse} title="Browse">
                <Ic.folder className="h-4 w-4" />
              </button>
            </div>
          </div>
          <div>
            <label className="nx-label">Tipe Log</label>
            <Select value={logType} onChange={setLogType} options={TYPES} />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Analisis Log
          </button>
          <div className="rounded-lg border border-nexus-border bg-nexus-bg p-3 text-xs text-nexus-muted">
            <p className="mb-1 font-semibold text-nexus-text">Pola yang dideteksi:</p>
            SSH Brute Force · Port Scan · SQL Injection · Directory Traversal · Privilege Escalation · Flood
          </div>
        </div>
      }
    />
  );
};

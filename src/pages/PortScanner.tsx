// src/pages/PortScanner.tsx — SDD bagian 5.2.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { Select } from "../components/Select";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";
import { useScanStore } from "../app/store/scan.store";

const MODES = [
  { value: "quick", label: "Quick Scan", hint: "nmap -T4 -F — top 100 port (~10s)" },
  { value: "standard", label: "Standard Scan", hint: "nmap -sV -sC — versi + default scripts" },
  { value: "os", label: "OS Detection", hint: "nmap -O -sV — deteksi OS" },
  { value: "full", label: "Full Scan", hint: "nmap -p- -sV -O — semua port" },
  { value: "vuln", label: "Vuln Scan", hint: "nmap --script=vuln" },
  { value: "stealth", label: "Stealth SYN", hint: "nmap -sS -T2 (butuh root)" },
  { value: "udp", label: "UDP Scan", hint: "nmap -sU port umum" },
];

export const PortScanner: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [target, setTarget] = useState("scanme.nmap.org");
  const [mode, setMode] = useState("standard");

  const run = () => {
    consoleRef.current?.start({
      command: "port_scan",
      args: buildArgs({ target, mode }),
      module: "port",
      target,
      mode,
    });
  };

  return (
    <ModuleScaffold
      title="Port Scanner"
      description="Scan port, deteksi OS & versi layanan dengan Nmap"
      icon={Ic.port}
      consoleRef={consoleRef}
      module="port"
      renderResult={(r) => (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <Stat label="Host" value={r.hostname || r.target} />
            <Stat label="Status" value={r.status} />
            <Stat label="OS" value={r.os_guess} />
          </div>
          <ResultTable
            csvName={`ports_${r.target}.csv`}
            rows={r.ports || []}
            columns={[
              { key: "port", header: "Port" },
              { key: "protocol", header: "Proto" },
              { key: "state", header: "State" },
              { key: "service", header: "Service" },
              { key: "version", header: "Version" },
            ]}
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Target (IP / domain / CIDR)</label>
            <input
              className="nx-input font-mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.1"
            />
          </div>
          <div>
            <label className="nx-label">Mode Scan</label>
            <Select value={mode} onChange={setMode} options={MODES} />
            <p className="mt-1.5 text-xs text-nexus-muted">
              {MODES.find((m) => m.value === mode)?.hint}
            </p>
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Mulai Scan
          </button>
        </div>
      }
    />
  );
};

const Stat: React.FC<{ label: string; value?: string }> = ({ label, value }) => (
  <div className="nx-card">
    <div className="text-xs text-nexus-muted">{label}</div>
    <div className="truncate font-mono text-sm text-nexus-text" title={value}>
      {value || "-"}
    </div>
  </div>
);

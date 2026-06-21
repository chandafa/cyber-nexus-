// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/DefenseMonitor.tsx — SDD bagian 5.6.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { Select } from "../components/Select";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";

const CHECKS = [
  { value: "all", label: "Semua Pemeriksaan" },
  { value: "firewall", label: "Firewall Rules" },
  { value: "ports", label: "Open Port Audit" },
  { value: "ssh", label: "SSH Hardening" },
  { value: "suid", label: "SUID/SGID Finder" },
  { value: "lynis", label: "Lynis System Audit" },
];

export const DefenseMonitor: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [submode, setSubmode] = useState("all");

  const run = () => {
    consoleRef.current?.start({
      command: "defense_check",
      args: buildArgs({ submode }),
      module: "defense",
      mode: submode,
    });
  };

  return (
    <ModuleScaffold
      title="Defense Monitor"
      description="Audit postur keamanan sistem & hardening check"
      icon={Ic.defense}
      consoleRef={consoleRef}
      module="defense"
      renderResult={(r) => (
        <div className="space-y-5">
          {r.lynis && (
            <div className="nx-card">
              <div className="text-xs text-nexus-muted">Hardening Index (Lynis)</div>
              <div className="mt-1 flex items-center gap-3">
                <div className="text-3xl font-bold text-nexus-accent2">{r.lynis.hardening_index}</div>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-nexus-border">
                  <div
                    className="h-full bg-nexus-accent2"
                    style={{ width: `${r.lynis.hardening_index}%` }}
                  />
                </div>
              </div>
            </div>
          )}
          {r.ssh_checks && (
            <div>
              <h3 className="mb-2 text-sm font-semibold text-nexus-text">SSH Hardening</h3>
              <ResultTable
                rows={r.ssh_checks}
                csvName="ssh_hardening.csv"
                columns={[
                  {
                    key: "passed",
                    header: "Status",
                    render: (c) => (
                      <span className={c.passed ? "text-green-400" : "text-red-300"}>
                        {c.passed ? "OK" : "WARN"}
                      </span>
                    ),
                  },
                  { key: "check", header: "Parameter" },
                  { key: "current", header: "Saat ini" },
                  { key: "recommendation", header: "Rekomendasi" },
                ]}
              />
            </div>
          )}
          {r.open_ports && (
            <Listing title="Open Ports" rows={r.open_ports} />
          )}
          {r.firewall && <Listing title="Firewall Rules" rows={r.firewall} />}
          {r.suid_files && <Listing title="SUID/SGID Files" rows={r.suid_files} />}
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Jenis Pemeriksaan</label>
            <Select value={submode} onChange={setSubmode} options={CHECKS} />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Jalankan Audit
          </button>
          <p className="text-xs text-nexus-muted">
            Beberapa pemeriksaan (iptables, SUID) optimal di Linux dan butuh privilege admin.
          </p>
        </div>
      }
    />
  );
};

const Listing: React.FC<{ title: string; rows: string[] }> = ({ title, rows }) => (
  <div>
    <h3 className="mb-2 text-sm font-semibold text-nexus-text">{title}</h3>
    <pre className="max-h-56 overflow-auto rounded-lg border border-nexus-border bg-nexus-bg p-3 font-mono text-xs text-nexus-green">
      {(rows || []).join("\n")}
    </pre>
  </div>
);

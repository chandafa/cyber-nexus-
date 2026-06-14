// src/pages/CloudChecker.tsx — SDD v2 §5.13.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { Select } from "../components/Select";
import { ResultTable } from "../components/ResultTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { buildArgs } from "../lib/tauri";

export const CloudChecker: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [provider, setProvider] = useState("aws");

  const run = () =>
    consoleRef.current?.start({
      command: "cloud_check",
      args: buildArgs({ provider }),
      module: "cloud",
      target: provider,
    });

  return (
    <ModuleScaffold
      title="Cloud Config Checker"
      description="Cek misconfiguration AWS/Azure/GCP (Prowler)"
      icon={Ic.cloud}
      consoleRef={consoleRef}
      module="cloud"
      renderResult={(r) => (
        <ResultTable
          csvName={`cloud_${r.provider}.csv`}
          rows={r.findings || []}
          empty="Tidak ada temuan."
          columns={[
            { key: "severity", header: "Sev", render: (f) => <SeverityBadge severity={f.severity} /> },
            { key: "title", header: "Temuan" },
            { key: "resource", header: "Resource" },
            { key: "remediation", header: "Remediasi" },
          ]}
        />
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Provider</label>
            <Select
              value={provider}
              onChange={setProvider}
              options={[
                { value: "aws", label: "AWS" },
                { value: "azure", label: "Azure" },
                { value: "gcp", label: "GCP" },
              ]}
            />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Cek Konfigurasi
          </button>
          <p className="text-xs text-nexus-muted">
            Memakai kredensial read-only milik Anda yang sudah dikonfigurasi di sistem.
          </p>
        </div>
      }
    />
  );
};

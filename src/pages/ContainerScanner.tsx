// src/pages/ContainerScanner.tsx — SDD v2 §5.12.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { buildArgs } from "../lib/tauri";

export const ContainerScanner: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [image, setImage] = useState("nginx:latest");

  const run = () =>
    consoleRef.current?.start({
      command: "container_scan",
      args: buildArgs({ image }),
      module: "container",
      target: image,
    });

  return (
    <ModuleScaffold
      title="Container Scanner"
      description="Scan vulnerability image Docker (Trivy)"
      icon={Ic.container}
      consoleRef={consoleRef}
      module="container"
      renderResult={(r) => (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-2">
            {(["critical", "high", "medium"] as const).map((s) => (
              <div key={s} className="nx-card text-center">
                <div className="text-xl font-bold">{r.by_severity?.[s] ?? 0}</div>
                <SeverityBadge severity={s} />
              </div>
            ))}
          </div>
          <ResultTable
            csvName="container_vulns.csv"
            rows={r.vulnerabilities || []}
            columns={[
              { key: "severity", header: "Sev", render: (v) => <SeverityBadge severity={v.severity} /> },
              { key: "vuln_id", header: "CVE" },
              { key: "package", header: "Package" },
              { key: "installed_version", header: "Versi" },
              { key: "fixed_version", header: "Fixed" },
            ]}
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Nama Image</label>
            <input className="nx-input font-mono" value={image} onChange={(e) => setImage(e.target.value)} />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Scan Image
          </button>
          <p className="text-xs text-nexus-muted">Membutuhkan Docker berjalan untuk image nyata.</p>
        </div>
      }
    />
  );
};

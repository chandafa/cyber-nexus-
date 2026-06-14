// src/pages/SslAuditor.tsx — SDD v2 §5.7.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";

const STATUS_CLS: Record<string, string> = {
  ok: "text-nexus-green",
  warning: "text-severity-medium",
  critical: "text-severity-critical",
};

export const SslAuditor: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [target, setTarget] = useState("example.com");
  const [port, setPort] = useState("443");

  const run = () =>
    consoleRef.current?.start({
      command: "ssl_audit",
      args: buildArgs({ target, port }),
      module: "ssl",
      target,
    });

  return (
    <ModuleScaffold
      title="SSL/TLS Auditor"
      description="Audit cipher, sertifikat & protokol deprecated (sslyze)"
      icon={Ic.ssl}
      consoleRef={consoleRef}
      module="ssl"
      renderResult={(r) => (
        <div className="space-y-4">
          <div className="flex gap-3">
            <div className="nx-card">
              <div className="text-xs text-nexus-muted">Temuan Kritis</div>
              <div className="text-2xl font-bold text-severity-critical">{r.critical_count ?? 0}</div>
            </div>
            <div className="nx-card">
              <div className="text-xs text-nexus-muted">Total Temuan</div>
              <div className="text-2xl font-bold text-nexus-text">{r.total ?? 0}</div>
            </div>
          </div>
          <ResultTable
            csvName={`tls_${r.target}.csv`}
            rows={r.findings || []}
            columns={[
              {
                key: "status",
                header: "Status",
                render: (f) => (
                  <span className={`font-semibold uppercase ${STATUS_CLS[f.status] || ""}`}>
                    {f.status}
                  </span>
                ),
              },
              { key: "category", header: "Kategori" },
              { key: "name", header: "Item" },
              { key: "detail", header: "Detail" },
            ]}
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Target (host)</label>
            <input className="nx-input font-mono" value={target} onChange={(e) => setTarget(e.target.value)} />
          </div>
          <div>
            <label className="nx-label">Port</label>
            <input className="nx-input font-mono" value={port} onChange={(e) => setPort(e.target.value)} />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Audit TLS
          </button>
        </div>
      }
    />
  );
};

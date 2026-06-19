// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/ApiTester.tsx — SDD v2 §5.10.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { Select } from "../components/Select";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";

export const ApiTester: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [target, setTarget] = useState("http://demo.test");
  const [submode, setSubmode] = useState("endpoints");

  const run = () =>
    consoleRef.current?.start({
      command: "api_test",
      args: buildArgs({ target, submode }),
      module: "api",
      target,
    });

  return (
    <ModuleScaffold
      title="API Security Tester"
      description="Fuzzing endpoint REST + GraphQL introspection (ffuf)"
      icon={Ic.api}
      consoleRef={consoleRef}
      module="api"
      renderResult={(r) => (
        <div className="space-y-4">
          {r.graphql && (
            <div className="nx-card">
              <div className="text-xs text-nexus-muted">GraphQL Introspection</div>
              <div className="mt-1 text-sm text-nexus-text">
                {r.graphql.introspection_enabled ? (
                  <span className="text-severity-medium">
                    Aktif — {r.graphql.type_count} tipe schema bocor. {r.graphql.recommendation}
                  </span>
                ) : (
                  <span className="text-nexus-green">Nonaktif (aman)</span>
                )}
              </div>
            </div>
          )}
          <ResultTable
            csvName="api_endpoints.csv"
            rows={r.endpoints || []}
            empty="Tidak ada endpoint ditemukan."
            columns={[
              { key: "status", header: "Status" },
              { key: "url", header: "URL" },
              { key: "length", header: "Size" },
            ]}
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Base URL API</label>
            <input className="nx-input font-mono" value={target} onChange={(e) => setTarget(e.target.value)} />
          </div>
          <div>
            <label className="nx-label">Mode</label>
            <Select
              value={submode}
              onChange={setSubmode}
              options={[
                { value: "endpoints", label: "Endpoint Discovery" },
                { value: "graphql", label: "GraphQL Introspection" },
              ]}
            />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Mulai Test
          </button>
        </div>
      }
    />
  );
};

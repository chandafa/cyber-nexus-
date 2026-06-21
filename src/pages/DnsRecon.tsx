// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/DnsRecon.tsx — Subdomain / DNS Recon.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";

export const DnsRecon: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [domain, setDomain] = useState("example.com");
  const [wordlist, setWordlist] = useState("");

  const run = () =>
    consoleRef.current?.start({
      command: "dns_recon",
      args: buildArgs({ domain, wordlist }),
      module: "dns_recon",
      target: domain,
    });

  return (
    <ModuleScaffold
      title="Subdomain / DNS Recon"
      description="Enumerasi subdomain & DNS (tanpa tool eksternal)"
      icon={Ic.network}
      consoleRef={consoleRef}
      module="dns_recon"
      renderResult={(r) => (
        <div className="space-y-4">
          <div className="nx-card text-center">
            <div className="text-xl font-bold">{r.total ?? 0}</div>
            <div className="text-xs text-nexus-muted">Subdomain aktif</div>
          </div>
          <ResultTable
            csvName="subdomains.csv"
            rows={r.subdomains || []}
            columns={[
              { key: "subdomain", header: "Subdomain" },
              { key: "ip", header: "IP" },
            ]}
          />
          <ResultTable
            csvName="dns_records.csv"
            rows={r.records || []}
            columns={[
              { key: "type", header: "Type" },
              { key: "name", header: "Name" },
              { key: "value", header: "Value" },
            ]}
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Domain</label>
            <input
              className="nx-input font-mono"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
            />
          </div>
          <div>
            <label className="nx-label">Wordlist (opsional, path file)</label>
            <input
              className="nx-input font-mono"
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              placeholder="kosongkan untuk daftar bawaan"
            />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Mulai Recon
          </button>
          <p className="text-xs text-nexus-muted">
            Resolusi DNS nyata via Python stdlib (socket). Tanpa tool eksternal.
          </p>
        </div>
      }
    />
  );
};

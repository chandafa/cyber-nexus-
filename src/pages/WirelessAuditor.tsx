// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/WirelessAuditor.tsx — SDD v2 §5.11.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs } from "../lib/tauri";

const RATING_CLS: Record<string, string> = {
  ok: "text-nexus-green",
  warning: "text-severity-medium",
  critical: "text-severity-critical",
};

export const WirelessAuditor: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [iface, setIface] = useState("wlan0");

  const run = () =>
    consoleRef.current?.start({
      command: "wireless_scan",
      args: buildArgs({ interface: iface, duration: 12 }),
      module: "wireless",
      target: iface,
    });

  return (
    <ModuleScaffold
      title="Wireless Auditor"
      description="Audit keamanan WiFi (aircrack-ng, butuh adapter monitor)"
      icon={Ic.wireless}
      consoleRef={consoleRef}
      module="wireless"
      renderResult={(r) => (
        <div className="space-y-3">
          <div className="nx-card">
            <div className="text-xs text-nexus-muted">Jaringan lemah/terbuka</div>
            <div className="text-2xl font-bold text-severity-critical">{r.weak_count ?? 0}</div>
          </div>
          <ResultTable
            csvName="wifi.csv"
            rows={(r.networks || []).map((n: any) => ({
              essid: n.essid,
              bssid: n.bssid,
              channel: n.channel,
              encryption: n.encryption,
              rating: n.assessment?.rating,
              note: n.assessment?.note,
            }))}
            columns={[
              { key: "essid", header: "SSID" },
              { key: "channel", header: "CH" },
              { key: "encryption", header: "Enkripsi" },
              {
                key: "rating",
                header: "Nilai",
                render: (n) => (
                  <span className={`font-semibold uppercase ${RATING_CLS[n.rating] || ""}`}>{n.rating}</span>
                ),
              },
              { key: "note", header: "Catatan" },
            ]}
          />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Interface WiFi</label>
            <input className="nx-input font-mono" value={iface} onChange={(e) => setIface(e.target.value)} />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Scan WiFi
          </button>
          <p className="rounded border border-yellow-500/30 bg-severity-medium/10 px-3 py-2 text-xs text-yellow-200">
            Audit hanya jaringan WiFi milik sendiri. Butuh adapter mode monitor (Linux).
          </p>
        </div>
      }
    />
  );
};

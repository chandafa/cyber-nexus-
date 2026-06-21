// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NetworkScanner.tsx — SDD bagian 5.1.
import React, { useEffect, useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { Select } from "../components/Select";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { buildArgs, listInterfaces, isTauri } from "../lib/tauri";

const PROTO_FILTERS = [
  { value: "", label: "Semua" },
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "port 80 or port 443", label: "HTTP/HTTPS" },
  { value: "port 53", label: "DNS" },
  { value: "arp", label: "ARP" },
];

export const NetworkScanner: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [iface, setIface] = useState("");
  const [filter, setFilter] = useState("");
  const [limit, setLimit] = useState("40");

  const loadIfaces = async () => {
    if (!isTauri()) {
      setInterfaces(["(preview) interface tidak tersedia tanpa Tauri"]);
      return;
    }
    try {
      const { interfaces } = await listInterfaces();
      setInterfaces(interfaces);
      if (interfaces.length && !interfaces.includes(iface)) setIface(interfaces[0]);
    } catch {
      setInterfaces(["(gagal memuat interface)"]);
    }
  };

  useEffect(() => {
    loadIfaces();
  }, []);

  const run = () => {
    consoleRef.current?.start({
      command: "network_scan",
      args: buildArgs({ interface: iface, filter, packet_limit: limit }),
      module: "network",
      target: iface,
    });
  };

  return (
    <ModuleScaffold
      title="Network Scanner"
      description="Live packet capture & analisis traffic dengan tshark"
      icon={Ic.network}
      consoleRef={consoleRef}
      module="network"
      renderResult={(r) => (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="nx-card">
              <div className="text-xs text-nexus-muted">Total Paket</div>
              <div className="text-2xl font-bold text-nexus-accent2">{r.packets ?? 0}</div>
            </div>
            <div className="nx-card">
              <div className="text-xs text-nexus-muted">Total Bytes</div>
              <div className="text-2xl font-bold text-nexus-accent">{r.bytes ?? 0}</div>
            </div>
          </div>
          <div>
            <h3 className="mb-2 text-sm font-semibold text-nexus-text">Top Talkers</h3>
            <ResultTable
              rows={r.top_talkers || []}
              csvName="top_talkers.csv"
              columns={[
                { key: "ip", header: "IP Address" },
                { key: "count", header: "Jumlah Paket" },
              ]}
            />
          </div>
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <label className="nx-label">Interface Jaringan</label>
              <button className="inline-flex items-center gap-1 text-xs text-nexus-accent2" onClick={loadIfaces}>
                <Ic.refresh className="h-3 w-3" /> refresh
              </button>
            </div>
            <Select
              value={iface}
              onChange={setIface}
              options={interfaces.map((it) => ({ value: it, label: it }))}
            />
          </div>
          <div>
            <label className="nx-label">Filter Protokol (BPF)</label>
            <Select value={filter} onChange={setFilter} options={PROTO_FILTERS} />
          </div>
          <div>
            <label className="nx-label">Batas Paket</label>
            <input
              className="nx-input"
              type="number"
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
            />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Mulai Capture
          </button>
          <p className="text-xs text-nexus-muted">
            tshark butuh hak akses admin/root untuk capture pada interface nyata.
          </p>
        </div>
      }
    />
  );
};

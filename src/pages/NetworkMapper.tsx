// src/pages/NetworkMapper.tsx — SDD modul #6.
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { TopologyMap } from "../components/TopologyMap";
import { buildArgs } from "../lib/tauri";

export const NetworkMapper: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [target, setTarget] = useState("192.168.1.0/24");

  const run = () => {
    consoleRef.current?.start({
      command: "network_map",
      args: buildArgs({ target }),
      module: "mapper",
      target,
    });
  };

  return (
    <ModuleScaffold
      title="Network Mapper"
      description="Visualisasi topologi jaringan interaktif (host discovery)"
      icon={Ic.mapper}
      consoleRef={consoleRef}
      module="mapper"
      renderResult={(r) => (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="nx-card">
              <div className="text-xs text-nexus-muted">Host ditemukan</div>
              <div className="text-2xl font-bold text-nexus-accent2">{r.host_count ?? 0}</div>
            </div>
            <p className="text-xs text-nexus-muted">
              Node tosca = gateway, ungu = host. Drag node untuk mengatur tata letak.
            </p>
          </div>
          <TopologyMap nodes={r.nodes || []} edges={r.edges || []} />
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Target Range (CIDR)</label>
            <input
              className="nx-input font-mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.0/24"
            />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Petakan Jaringan
          </button>
          <p className="text-xs text-nexus-muted">
            Menjalankan ping sweep (nmap -sn) untuk menemukan host aktif, lalu membangun
            graf topologi.
          </p>
        </div>
      }
    />
  );
};

// src/pages/NexusAgents.tsx — Panel Manajemen Agen & Telemetri WAZUH-Style.
import React, { useEffect, useState, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Ic } from "../lib/icons";
import { isTauri } from "../lib/tauri";

interface Agent {
  ip: string;
  port: number;
  connected_at: string;
}

interface ListenerStatus {
  is_running: boolean;
  port_1514: number;
  port_1515: number;
  lan_ip?: string;
  connected_agents: Agent[];
}

interface AgentTelemetry {
  cpu?: number;
  ram?: number;
  ramDetails?: string;
  ebpfBlocked?: number;
  uptime?: string;
  ebpfActive?: boolean;
}

interface EventLog {
  ts: string;
  ip: string;
  payload: string;
}

export const NexusAgents: React.FC = () => {
  const [status, setStatus] = useState<ListenerStatus>({
    is_running: false,
    port_1514: 1514,
    port_1515: 1515,
    connected_agents: [],
  });

  const [portData, setPortData] = useState("1514");
  const [portEnroll, setPortEnroll] = useState("1515");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [selectedAgentIp, setSelectedAgentIp] = useState<string | null>(null);
  const [agentMetrics, setAgentMetrics] = useState<Record<string, AgentTelemetry>>({});
  const [events, setEvents] = useState<EventLog[]>([]);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  const fetchStatus = async () => {
    if (!isTauri()) {
      setLoading(false);
      return;
    }
    try {
      const res = await invoke<any>("get_nexus_listener_status");
      setStatus({
        is_running: res.is_running,
        port_1514: res.port_1514,
        port_1515: res.port_1515,
        lan_ip: res.lan_ip,
        connected_agents: res.connected_agents || [],
      });
      setPortData(String(res.port_1514));
      setPortEnroll(String(res.port_1515));
      setError(null);
    } catch (err: any) {
      console.error(err);
      setError(err?.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();

    let unlistenConnected: any;
    let unlistenDisconnected: any;
    let unlistenEvent: any;
    let unlistenStopped: any;

    const setupListeners = async () => {
      if (!isTauri()) return;

      unlistenConnected = await listen<any>("nexus-agent-connected", (event) => {
        const agent = event.payload;
        setStatus((prev) => ({
          ...prev,
          connected_agents: [...prev.connected_agents.filter((a) => a.ip !== agent.ip), agent],
        }));
        
        // Log event
        addEventLog(agent.ip, `[SYSTEM] Agen terhubung dari port ${agent.port}`);
      });

      unlistenDisconnected = await listen<string>("nexus-agent-disconnected", (event) => {
        const ip = event.payload;
        setStatus((prev) => ({
          ...prev,
          connected_agents: prev.connected_agents.filter((a) => a.ip !== ip),
        }));
        
        // Clear selection if deleted
        setSelectedAgentIp((prev) => (prev === ip ? null : prev));

        addEventLog(ip, `[SYSTEM] Agen terputus dari Manager.`);
      });

      unlistenEvent = await listen<any>("nexus-agent-event", (event) => {
        const { ip, payload, ts } = event.payload;
        addEventLog(ip, payload);

        // Parse telemetry if heartbeat
        if (payload.includes("HEARTBEAT STATS:")) {
          const metrics = parseTelemetry(payload);
          if (metrics) {
            setAgentMetrics((prev) => {
              const current = prev[ip] || {};
              return {
                ...prev,
                [ip]: {
                  ...current,
                  ...metrics,
                },
              };
            });
          }
        }
      });

      unlistenStopped = await listen("nexus-listener-stopped", () => {
        setStatus((prev) => ({
          ...prev,
          is_running: false,
          connected_agents: [],
        }));
        setSelectedAgentIp(null);
        addEventLog("0.0.0.0", "[SYSTEM] Listener dihentikan secara total (PnP disarm).");
      });
    };

    setupListeners();

    return () => {
      if (unlistenConnected) unlistenConnected();
      if (unlistenDisconnected) unlistenDisconnected();
      if (unlistenEvent) unlistenEvent();
      if (unlistenStopped) unlistenStopped();
    };
  }, []);

  useEffect(() => {
    // Auto scroll console
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  const addEventLog = (ip: string, payload: string) => {
    const ts = new Date().toLocaleTimeString();
    setEvents((prev) => [...prev.slice(-199), { ts, ip, payload }]);
  };

  const parseTelemetry = (payload: string): AgentTelemetry | null => {
    try {
      const statsPart = payload.split("HEARTBEAT STATS:")[1]?.trim();
      if (!statsPart) return null;
      const parts = statsPart.split("|").map((p) => p.trim());
      const telemetry: AgentTelemetry = {};
      
      for (const part of parts) {
        if (part.startsWith("CPU:")) {
          telemetry.cpu = parseFloat(part.replace("CPU:", "").replace("%", "").trim());
        } else if (part.startsWith("RAM:")) {
          const ramStr = part.replace("RAM:", "").trim();
          telemetry.ram = parseFloat(ramStr.split("%")[0].trim());
          telemetry.ramDetails = ramStr;
        } else if (part.includes("eBPF Blocked:")) {
          telemetry.ebpfBlocked = parseInt(part.replace("eBPF Blocked:", "").replace("IPs", "").trim(), 10);
        } else if (part.startsWith("Uptime:")) {
          telemetry.uptime = part.replace("Uptime:", "").trim();
        }
      }
      return telemetry;
    } catch (e) {
      return null;
    }
  };

  const handleToggleListener = async () => {
    if (!isTauri()) return;
    setError(null);
    try {
      if (status.is_running) {
        await invoke("stop_nexus_listener");
        setStatus((prev) => ({ ...prev, is_running: false }));
      } else {
        const pData = parseInt(portData, 10);
        const pEnroll = parseInt(portEnroll, 10);
        if (isNaN(pData) || isNaN(pEnroll)) {
          throw new Error("Port harus berupa angka valid");
        }
        await invoke("start_nexus_listener", { portData: pData, portEnroll: pEnroll });
        setStatus((prev) => ({
          ...prev,
          is_running: true,
          port_1514: pData,
          port_1515: pEnroll,
        }));
        addEventLog("0.0.0.0", `[SYSTEM] Listener aktif. Mendengarkan data di port ${pData} & enrollment di port ${pEnroll}.`);
      }
    } catch (err: any) {
      setError(err?.message || String(err));
    }
  };

  const handleToggleEbpfShield = async (ip: string) => {
    if (!isTauri()) return;
    const current = agentMetrics[ip] || {};
    const nextActive = !current.ebpfActive;
    
    try {
      const command = nextActive ? "EBPF_ACTIVE:true" : "EBPF_ACTIVE:false";
      await invoke("send_nexus_agent_command", { ip, command });
      
      setAgentMetrics((prev) => ({
        ...prev,
        [ip]: {
          ...(prev[ip] || {}),
          ebpfActive: nextActive,
        },
      }));

      addEventLog(ip, `[SYSTEM] Perintah terkirim ke agen: ${command}`);
    } catch (err: any) {
      alert(`Gagal mengirim perintah: ${err?.message || String(err)}`);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const selectedMetrics = selectedAgentIp ? agentMetrics[selectedAgentIp] || {} : null;

  if (loading) {
    return (
      <div className="p-6 flex flex-col items-center justify-center h-[80vh] text-nexus-muted font-mono text-xs gap-3">
        <Ic.refresh className="h-6 w-6 animate-spin text-nexus-accent" />
        <span>Memuat panel manajemen Nexus Agent...</span>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <header className="flex items-center gap-3">
        <div className="bg-nexus-accent/15 p-2 rounded">
          <Ic.server className="h-5 w-5 text-nexus-accent" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-nexus-text font-mono">Nexus Agent Manager</h1>
          <p className="text-xs text-nexus-muted">
            Konsol pusat manajemen telemetri server remote. Menerima log eBPF, audit syscall, & kontrol eBPF shield.
          </p>
        </div>
      </header>

      {error && (
        <div className="p-4 bg-red-950/20 border border-red-900/50 rounded-xl flex items-start gap-3 font-mono text-xs">
          <Ic.alert className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-red-300">Terjadi Kesalahan di Socket Listener</h4>
            <p className="text-red-400/80 mt-1">{error}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Columns (Management & List) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Listener Settings Card */}
          <div className="nx-card p-5 space-y-4">
            <div className="flex justify-between items-center border-b border-nexus-hairline pb-2">
              <h3 className="text-xs text-nexus-muted font-mono uppercase font-semibold">Port Listener Control</h3>
              <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                status.is_running
                  ? "bg-green-950/40 text-green-300 border-green-800"
                  : "bg-nexus-panel text-nexus-subtle border-nexus-border"
              }`}>
                {status.is_running ? "Sockets Active" : "Sockets Inactive"}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
              <div>
                <label className="text-[10px] uppercase font-bold text-nexus-muted font-mono block mb-1">
                  Data Port (TCP 1514)
                </label>
                <input
                  type="text"
                  value={portData}
                  disabled={status.is_running}
                  onChange={(e) => setPortData(e.target.value)}
                  className="nx-input w-full font-mono text-xs"
                />
              </div>

              <div>
                <label className="text-[10px] uppercase font-bold text-nexus-muted font-mono block mb-1">
                  Enrollment Port (TCP 1515)
                </label>
                <input
                  type="text"
                  value={portEnroll}
                  disabled={status.is_running}
                  onChange={(e) => setPortEnroll(e.target.value)}
                  className="nx-input w-full font-mono text-xs"
                />
              </div>

              <button
                onClick={handleToggleListener}
                className={`nx-btn-primary w-full py-2 font-mono text-xs flex items-center justify-center gap-1.5 ${
                  status.is_running
                    ? "hover:bg-red-950/40 hover:text-red-300 border-red-900/50 bg-red-950/20"
                    : ""
                }`}
              >
                {status.is_running ? (
                  <>
                    <Ic.stop className="h-4 w-4" /> Stop Listener
                  </>
                ) : (
                  <>
                    <Ic.play className="h-4 w-4" /> Start Listener
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Connected Agent List */}
          <div className="nx-card p-5 space-y-4">
            <h3 className="text-xs text-nexus-muted font-mono uppercase font-semibold">
              Koneksi Agen Aktif ({status.connected_agents.length})
            </h3>
            <div className="overflow-auto border border-nexus-hairline rounded max-h-60">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-nexus-panel text-nexus-muted font-semibold">
                  <tr>
                    <th className="px-3 py-2">Host IP</th>
                    <th className="px-3 py-2">Port</th>
                    <th className="px-3 py-2">Connected At</th>
                    <th className="px-3 py-2">eBPF Shield</th>
                    <th className="px-3 py-2 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-nexus-hairline text-nexus-text">
                  {status.connected_agents.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-3 py-6 text-center text-nexus-subtle italic">
                        Belum ada agen remote terhubung. Aktifkan listener dan instal agen di VPS Anda.
                      </td>
                    </tr>
                  ) : (
                    status.connected_agents.map((agent) => {
                      const isSelected = selectedAgentIp === agent.ip;
                      const metrics = agentMetrics[agent.ip] || {};
                      return (
                        <tr
                          key={agent.ip}
                          onClick={() => setSelectedAgentIp(agent.ip)}
                          className={`hover:bg-nexus-panel/40 cursor-pointer ${
                            isSelected ? "bg-nexus-accent/10" : ""
                          }`}
                        >
                          <td className="px-3 py-2 font-bold flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse inline-block" />
                            {agent.ip}
                          </td>
                          <td className="px-3 py-2 text-nexus-muted">{agent.port}</td>
                          <td className="px-3 py-2 text-nexus-muted">{agent.connected_at}</td>
                          <td className="px-3 py-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                              metrics.ebpfActive 
                                ? "bg-green-950/40 text-green-300 border border-green-800"
                                : "bg-nexus-panel text-nexus-subtle border border-nexus-border"
                            }`}>
                              {metrics.ebpfActive ? "Shield Active" : "Shield Idle"}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-center" onClick={(e) => e.stopPropagation()}>
                            <button
                              onClick={() => handleToggleEbpfShield(agent.ip)}
                              className={`text-[10px] px-2 py-0.5 border rounded font-semibold ${
                                metrics.ebpfActive
                                  ? "text-red-400 border-red-900/50 hover:bg-red-950/20"
                                  : "text-green-400 border-green-900/50 hover:bg-green-950/20"
                              }`}
                            >
                              {metrics.ebpfActive ? "Matikan eBPF" : "Aktifkan eBPF"}
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column (Metrics & Help) */}
        <div className="space-y-6">
          {/* Agent Inspector */}
          <div className="nx-card p-5 space-y-4">
            <h3 className="text-xs text-nexus-muted font-mono uppercase font-semibold border-b border-nexus-hairline pb-2 flex items-center gap-1.5">
              <Ic.activity className="h-4 w-4 text-nexus-accent" /> Telemetri Node Agen
            </h3>
            {selectedAgentIp && selectedMetrics ? (
              <div className="space-y-4 font-mono text-xs">
                <div className="bg-nexus-panel p-2 rounded border border-nexus-border/50">
                  <div className="text-[10px] text-nexus-subtle">IP Target</div>
                  <div className="text-sm font-semibold text-nexus-text">{selectedAgentIp}</div>
                </div>

                {/* CPU meter */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-nexus-muted">CPU Usage:</span>
                    <span className="text-nexus-text font-bold">{selectedMetrics.cpu ?? 0}%</span>
                  </div>
                  <div className="h-2 bg-nexus-panel rounded-full overflow-hidden border border-nexus-border/40">
                    <div
                      className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                      style={{ width: `${selectedMetrics.cpu ?? 0}%` }}
                    />
                  </div>
                </div>

                {/* RAM meter */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-nexus-muted">Memory Usage:</span>
                    <span className="text-nexus-text font-bold">{selectedMetrics.ram ?? 0}%</span>
                  </div>
                  <div className="h-2 bg-nexus-panel rounded-full overflow-hidden border border-nexus-border/40">
                    <div
                      className="h-full bg-purple-500 rounded-full transition-all duration-500"
                      style={{ width: `${selectedMetrics.ram ?? 0}%` }}
                    />
                  </div>
                  <div className="text-[9px] text-nexus-subtle mt-0.5">
                    Detail: {selectedMetrics.ramDetails ?? "–"}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-center pt-2">
                  <div className="bg-nexus-panel p-2 rounded border border-nexus-border/30">
                    <div className="text-[9px] text-nexus-subtle uppercase">Blocked IPs</div>
                    <div className="text-sm font-bold text-red-400">{selectedMetrics.ebpfBlocked ?? 0}</div>
                  </div>
                  <div className="bg-nexus-panel p-2 rounded border border-nexus-border/30">
                    <div className="text-[9px] text-nexus-subtle uppercase">Node Uptime</div>
                    <div className="text-[11px] font-bold text-nexus-text truncate">
                      {selectedMetrics.uptime ? selectedMetrics.uptime.replace("Uptime:", "").trim() : "–"}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-10 text-nexus-subtle font-mono text-xs italic">
                Pilih salah satu IP Agen untuk menginspeksi metrik perangkat.
              </div>
            )}
          </div>

          {/* Deployment Quick Guide */}
          <div className="nx-card p-5 space-y-4">
            <h3 className="text-xs text-nexus-muted font-mono uppercase font-semibold border-b border-nexus-hairline pb-2 flex items-center gap-1.5">
              <Ic.toolsCheck className="h-4 w-4 text-nexus-accent2" /> Panduan Deployment Agen
            </h3>
            <div className="space-y-3 font-mono text-[11px] text-nexus-muted leading-relaxed">
              <p>Instalasi cepat agen pada target VPS/server Linux dengan menjalankan perintah satu baris berikut:</p>
              
              <div className="space-y-1">
                <div className="text-[10px] text-nexus-subtle">Perintah Pemasangan (Auto-configure):</div>
                <div className="bg-nexus-panel p-2 rounded border border-nexus-border/50 flex items-center justify-between gap-2">
                  <code className="text-nexus-text text-[10px] break-all select-all font-mono">
                    curl -sSL http://{status.lan_ip || "YOUR_MANAGER_LAN_IP"}:{status.port_1515}/install | sudo bash
                  </code>
                  <button
                    onClick={() => copyToClipboard(`curl -sSL http://${status.lan_ip || "YOUR_MANAGER_LAN_IP"}:${status.port_1515}/install | sudo bash`)}
                    className="nx-btn-ghost p-1 shrink-0"
                    title="Salin"
                  >
                    <Ic.copy className="h-3 w-3" />
                  </button>
                </div>
              </div>
              <p className="text-[10px] text-nexus-subtle">
                {status.lan_ip
                  ? "Jalankan satu baris di atas pada endpoint Linux/WSL target — IP Manager sudah terisi otomatis. Tak perlu menempel skrip; agen nyata akan terpasang & mendaftar sendiri."
                  : "Ganti YOUR_MANAGER_LAN_IP dengan IP LAN komputer Manager Anda. Manager menyajikan skrip instalasi offline & mengkonfigurasi agen otomatis."}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Real-time event log terminal */}
      <div className="nx-card p-5 space-y-4">
        <div className="flex justify-between items-center border-b border-nexus-hairline pb-2">
          <h3 className="text-xs text-nexus-muted font-mono uppercase font-semibold flex items-center gap-1.5">
            <Ic.terminal className="h-4 w-4 text-nexus-accent" /> Telemetry & Alert Stream (Port 1514 Sockets)
          </h3>
          <button
            onClick={() => setEvents([])}
            className="text-[10px] text-nexus-subtle hover:text-red-400 font-mono flex items-center gap-1 px-2 py-1 border border-nexus-border hover:border-red-900/50 rounded transition-all"
          >
            <Ic.trash className="h-3 w-3" /> Hapus Log
          </button>
        </div>
        <div className="bg-nexus-panel/75 border border-nexus-border/50 rounded-lg p-3 h-52 overflow-auto font-mono text-[11px] leading-relaxed text-nexus-subtle">
          {events.length === 0 ? (
            <div className="text-center py-12 text-nexus-subtle italic">
              Menunggu transmisi log telemetri dari agen remote...
            </div>
          ) : (
            events.map((evt, i) => (
              <div key={i} className="py-0.5 border-b border-nexus-hairline/10 last:border-0 hover:bg-white/5 px-1 flex gap-2">
                <span className="text-nexus-accent font-semibold shrink-0">[{evt.ts}]</span>
                <span className="text-cyan-400 font-semibold shrink-0">[{evt.ip}]</span>
                <span className="text-nexus-text break-all">{evt.payload}</span>
              </div>
            ))
          )}
          <div ref={consoleEndRef} />
        </div>
      </div>
    </div>
  );
};

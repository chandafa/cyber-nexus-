// src/pages/SystemHealth.tsx — SDD §12 System health statistics and supervisor watchdog UI
import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Ic } from "../lib/icons";

interface SystemStatus {
  cpu_usage: number;
  memory_usage: number;
  total_memory: number;
  used_memory: number;
  uptime: number;
  disk_usage: number;
  total_disk: number;
  available_disk: number;
  os_name: string;
  os_version: string;
  kernel_version: string;
}

interface SupervisorStatus {
  active_scan_id: string | null;
  is_enabled: boolean;
  auto_restarts: number;
  logs: string[];
}

export const SystemHealth: React.FC = () => {
  const [sysStatus, setSysStatus] = useState<SystemStatus | null>(null);
  const [supStatus, setSupStatus] = useState<SupervisorStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const sys = await invoke<SystemStatus>("get_system_status");
      const sup = await invoke<SupervisorStatus>("get_supervisor_status");
      setSysStatus(sys);
      setSupStatus(sup);
      setLoading(false);
    } catch (err: any) {
      console.error(err);
      setError(err?.message || String(err));
      setLoading(false);
    }
  };

  useEffect(() => {
    // Ambil data awal langsung saat mount agar tidak kosong
    fetchData();

    // Dengar update real-time dari thread Rust background (mengurangi IPC Roundtrips / Polling)
    let unlistenTelemetry: any;
    const setupTelemetryListener = async () => {
      unlistenTelemetry = await listen<{ system: SystemStatus; supervisor: SupervisorStatus }>(
        "system-telemetry",
        (event) => {
          setSysStatus(event.payload.system);
          setSupStatus(event.payload.supervisor);
          setLoading(false);
        }
      );
    };
    setupTelemetryListener();

    // Dengar event auto-restart watchdog untuk meresegarkan log
    let unlistenRestart: any;
    const setupRestartListener = async () => {
      unlistenRestart = await listen("waf-watchdog-restart", () => {
        fetchData();
      });
    };
    setupRestartListener();

    return () => {
      if (unlistenTelemetry) unlistenTelemetry();
      if (unlistenRestart) unlistenRestart();
    };
  }, []);

  const toggleSupervisor = async () => {
    if (!supStatus) return;
    try {
      const nextState = !supStatus.is_enabled;
      await invoke("set_supervisor_enabled", { enabled: nextState });
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const clearLogs = async () => {
    try {
      await invoke("clear_supervisor_logs");
      fetchData();
    } catch (err) {
      console.error(err);
    }
  };

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    
    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    parts.push(`${s}s`);
    return parts.join(" ");
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  if (loading && !sysStatus) {
    return (
      <div className="p-6 flex flex-col items-center justify-center h-[80vh] text-nexus-muted font-mono text-xs gap-3">
        <Ic.refresh className="h-6 w-6 animate-spin text-nexus-accent" />
        <span>Mengambil statistik sistem & kernel...</span>
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
          <h1 className="text-xl font-semibold text-nexus-text font-mono">System & Kernel Monitor</h1>
          <p className="text-xs text-nexus-muted">Pantau kesehatan OS, CPU, Memori, dan status Watchdog Supervisor WAF.</p>
        </div>
      </header>

      {error && (
        <div className="p-4 bg-red-950/20 border border-red-900/50 rounded-xl flex items-start gap-3">
          <Ic.alert className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
          <div>
            <h4 className="text-xs font-semibold text-red-300">Gagal Membaca Telemetri Sistem</h4>
            <p className="text-xs text-red-400/80 mt-1 font-mono">{error}</p>
          </div>
        </div>
      )}

      {sysStatus && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card CPU */}
          <div className="nx-card p-4 space-y-3 relative overflow-hidden">
            <div className="flex justify-between items-center">
              <span className="text-xs text-nexus-muted font-mono uppercase font-semibold">CPU Usage</span>
              <Ic.activity className="h-4 w-4 text-cyan-400" />
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold text-nexus-text font-mono">{sysStatus.cpu_usage.toFixed(1)}%</span>
            </div>
            <div className="w-full bg-nexus-surface h-1.5 rounded-full overflow-hidden">
              <div 
                className="bg-cyan-500 h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(6,182,212,0.6)]"
                style={{ width: `${Math.min(sysStatus.cpu_usage, 100)}%` }}
              />
            </div>
          </div>

          {/* Card Memory */}
          <div className="nx-card p-4 space-y-3 relative overflow-hidden">
            <div className="flex justify-between items-center">
              <span className="text-xs text-nexus-muted font-mono uppercase font-semibold">Memory Usage</span>
              <Ic.dashboard className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold text-nexus-text font-mono">{sysStatus.memory_usage.toFixed(1)}%</span>
              <span className="text-[10px] text-nexus-muted font-mono">
                ({formatBytes(sysStatus.used_memory)} / {formatBytes(sysStatus.total_memory)})
              </span>
            </div>
            <div className="w-full bg-nexus-surface h-1.5 rounded-full overflow-hidden">
              <div 
                className="bg-emerald-500 h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]"
                style={{ width: `${Math.min(sysStatus.memory_usage, 100)}%` }}
              />
            </div>
          </div>

          {/* Card Disk */}
          <div className="nx-card p-4 space-y-3 relative overflow-hidden">
            <div className="flex justify-between items-center">
              <span className="text-xs text-nexus-muted font-mono uppercase font-semibold">Storage Usage</span>
              <Ic.folder className="h-4 w-4 text-amber-400" />
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold text-nexus-text font-mono">{sysStatus.disk_usage.toFixed(1)}%</span>
              <span className="text-[10px] text-nexus-muted font-mono">
                ({formatBytes(sysStatus.total_disk - sysStatus.available_disk)} / {formatBytes(sysStatus.total_disk)})
              </span>
            </div>
            <div className="w-full bg-nexus-surface h-1.5 rounded-full overflow-hidden">
              <div 
                className="bg-amber-500 h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(245,158,11,0.6)]"
                style={{ width: `${Math.min(sysStatus.disk_usage, 100)}%` }}
              />
            </div>
          </div>

          {/* Card Uptime */}
          <div className="nx-card p-4 space-y-3 relative overflow-hidden">
            <div className="flex justify-between items-center">
              <span className="text-xs text-nexus-muted font-mono uppercase font-semibold">System Uptime</span>
              <Ic.history className="h-4 w-4 text-purple-400" />
            </div>
            <div className="flex items-baseline gap-1.5 py-1">
              <span className="text-lg font-bold text-nexus-text font-mono tracking-tight">{formatUptime(sysStatus.uptime)}</span>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Detail OS & Kernel */}
        {sysStatus && (
          <div className="nx-card p-5 space-y-4 lg:col-span-1">
            <h3 className="nx-section text-sm font-semibold text-nexus-text font-mono">Spesifikasi Sistem</h3>
            <div className="space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1 border-b border-nexus-hairline">
                <span className="text-nexus-muted">OS Name:</span>
                <span className="text-nexus-text font-semibold">{sysStatus.os_name}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-nexus-hairline">
                <span className="text-nexus-muted">OS Version:</span>
                <span className="text-nexus-text text-right font-semibold max-w-[180px] truncate" title={sysStatus.os_version}>
                  {sysStatus.os_version}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-nexus-hairline">
                <span className="text-nexus-muted">Kernel Version:</span>
                <span className="text-nexus-text text-right font-semibold max-w-[180px] truncate" title={sysStatus.kernel_version}>
                  {sysStatus.kernel_version}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-nexus-muted">eBPF Compatibility:</span>
                <span className={`font-semibold ${sysStatus.os_name.toLowerCase().includes("linux") ? "text-green-400" : "text-amber-400"}`}>
                  {sysStatus.os_name.toLowerCase().includes("linux") ? "Native (Supported)" : "WSL2 Needed"}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* WAF Supervisor Watchdog */}
        {supStatus && (
          <div className="nx-card p-5 space-y-4 lg:col-span-2 flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center mb-4">
                <h3 className="nx-section text-sm font-semibold text-nexus-text font-mono">WAF Watchdog Supervisor</h3>
                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                  supStatus.is_enabled 
                    ? "bg-green-950/40 text-green-300 border-green-800" 
                    : "bg-red-950/40 text-red-300 border-red-800"
                }`}>
                  {supStatus.is_enabled ? "Watchdog Active" : "Watchdog Inactive"}
                </span>
              </div>
              
              <div className="grid grid-cols-2 gap-4 mb-4 font-mono text-xs">
                <div className="p-3 bg-nexus-surface border border-nexus-border rounded-lg">
                  <div className="text-nexus-muted">Auto-Healing Restarts</div>
                  <div className="text-xl font-bold text-nexus-text mt-1">{supStatus.auto_restarts} kali</div>
                </div>
                <div className="p-3 bg-nexus-surface border border-nexus-border rounded-lg">
                  <div className="text-nexus-muted">Active WAF Scan ID</div>
                  <div className="text-xs font-semibold text-nexus-text mt-2 truncate" title={supStatus.active_scan_id || "None"}>
                    {supStatus.active_scan_id ? supStatus.active_scan_id.substring(0, 8) + "..." : "Tidak Aktif"}
                  </div>
                </div>
              </div>
            </div>

            <div className="flex gap-2">
              <button 
                onClick={toggleSupervisor}
                className={`nx-btn-ghost flex-1 py-2 font-mono text-xs flex items-center justify-center gap-1.5 ${
                  supStatus.is_enabled ? "hover:bg-red-950/40 hover:text-red-300 border-red-900/50" : "hover:bg-green-950/40 hover:text-green-300 border-green-900/50"
                }`}
              >
                {supStatus.is_enabled ? (
                  <>
                    <Ic.stop className="h-3.5 w-3.5" /> Matikan Watchdog
                  </>
                ) : (
                  <>
                    <Ic.play className="h-3.5 w-3.5" /> Aktifkan Watchdog
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Supervisor Event Logs */}
      {supStatus && (
        <div className="nx-card p-5 space-y-4">
          <div className="flex justify-between items-center border-b border-nexus-hairline pb-2">
            <h3 className="text-sm font-semibold text-nexus-text font-mono flex items-center gap-1.5">
              <Ic.terminal className="h-4 w-4 text-nexus-accent" /> Supervisor Event Logs
            </h3>
            <button 
              onClick={clearLogs}
              className="text-[10px] text-nexus-muted hover:text-red-400 font-mono flex items-center gap-1 px-2 py-1 border border-nexus-border hover:border-red-900/50 rounded transition-all"
            >
              <Ic.trash className="h-3 w-3" /> Bersihkan Log
            </button>
          </div>
          <div className="bg-nexus-panel/70 border border-nexus-border/50 rounded-lg p-3 h-48 overflow-auto font-mono text-[11px] leading-relaxed text-nexus-muted">
            {supStatus.logs.map((log, i) => (
              <div 
                key={i} 
                className={`py-1 border-b border-nexus-hairline/20 last:border-0 ${
                  log.includes("[CRITICAL]") ? "text-red-400 font-semibold" : 
                  log.includes("[SYSTEM]") ? "text-cyan-400" : "text-nexus-muted"
                }`}
              >
                {log}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// src/pages/EbpfSecurity.tsx — eBPF Security Shield dashboard (Phase 2 & 3)
import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Ic } from "../lib/icons";
import { Select, Option } from "../components/Select";

interface EbpfStatus {
  is_active: boolean;
  interface: string;
  packets_inspected: number;
  packets_dropped: number;
  mode: string;
}

interface IdsAlert {
  ts: string;
  parent_pid: number;
  parent_name: string;
  child_pid: number;
  child_name: string;
  cmdline: string;
  severity: string;
  rule: string;
}

function formatInterfaceOption(raw: string): Option {
  const lastOpen = raw.lastIndexOf("(");
  const lastClose = raw.lastIndexOf(")");
  if (lastOpen !== -1 && lastClose !== -1 && lastClose > lastOpen) {
    const friendly = raw.substring(lastOpen + 1, lastClose).trim();
    const rest = raw.substring(0, lastOpen).trim();
    // Clean up interface number from rest if present, e.g. "1. \Device..." -> "\Device..."
    const cleanRest = rest.replace(/^\d+\.\s+/, "");
    return {
      value: raw,
      label: friendly,
      hint: cleanRest,
    };
  }
  
  // Fallback: strip number if present
  const cleanLabel = raw.replace(/^\d+\.\s+/, "");
  return {
    value: raw,
    label: cleanLabel,
    hint: "",
  };
}

export const EbpfSecurity: React.FC = () => {
  const [status, setStatus] = useState<EbpfStatus | null>(null);
  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  const [alerts, setAlerts] = useState<IdsAlert[]>([]);
  const [interfaces, setInterfaces] = useState<Option[]>([]);
  const [newIp, setNewIp] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const stat = await invoke<EbpfStatus>("get_ebpf_status");
      const ips = await invoke<string[]>("get_blocked_ips");
      const alr = await invoke<IdsAlert[]>("get_ids_alerts");
      const ifacesResult = await invoke<{ interfaces: string[] }>("list_interfaces");
      setStatus(stat);
      setBlockedIps(ips);
      setAlerts(alr);
      setInterfaces((ifacesResult.interfaces || []).map(formatInterfaceOption));
      setError(null);
    } catch (err: any) {
      console.error(err);
      setError(err?.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Listen to telemetry updates from Rust simulator
    let unlistenTelemetry: any;
    const setupTelemetryListener = async () => {
      unlistenTelemetry = await listen("ebpf-telemetry-update", () => {
        // Fetch status to refresh packet counts
        invoke<EbpfStatus>("get_ebpf_status")
          .then(setStatus)
          .catch(console.error);
      });
    };
    setupTelemetryListener();

    // Listen to IDS alerts from Rust simulator
    let unlistenAlerts: any;
    const setupAlertsListener = async () => {
      unlistenAlerts = await listen("ebpf-ids-alert", () => {
        invoke<IdsAlert[]>("get_ids_alerts")
          .then(setAlerts)
          .catch(console.error);
      });
    };
    setupAlertsListener();

    return () => {
      if (unlistenTelemetry) unlistenTelemetry();
      if (unlistenAlerts) unlistenAlerts();
    };
  }, []);

  const handleToggleEbpf = async () => {
    if (!status) return;
    try {
      const nextActive = !status.is_active;
      await invoke("set_ebpf_active", { active: nextActive });
      setStatus(prev => prev ? { ...prev, is_active: nextActive } : null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSelectInterface = async (iface: string) => {
    try {
      await invoke("set_ebpf_interface", { interface: iface });
      setStatus(prev => prev ? { ...prev, interface: iface } : null);
    } catch (err) {
      console.error(err);
    }
  };

  const handleBlockIp = async (e: React.FormEvent) => {
    e.preventDefault();
    const ipToBlock = newIp.trim();
    if (!ipToBlock) return;
    try {
      await invoke("block_ip", { ip: ipToBlock });
      setNewIp("");
      const ips = await invoke<string[]>("get_blocked_ips");
      setBlockedIps(ips);
    } catch (err: any) {
      alert(err?.message || String(err));
    }
  };

  const handleUnblockIp = async (ip: string) => {
    try {
      await invoke("unblock_ip", { ip });
      const ips = await invoke<string[]>("get_blocked_ips");
      setBlockedIps(ips);
    } catch (err) {
      console.error(err);
    }
  };

  const handleClearAlerts = async () => {
    try {
      await invoke("clear_ids_alerts");
      setAlerts([]);
    } catch (err) {
      console.error(err);
    }
  };

  if (loading && !status) {
    return (
      <div className="p-6 flex flex-col items-center justify-center h-[80vh] text-nexus-muted font-mono text-xs gap-3">
        <Ic.refresh className="h-6 w-6 animate-spin text-nexus-accent" />
        <span>Memuat modul keamanan kernel eBPF...</span>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <header className="flex items-center gap-3">
        <div className="bg-nexus-accent/15 p-2 rounded">
          <Ic.suite className="h-5 w-5 text-nexus-accent" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-nexus-text font-mono">eBPF Security Shield</h1>
          <p className="text-xs text-nexus-muted">
            Proteksi kernel-space tingkat rendah. Blokir serangan port scan (XDP) & deteksi eksploitasi RCE (kprobes).
          </p>
        </div>
      </header>

      {error && (
        <div className="p-4 bg-red-950/20 border border-red-900/50 rounded-xl flex items-start gap-3 font-mono text-xs">
          <Ic.alert className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-red-300">Gagal Mengakses Driver eBPF</h4>
            <p className="text-red-400/80 mt-1">{error}</p>
          </div>
        </div>
      )}

      {status && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Status Panel */}
          <div className="nx-card p-5 space-y-4 flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-xs text-nexus-muted font-mono uppercase font-semibold">eBPF Driver Status</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                  status.is_active 
                    ? "bg-green-950/40 text-green-300 border-green-800" 
                    : "bg-red-950/40 text-red-300 border-red-800"
                }`}>
                  {status.is_active ? "Shield Active" : "Shield Inactive"}
                </span>
              </div>
              <div className="space-y-2 font-mono text-xs">
                <div className="flex flex-col gap-1 py-1 border-b border-nexus-hairline">
                  <span className="text-nexus-muted text-[11px]">Interface:</span>
                  <Select
                    value={status.interface}
                    onChange={handleSelectInterface}
                    options={interfaces.length > 0 ? interfaces : [formatInterfaceOption(status.interface)]}
                    className="w-full mt-0.5"
                  />
                </div>
                <div className="flex justify-between py-1 border-b border-nexus-hairline">
                  <span className="text-nexus-muted">Mode:</span>
                  <span className={`font-semibold ${status.mode === "Live" ? "text-green-400 animate-pulse" : "text-amber-400"}`}>
                    {status.mode === "Live" ? "Linux Kernel (Live)" : "Simulated (demo data)"}
                  </span>
                </div>
              </div>
            </div>
            <button
              onClick={handleToggleEbpf}
              className={`nx-btn-ghost w-full py-2 font-mono text-xs flex items-center justify-center gap-1.5 ${
                status.is_active 
                  ? "hover:bg-red-950/40 hover:text-red-300 border-red-900/50" 
                  : "hover:bg-green-950/40 hover:text-green-300 border-green-900/50"
              }`}
            >
              {status.is_active ? (
                <>
                  <Ic.stop className="h-3.5 w-3.5" /> Matikan eBPF Shield
                </>
              ) : (
                <>
                  <Ic.play className="h-3.5 w-3.5" /> Aktifkan eBPF Shield
                </>
              )}
            </button>
          </div>

          {/* Inspected Metric */}
          <div className="nx-card p-5 space-y-4 relative overflow-hidden">
            <div className="flex justify-between items-center">
              <span className="text-xs text-nexus-muted font-mono uppercase font-semibold">XDP Inspected Packets</span>
              <Ic.activity className="h-4 w-4 text-cyan-400" />
            </div>
            <div className="flex flex-col py-1">
              <span className="text-3xl font-bold text-nexus-text font-mono tracking-tight">
                {status.packets_inspected.toLocaleString()}
              </span>
              <span className="text-[10px] text-nexus-muted font-mono mt-1">
                Laju paket masuk yang diaudit di level driver.
              </span>
            </div>
          </div>

          {/* Dropped Metric */}
          <div className="nx-card p-5 space-y-4 relative overflow-hidden">
            <div className="flex justify-between items-center">
              <span className="text-xs text-nexus-muted font-mono uppercase font-semibold">XDP Dropped Packets</span>
              <Ic.alert className={`h-4 w-4 ${status.packets_dropped > 0 ? "text-red-400 animate-bounce" : "text-nexus-muted"}`} />
            </div>
            <div className="flex flex-col py-1">
              <span className={`text-3xl font-bold font-mono tracking-tight ${
                status.packets_dropped > 0 ? "text-red-400" : "text-nexus-text"
              }`}>
                {status.packets_dropped.toLocaleString()}
              </span>
              <span className="text-[10px] text-nexus-muted font-mono mt-1">
                Paket berbahaya yang didrop sebelum mencapai OS stack.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Blocked IPs & Firewall Manager */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Block IP Form */}
        <div className="nx-card p-5 space-y-4 lg:col-span-1">
          <h3 className="nx-section text-sm font-semibold text-nexus-text font-mono">XDP Blacklist IP</h3>
          <form onSubmit={handleBlockIp} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase font-bold text-nexus-muted font-mono">
                Tambahkan IP Blacklist
              </label>
              <input
                type="text"
                value={newIp}
                onChange={(e) => setNewIp(e.target.value)}
                placeholder="Contoh: 192.168.1.120"
                className="nx-input w-full font-mono text-xs"
              />
            </div>
            <button type="submit" className="nx-btn-primary w-full py-2 font-mono text-xs flex items-center justify-center gap-1.5">
              <Ic.save className="h-3.5 w-3.5" /> Blokir IP Sekarang
            </button>
          </form>
        </div>

        {/* Blocked IPs Table */}
        <div className="nx-card p-5 space-y-4 lg:col-span-2">
          <h3 className="nx-section text-sm font-semibold text-nexus-text font-mono">
            IP Terblokir di Driver ({blockedIps.length})
          </h3>
          <div className="overflow-auto max-h-48 border border-nexus-hairline rounded">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-nexus-panel text-nexus-muted font-semibold">
                <tr>
                  <th className="px-3 py-2">IP Address</th>
                  <th className="px-3 py-2 w-[120px] text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-nexus-hairline text-nexus-text">
                {blockedIps.length === 0 ? (
                  <tr>
                    <td colSpan={2} className="px-3 py-6 text-center text-nexus-subtle italic">
                      Tidak ada IP terblokir di blacklist XDP.
                    </td>
                  </tr>
                ) : (
                  blockedIps.map((ip) => (
                    <tr key={ip} className="hover:bg-nexus-panel/40">
                      <td className="px-3 py-2">{ip}</td>
                      <td className="px-3 py-2 text-center">
                        <button
                          onClick={() => handleUnblockIp(ip)}
                          className="text-red-400 hover:text-red-500 font-semibold text-[11px] px-2 py-0.5 border border-nexus-border hover:border-red-950/30 rounded"
                        >
                          Lepas Blokir
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Syscall Trace IDS Logs */}
      <div className="nx-card p-5 space-y-4">
        <div className="flex justify-between items-center border-b border-nexus-hairline pb-2">
          <h3 className="text-sm font-semibold text-nexus-text font-mono flex items-center gap-1.5">
            <Ic.terminal className="h-4 w-4 text-nexus-accent" /> eBPF IDS Syscall Trace Audits (sys_enter_execve)
          </h3>
          <button 
            onClick={handleClearAlerts}
            className="text-[10px] text-nexus-muted hover:text-red-400 font-mono flex items-center gap-1 px-2 py-1 border border-nexus-border hover:border-red-900/50 rounded transition-all"
          >
            <Ic.trash className="h-3 w-3" /> Bersihkan IDS Log
          </button>
        </div>
        <div className="bg-nexus-panel/70 border border-nexus-border/50 rounded-lg p-3 h-64 overflow-auto font-mono text-[11px] leading-relaxed text-nexus-muted">
          {alerts.length === 0 ? (
            <div className="text-center py-12 text-nexus-subtle italic">
              IDS Audit sedang mendengarkan tracepoint syscall kernel...
            </div>
          ) : (
            alerts.slice().reverse().map((a, i) => (
              <div 
                key={i} 
                className="py-1.5 border-b border-nexus-hairline/20 last:border-0 hover:bg-white/5 transition-colors px-1"
              >
                <div className="flex justify-between text-[10px] text-nexus-subtle mb-0.5">
                  <span>[{a.ts}] Event: Tracepoint sys_enter_execve</span>
                  <span className="text-red-500 font-bold tracking-wider">{a.severity} - Rule: {a.rule}</span>
                </div>
                <div className="text-red-400">
                  <span className="text-nexus-text font-semibold">{a.parent_name} (PID {a.parent_pid})</span>
                  {" mengeksekusi shell subprocess "}
                  <span className="text-red-300 font-semibold bg-red-950/40 px-1 py-0.5 rounded">{a.child_name} (PID {a.child_pid})</span>
                </div>
                <div className="text-[10.5px] text-nexus-subtle font-mono mt-1 bg-nexus-surface p-1.5 rounded border border-nexus-border/40">
                  Command: <span className="text-nexus-text">{a.cmdline}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

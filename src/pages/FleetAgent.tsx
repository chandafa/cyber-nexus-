// src/pages/FleetAgent.tsx — Nexus Agent: daemon endpoint yang lapor ke manager.
import React, { useEffect, useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { buildArgs, runToolJson } from "../lib/tauri";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";
import { useToastStore } from "../app/store/toast.store";

export const FleetAgent: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const toast = useToastStore((s) => s.show);

  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("8765");
  const [enrollKey, setEnrollKey] = useState("");
  const [name, setName] = useState("");

  const scan = useScanRuntimeStore((s) => s.scans["fleet_agent"]);
  const isRunning = scan?.running ?? false;
  const [status, setStatus] = useState<any>(null);

  const refresh = async () => {
    try {
      setStatus(await runToolJson("agent_status"));
    } catch (err) {
      console.error(err);
    }
  };

  const enroll = async () => {
    if (!enrollKey.trim()) {
      toast("Masukkan Enrollment Key dari manager dulu.", { kind: "error" });
      return;
    }
    const r = await runToolJson("agent_enroll", buildArgs({ host, port, enroll_key: enrollKey.trim(), name }));
    if (r.ok) {
      toast(`Ter-enroll sebagai ${r.agent_id}. Sekarang jalankan daemon.`, { kind: "success" });
      refresh();
    } else {
      toast(`Enrollment gagal: ${r.error}`, { kind: "error" });
    }
  };

  const reset = async () => {
    await runToolJson("agent_reset");
    toast("Enrollment dilupakan. Anda bisa mendaftar ke manager lain.", { kind: "info" });
    refresh();
  };

  const start = () => {
    consoleRef.current?.start({
      command: "agent_start",
      args: [],
      module: "fleet_agent",
    });
  };
  const stop = () => useScanRuntimeStore.getState().stop("fleet_agent");

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, []);

  const enrolled = status?.enrolled;

  const form = (
    <div className="space-y-5">
      <div className="border border-nexus-hairline rounded p-3 bg-nexus-panel/50 space-y-3">
        <h4 className="text-xs font-semibold text-nexus-text flex items-center gap-1.5">
          <Ic.lock className="h-3.5 w-3.5 text-nexus-accent" /> Enrollment ke Manager
        </h4>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="nx-label">Manager Host</label>
            <input className="nx-input font-mono" value={host} onChange={(e) => setHost(e.target.value)} />
          </div>
          <div>
            <label className="nx-label">Port</label>
            <input className="nx-input font-mono" value={port} onChange={(e) => setPort(e.target.value)} />
          </div>
        </div>
        <div>
          <label className="nx-label">Enrollment Key</label>
          <input className="nx-input font-mono text-xs" value={enrollKey} onChange={(e) => setEnrollKey(e.target.value)}
            placeholder="tempel key dari halaman Fleet Manager" />
        </div>
        <div>
          <label className="nx-label">Nama Agent (opsional)</label>
          <input className="nx-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="mis. laptop-budi" />
        </div>
        <div className="grid grid-cols-2 gap-2">
          <button className="nx-btn-primary py-1.5 text-xs" onClick={enroll}>
            <Ic.check className="h-3.5 w-3.5 mr-1" /> {enrolled ? "Re-enroll" : "Enroll"}
          </button>
          <button className="nx-btn-ghost py-1.5 text-xs" onClick={reset} disabled={!enrolled}>
            <Ic.trash className="h-3.5 w-3.5 mr-1" /> Lupakan
          </button>
        </div>
      </div>

      <button
        className="nx-btn-primary w-full flex items-center justify-center font-semibold disabled:opacity-50"
        disabled={!enrolled}
        onClick={() => (isRunning ? stop() : start())}
      >
        {isRunning ? <Ic.stop className="h-4 w-4 mr-2" /> : <Ic.play className="h-4 w-4 mr-2" />}
        {isRunning ? "Stop Agent Daemon" : "Start Agent Daemon"}
      </button>
      {!enrolled && (
        <p className="text-[11px] text-nexus-subtle text-center">Enroll dulu sebelum menjalankan daemon.</p>
      )}

      {/* Status panel */}
      <div className="border border-nexus-hairline rounded p-3 bg-nexus-panel/40 space-y-1.5 text-xs">
        <Row k="Status daemon" v={isRunning ? "berjalan" : "berhenti"} cls={isRunning ? "text-emerald-400" : "text-nexus-subtle"} />
        <Row k="Enrolled" v={enrolled ? "ya" : "belum"} cls={enrolled ? "text-emerald-400" : "text-amber-400"} />
        <Row k="Agent ID" v={status?.agent_id || "—"} mono />
        <Row k="Manager" v={status ? `${status.manager_host || "—"}:${status.manager_port || ""}` : "—"} mono />
        <Row k="Policy versi" v={status?.policy_version ?? "—"} />
        <Row k="Antrian event" v={status?.queue_size ?? 0} />
      </div>

      <div className="text-[11px] text-nexus-subtle leading-relaxed">
        <b className="text-nexus-muted">Collectors:</b> {status?.collectors?.join(", ") || "system, ports, users, disk, firewall"}.
        Hanya memindai postur keamanan host ini; dikirim ke manager Anda di LAN.
      </div>
    </div>
  );

  return (
    <ModuleScaffold
      title="Nexus Agent — Endpoint Daemon"
      description="Daemon ringan: enroll ke manager, kirim heartbeat & telemetri keamanan berkala, terima policy/perintah (arsitektur ala-Wazuh)."
      icon={Ic.suite}
      consoleRef={consoleRef}
      module="fleet_agent"
      form={form}
    />
  );
};

const Row: React.FC<{ k: string; v: any; cls?: string; mono?: boolean }> = ({ k, v, cls, mono }) => (
  <div className="flex justify-between gap-2">
    <span className="text-nexus-subtle">{k}</span>
    <span className={`${cls || "text-nexus-text"} ${mono ? "font-mono text-[11px] truncate max-w-[180px]" : ""}`}>{v}</span>
  </div>
);

export default FleetAgent;

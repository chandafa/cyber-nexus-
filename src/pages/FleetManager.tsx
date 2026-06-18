// src/pages/FleetManager.tsx — Nexus Manager: server pusat fleet (multi-agent monitoring).
import React, { useEffect, useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { buildArgs, runToolJson } from "../lib/tauri";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";
import { useToastStore } from "../app/store/toast.store";

const SEV_CLS: Record<string, string> = {
  critical: "bg-red-950/30 text-red-300",
  high: "bg-orange-950/30 text-orange-300",
  medium: "bg-yellow-950/30 text-yellow-200",
  low: "bg-sky-950/30 text-sky-200",
  info: "text-nexus-muted",
};

export const FleetManager: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const toast = useToastStore((s) => s.show);

  const [bindHost, setBindHost] = useState("0.0.0.0");
  const [port, setPort] = useState("8765");

  const scan = useScanRuntimeStore((s) => s.scans["fleet_manager"]);
  const isRunning = scan?.running ?? false;

  const [status, setStatus] = useState<any>(null);
  const [agents, setAgents] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [policy, setPolicy] = useState<string>("");
  const [tab, setTab] = useState<"agents" | "alerts" | "events" | "policy">("alerts");

  const start = () => {
    consoleRef.current?.start({
      command: "manager_start",
      args: buildArgs({ foreground: true, host: bindHost, port }),
      module: "fleet_manager",
    });
  };
  const stop = () => useScanRuntimeStore.getState().stop("fleet_manager");

  const refresh = async () => {
    try {
      const st = await runToolJson("manager_status", buildArgs({ host: "127.0.0.1", port }));
      setStatus(st);
      const a = await runToolJson("fleet_agents");
      setAgents(a.agents || []);
      const e = await runToolJson("fleet_events", ["--limit", "200"]);
      setEvents(e.events || []);
      const al = await runToolJson("fleet_alerts", ["--limit", "200"]);
      setAlerts(al.alerts || []);
      if (!policy) {
        const p = await runToolJson("fleet_policy_get");
        setPolicy(JSON.stringify(p.policy, null, 2));
      }
    } catch (err) {
      console.error(err);
    }
  };

  const savePolicy = async () => {
    try {
      JSON.parse(policy); // validasi lokal
    } catch {
      toast("Policy bukan JSON yang valid.", { kind: "error" });
      return;
    }
    const r = await runToolJson("fleet_policy_set", ["--policy", policy]);
    if (r.ok) toast(`Policy disimpan -> versi ${r.policy_version}. Agent menariknya pada heartbeat berikutnya.`, { kind: "success" });
    else toast(r.error || "Gagal menyimpan policy.", { kind: "error" });
  };

  const sendCommand = async (agentId: string, cmd: string) => {
    await runToolJson("fleet_command", buildArgs({ agent_id: agentId, cmd }));
    toast(`Perintah '${cmd}' diantri untuk ${agentId}.`, { kind: "success" });
  };

  const ackAlert = async (id: string, next: string) => {
    await runToolJson("fleet_alert_ack", buildArgs({ id, status: next }));
    refresh();
  };

  const remediate = async (a: any) => {
    const r = a.rule_id || "";
    let action = "harden";
    const extra: Record<string, string> = {};
    if (r === "NEXUS-FW-001") action = "enable_firewall";
    else if (r === "NEXUS-PROC-001") { action = "kill_process"; extra.process = a.target?.process || ""; }
    else if (r === "NEXUS-SCA-001") action = "disable_guest";
    else if (r.startsWith("NEXUS-AUTH") || r === "NEXUS-LOG-001" || r === "NEXUS-LOG-005") {
      action = "block_ip";
      const ip = window.prompt("Blokir IP mana?");
      if (!ip) return;
      extra.ip = ip;
    }
    if (!window.confirm(`Kirim remediasi "${action}" ke agent? (DRY-RUN — eksekusi nyata hanya jika policy.active_response aktif)`)) return;
    const res = await runToolJson("fleet_respond", buildArgs({ agent_id: a.agent_id, action, ...extra }));
    if (res.ok) toast(`Remediasi '${action}' diantri ke agent.`, { kind: "success" });
    else toast(res.error || "Gagal mengirim remediasi.", { kind: "error" });
  };

  const copy = (text: string, label: string) => {
    navigator.clipboard?.writeText(text);
    toast(`${label} disalin.`, { kind: "success" });
  };

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [port]);

  const online = agents.filter((a) => a.status === "online").length;

  const form = (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="nx-label">Bind Host</label>
          <input className="nx-input font-mono" value={bindHost} onChange={(e) => setBindHost(e.target.value)} />
        </div>
        <div>
          <label className="nx-label">Port</label>
          <input className="nx-input font-mono" value={port} onChange={(e) => setPort(e.target.value)} />
        </div>
      </div>
      <p className="text-[11px] text-nexus-subtle leading-relaxed">
        Gunakan <span className="font-mono">0.0.0.0</span> agar endpoint di LAN dapat mendaftar. Enrollment key
        & HMAC per-agent mengamankan koneksi. Data tidak dikirim ke internet.
      </p>

      <button
        className="nx-btn-primary w-full flex items-center justify-center font-semibold"
        onClick={() => (isRunning ? stop() : start())}
      >
        {isRunning ? <Ic.stop className="h-4 w-4 mr-2" /> : <Ic.play className="h-4 w-4 mr-2" />}
        {isRunning ? "Stop Manager" : "Start Manager"}
      </button>

      {/* Enrollment credentials */}
      <div className="border border-nexus-hairline rounded p-3 bg-nexus-panel/50 space-y-2.5">
        <h4 className="text-xs font-semibold text-nexus-text flex items-center gap-1.5">
          <Ic.lock className="h-3.5 w-3.5 text-nexus-accent" /> Kredensial Enrollment
        </h4>
        <CredRow label="Enrollment Key" value={status?.enroll_key} onCopy={copy} />
        <CredRow label="Admin Token" value={status?.admin_token} onCopy={copy} />
        <p className="text-[10.5px] text-nexus-subtle">
          Masukkan Manager host:port + Enrollment Key ini di halaman <b>Fleet Agent</b> pada endpoint.
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-2 text-center">
        <Stat label="Online" value={`${online}/${agents.length}`} />
        <Stat label="Open alerts" value={status?.alerts_open ?? 0}
              cls={(status?.alerts_open ?? 0) > 0 ? "text-red-400" : "text-emerald-400"} />
        <Stat label="Risk" value={status?.risk_score ?? 0} />
      </div>

      {/* Posture score (network/server/website) */}
      {status?.posture?.scores && (
        <div className="border border-nexus-hairline rounded p-3 bg-nexus-panel/40">
          <h4 className="text-[10px] uppercase tracking-wide text-nexus-subtle mb-2">Security posture</h4>
          <div className="grid grid-cols-3 gap-2 text-center">
            <Posture label="Network" v={status.posture.scores.network_security} />
            <Posture label="Server" v={status.posture.scores.server_hardening} />
            <Posture label="Website" v={status.posture.scores.website_security} />
          </div>
        </div>
      )}
    </div>
  );

  return (
    <>
      <ModuleScaffold
        title="Nexus Manager — Fleet Server"
        description="Server pusat penerima telemetri agent: enrollment, heartbeat, event queue, dan distribusi policy (arsitektur ala-Wazuh)."
        icon={Ic.server}
        consoleRef={consoleRef}
        module="fleet_manager"
        form={form}
      />

      <div className="border-t border-nexus-hairline bg-nexus-surface">
        <div className="flex gap-1 px-4 pt-2 border-b border-nexus-hairline">
          {(["agents", "alerts", "events", "policy"] as const).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 text-xs font-semibold capitalize transition-colors border-b-2 ${
                tab === t ? "border-nexus-accent text-nexus-text" : "border-transparent text-nexus-muted hover:text-nexus-text"}`}>
              {t === "agents" ? `Agents (${agents.length})` : t === "alerts" ? `Alerts (${alerts.length})`
                : t === "events" ? `Events (${events.length})` : "Policy"}
            </button>
          ))}
          <button className="ml-auto nx-btn-ghost text-xs my-1" onClick={refresh}>
            <Ic.refresh className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>

        <div className="p-4 max-h-72 overflow-auto">
          {tab === "agents" && (
            agents.length === 0 ? <Empty text="Belum ada agent terdaftar. Jalankan manager, lalu enroll agent dari endpoint." /> : (
              <table className="w-full text-xs">
                <thead className="text-left text-nexus-muted">
                  <tr><Th>Agent</Th><Th>Host / OS</Th><Th>IP</Th><Th>Status</Th><Th>Last Seen</Th><Th>Aksi</Th></tr>
                </thead>
                <tbody className="divide-y divide-nexus-hairline font-mono text-nexus-text">
                  {agents.map((a) => (
                    <tr key={a.agent_id} className="hover:bg-nexus-panel/40">
                      <td className="px-2 py-1.5">{a.name || a.hostname}<div className="text-[10px] text-nexus-subtle">{a.agent_id}</div></td>
                      <td className="px-2 py-1.5">{a.hostname}<div className="text-[10px] text-nexus-subtle">{a.os} {a.os_release}</div></td>
                      <td className="px-2 py-1.5">{a.ip || "—"}</td>
                      <td className="px-2 py-1.5">
                        <span className={`inline-flex items-center gap-1 ${a.status === "online" ? "text-emerald-400" : "text-nexus-subtle"}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${a.status === "online" ? "bg-emerald-400" : "bg-nexus-subtle"}`} />{a.status}
                        </span>
                      </td>
                      <td className="px-2 py-1.5 text-[11px]">{a.last_seen_iso}</td>
                      <td className="px-2 py-1.5">
                        <button className="text-nexus-accent hover:brightness-110 text-[11px]" onClick={() => sendCommand(a.agent_id, "collect_now")}>
                          Scan now
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}

          {tab === "alerts" && (
            alerts.length === 0 ? <Empty text="Belum ada alert. Rule engine menghasilkan alert dari event agent." /> : (
              <table className="w-full text-xs">
                <thead className="text-left text-nexus-muted">
                  <tr><Th>Waktu</Th><Th>Lvl</Th><Th>Severity</Th><Th>Rule</Th><Th>Judul</Th><Th>MITRE</Th><Th>Status</Th><Th>Aksi</Th></tr>
                </thead>
                <tbody className="divide-y divide-nexus-hairline text-nexus-text">
                  {alerts.map((a) => {
                    const next = a.status === "open" ? "ack" : a.status === "ack" ? "resolved" : "open";
                    return (
                      <tr key={a.id} className={`hover:bg-nexus-panel/40 ${SEV_CLS[a.severity] || ""}`}>
                        <td className="px-2 py-1.5 font-mono text-[11px] whitespace-nowrap">{a.ts_iso}</td>
                        <td className="px-2 py-1.5 font-bold">{a.level}</td>
                        <td className="px-2 py-1.5 uppercase text-[10px] font-bold">{a.severity}</td>
                        <td className="px-2 py-1.5 font-mono text-[10px] text-nexus-subtle">{a.rule_id}</td>
                        <td className="px-2 py-1.5">{a.title}<div className="text-[10px] text-nexus-subtle truncate max-w-[300px]">{a.recommendation}</div></td>
                        <td className="px-2 py-1.5 text-[10px] text-sky-300">{(a.mitre || []).join(", ")}</td>
                        <td className="px-2 py-1.5 text-[11px]">{a.status}</td>
                        <td className="px-2 py-1.5 whitespace-nowrap">
                          <button className="text-nexus-accent hover:brightness-110 text-[11px] mr-2" onClick={() => ackAlert(a.id, next)}>→{next}</button>
                          <button className="text-emerald-400 hover:brightness-110 text-[11px]" onClick={() => remediate(a)} title="Auto-remediation (dry-run default)">🛡 Amankan</button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )
          )}

          {tab === "events" && (
            events.length === 0 ? <Empty text="Belum ada event masuk." /> : (
              <table className="w-full text-xs">
                <thead className="text-left text-nexus-muted">
                  <tr><Th>Waktu</Th><Th>Severity</Th><Th>Tipe</Th><Th>Judul</Th><Th>Agent</Th></tr>
                </thead>
                <tbody className="divide-y divide-nexus-hairline text-nexus-text">
                  {events.map((e) => (
                    <tr key={e.id} className={`hover:bg-nexus-panel/40 ${SEV_CLS[e.severity] || ""}`}>
                      <td className="px-2 py-1.5 font-mono text-[11px] whitespace-nowrap">{e.ts_iso}</td>
                      <td className="px-2 py-1.5 uppercase text-[10px] font-bold">{e.severity}</td>
                      <td className="px-2 py-1.5 font-mono text-[11px]">{e.type}</td>
                      <td className="px-2 py-1.5">{e.title}<div className="text-[10px] text-nexus-subtle truncate max-w-[320px]">{e.detail}</div></td>
                      <td className="px-2 py-1.5 font-mono text-[10px] text-nexus-subtle">{e.agent_id?.slice(0, 12)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}

          {tab === "policy" && (
            <div className="space-y-2">
              <p className="text-[11px] text-nexus-muted">
                Policy JSON didorong ke semua agent. Ubah interval heartbeat/collect, daftar collector, port berisiko,
                lalu Simpan — versi naik & agent menariknya otomatis.
              </p>
              <textarea
                className="nx-input font-mono text-[11px] w-full h-44 resize-none"
                value={policy}
                onChange={(e) => setPolicy(e.target.value)}
                spellCheck={false}
              />
              <button className="nx-btn-primary px-4 py-1.5 text-xs" onClick={savePolicy}>
                <Ic.save className="h-3.5 w-3.5 mr-1.5" /> Simpan & Distribusikan Policy
              </button>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

const CredRow: React.FC<{ label: string; value?: string; onCopy: (v: string, l: string) => void }> = ({ label, value, onCopy }) => (
  <div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
    <div className="flex items-center gap-1.5">
      <code className="flex-1 truncate text-[11px] text-nexus-text bg-nexus-surface px-2 py-1 border border-nexus-hairline rounded">
        {value || "— (jalankan manager)"}
      </code>
      {value && (
        <button className="text-nexus-muted hover:text-nexus-accent" title="Salin" onClick={() => onCopy(value, label)}>
          <Ic.copy className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  </div>
);

const Stat: React.FC<{ label: string; value: any; cls?: string }> = ({ label, value, cls }) => (
  <div className="border border-nexus-hairline rounded py-2 bg-nexus-panel/40">
    <div className={`text-lg font-bold ${cls || "text-nexus-text"}`}>{value}</div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
  </div>
);

const Posture: React.FC<{ label: string; v: number }> = ({ label, v }) => {
  const cls = v >= 80 ? "text-emerald-400" : v >= 50 ? "text-yellow-400" : "text-red-400";
  return (
    <div>
      <div className={`text-base font-bold ${cls}`}>{v}</div>
      <div className="text-[10px] text-nexus-subtle">{label}</div>
    </div>
  );
};

const Th: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <th className="px-2 py-1.5 font-semibold">{children}</th>
);
const Empty: React.FC<{ text: string }> = ({ text }) => (
  <p className="text-xs text-nexus-subtle italic py-6 text-center">{text}</p>
);

export default FleetManager;

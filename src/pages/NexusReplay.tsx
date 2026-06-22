// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusReplay.tsx — Time-travel forensic scrubber: putar ulang event &
// alert secara kronologis untuk satu agent / incident.
import React, { useMemo, useState } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Frame {
  ts_iso: string;
  kind: "event" | "alert";
  severity: string;
  level?: number;
  title: string;
  detail: string;
  cum_events: number;
  cum_alerts: number;
  agent_id: string;
}

interface ReplayResp {
  ok: boolean;
  scope?: string;
  frame_count?: number;
  events?: number;
  alerts?: number;
  frames?: Frame[];
}

const SEV_CLS: Record<string, string> = {
  critical: "border-l-red-500 text-red-300",
  high: "border-l-orange-500 text-orange-300",
  medium: "border-l-yellow-500 text-yellow-200",
  low: "border-l-sky-500 text-sky-200",
  info: "border-l-nexus-hairline text-nexus-muted",
};

export const NexusReplay: React.FC = () => {
  const [agentId, setAgentId] = useState("");
  const [incident, setIncident] = useState("");
  const [fromTs, setFromTs] = useState("");
  const [toTs, setToTs] = useState("");
  const [limit, setLimit] = useState("2000");

  const [resp, setResp] = useState<ReplayResp | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [scrub, setScrub] = useState(0);

  const frames = resp?.frames || [];

  const replay = async () => {
    if (!agentId.trim() && !incident.trim()) {
      setError("Masukkan Agent ID atau Incident ID.");
      return;
    }
    setBusy(true);
    setError("");
    setScrub(0);
    try {
      const lim = parseInt(limit, 10);
      const d = await runToolJson<ReplayResp>(
        "fleet_replay",
        buildArgs({
          agent_id: agentId.trim() || undefined,
          incident: incident.trim() || undefined,
          from_ts: fromTs.trim() || undefined,
          to_ts: toTs.trim() || undefined,
          limit: Number.isNaN(lim) ? 2000 : lim,
        })
      );
      if ((d as any)?.ok === false) throw new Error((d as any).error || "replay gagal");
      setResp(d);
      setScrub((d?.frames || []).length); // tampilkan semua di awal
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const shown = useMemo(() => frames.slice(0, scrub), [frames, scrub]);

  return (
    <div className="mx-auto max-w-5xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.history className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">Forensic Replay</h1>
          <p className="text-sm text-nexus-muted">
            Putar ulang timeline event &amp; alert untuk menyusun kembali kronologi insiden.
          </p>
        </div>
      </header>

      {/* Controls */}
      <section className="border border-nexus-hairline bg-nexus-surface p-4 space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <label className="nx-label">Agent ID</label>
            <input className="nx-input font-mono" value={agentId} onChange={(e) => setAgentId(e.target.value)} placeholder="agent-… (atau kosongkan)" />
          </div>
          <div>
            <label className="nx-label">Incident ID</label>
            <input className="nx-input font-mono" value={incident} onChange={(e) => setIncident(e.target.value)} placeholder="inc-… (atau kosongkan)" />
          </div>
          <div>
            <label className="nx-label">From (ISO, opsional)</label>
            <input className="nx-input font-mono" value={fromTs} onChange={(e) => setFromTs(e.target.value)} placeholder="2026-06-22T00:00:00" />
          </div>
          <div>
            <label className="nx-label">To (ISO, opsional)</label>
            <input className="nx-input font-mono" value={toTs} onChange={(e) => setToTs(e.target.value)} placeholder="2026-06-22T23:59:59" />
          </div>
        </div>
        <div className="flex items-end gap-3">
          <div>
            <label className="nx-label">Limit</label>
            <input className="nx-input font-mono w-28" value={limit} onChange={(e) => setLimit(e.target.value)} />
          </div>
          <button className="nx-btn-primary text-xs" onClick={replay} disabled={busy}>
            <Ic.play className="h-3.5 w-3.5" /> {busy ? "Memuat…" : "Replay"}
          </button>
        </div>
      </section>

      {error && (
        <div className="border border-severity-critical/40 bg-severity-critical/10 px-4 py-2 text-sm text-severity-critical">
          {error}
        </div>
      )}

      {resp && (
        <>
          {/* Summary + scrubber */}
          <div className="flex flex-wrap items-center gap-2 text-xs text-nexus-subtle">
            <span className="nx-chip">Scope: <b className="text-nexus-text">{resp.scope || "—"}</b></span>
            <span className="nx-chip">Frames: <b className="text-nexus-text">{resp.frame_count ?? frames.length}</b></span>
            <span className="nx-chip">Events: <b className="text-nexus-text">{resp.events ?? 0}</b></span>
            <span className="nx-chip">Alerts: <b className="text-nexus-text">{resp.alerts ?? 0}</b></span>
          </div>

          {frames.length > 0 && (
            <div className="flex items-center gap-3">
              <span className="text-[11px] text-nexus-muted whitespace-nowrap">Scrub</span>
              <input
                type="range"
                min={0}
                max={frames.length}
                value={scrub}
                onChange={(e) => setScrub(parseInt(e.target.value, 10))}
                className="flex-1 accent-nexus-accent"
              />
              <span className="text-[11px] font-mono text-nexus-text whitespace-nowrap">
                {scrub}/{frames.length}
              </span>
            </div>
          )}

          {/* Timeline */}
          <section className="border border-nexus-hairline bg-nexus-surface">
            <ol className="divide-y divide-nexus-hairline/60">
              {shown.map((f, i) => (
                <li key={i} className={`flex gap-3 border-l-2 px-4 py-2.5 ${SEV_CLS[f.severity] || SEV_CLS.info}`}>
                  <div className="pt-0.5">
                    {f.kind === "alert" ? (
                      <Ic.alert className="h-4 w-4 text-red-400" />
                    ) : (
                      <Ic.activity className="h-4 w-4 text-nexus-muted" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="font-mono text-[10px] text-nexus-subtle">{f.ts_iso}</span>
                      <span className="text-[9px] uppercase font-bold tracking-wider text-nexus-subtle">{f.kind}</span>
                      <span className="text-[9px] uppercase font-bold tracking-wider">{f.severity}</span>
                      {f.level != null && <span className="text-[10px] font-mono text-nexus-subtle">lvl {f.level}</span>}
                    </div>
                    <div className="text-sm text-nexus-text truncate">{f.title}</div>
                    {f.detail && <div className="text-[11px] text-nexus-subtle truncate">{f.detail}</div>}
                  </div>
                  <div className="text-right whitespace-nowrap text-[10px] text-nexus-subtle">
                    <div>Σ ev {f.cum_events}</div>
                    <div>Σ al {f.cum_alerts}</div>
                  </div>
                </li>
              ))}
            </ol>
            {!frames.length && (
              <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
                Tidak ada frame pada rentang ini.
              </p>
            )}
          </section>
        </>
      )}
    </div>
  );
};

export default NexusReplay;

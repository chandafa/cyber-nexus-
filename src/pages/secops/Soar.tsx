// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/Soar.tsx — SOAR: playbook otomatis + riwayat eksekusi.
// Memanggil runner: soar_playbooks / soar_runs (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Playbook {
  id: string;
  name: string;
  trigger: { on: string; conditions: Record<string, unknown> };
  mode: string;
  enabled: boolean;
}
interface Run {
  ts_iso: string;
  playbook_name: string;
  entity: string;
  status: string;
}

const modePill = (m: string) =>
  m === "active"
    ? "border-nexus-accent/40 bg-nexus-accent/10 text-nexus-accent"
    : "border-nexus-warning/40 bg-nexus-warning/10 text-nexus-warning";

export const Soar: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const [pb, rn] = await Promise.all([
        runToolJson<any>("soar_playbooks"),
        runToolJson<any>("soar_runs", ["--limit", "100"]),
      ]);
      setPlaybooks(pb?.playbooks || []);
      setRuns(rn?.runs || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.mitigation className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">SOAR — Playbooks</h1>
          <p className="text-sm text-nexus-muted">
            Playbook menjalankan respons nyata (aksi destruktif default dry-run).
          </p>
        </div>
        <button
          onClick={load}
          disabled={busy}
          className="flex items-center gap-1.5 border border-nexus-border px-3 py-1.5 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
        >
          <Ic.refresh className="h-4 w-4" /> Refresh
        </button>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-nexus-subtle">Playbooks</h2>
        <div className="border border-nexus-hairline bg-nexus-surface">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                <th className="px-4 py-2.5">Playbook</th>
                <th className="px-4 py-2.5">Trigger</th>
                <th className="px-4 py-2.5">Mode</th>
                <th className="px-4 py-2.5">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {playbooks.map((p) => (
                <tr key={p.id} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                  <td className="px-4 py-2.5 text-nexus-text">
                    {p.name}
                    <div className="text-[10px] text-nexus-subtle">{p.id}</div>
                  </td>
                  <td className="px-4 py-2.5 text-[11px] text-nexus-muted">
                    {p.trigger?.on} {JSON.stringify(p.trigger?.conditions || {})}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${modePill(p.mode)}`}>
                      {p.mode}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-[11px] text-nexus-muted">{p.enabled ? "on" : "off"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!playbooks.length && (
            <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
              {busy ? "Memuat…" : "Belum ada playbook. Jalankan manager agar playbook default terpasang."}
            </p>
          )}
        </div>
      </div>

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-nexus-subtle">Recent runs</h2>
        <div className="border border-nexus-hairline bg-nexus-surface">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                <th className="px-4 py-2.5">Time</th>
                <th className="px-4 py-2.5">Playbook</th>
                <th className="px-4 py-2.5">Entity</th>
                <th className="px-4 py-2.5">Status</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r, k) => (
                <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                  <td className="whitespace-nowrap px-4 py-2.5 text-[11px] text-nexus-subtle">{r.ts_iso}</td>
                  <td className="px-4 py-2.5 text-nexus-text">{r.playbook_name}</td>
                  <td className="px-4 py-2.5 text-nexus-muted">{r.entity}</td>
                  <td className="px-4 py-2.5 text-[11px] text-nexus-muted">{r.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!runs.length && (
            <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">Belum ada eksekusi playbook.</p>
          )}
        </div>
      </div>
    </div>
  );
};

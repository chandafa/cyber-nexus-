// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/Ndr.tsx — NDR: deteksi jaringan (beaconing/C2/port-scan).
// Memanggil runner: ndr_stats / ndr_talkers (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Talker {
  dst: string;
  connections: number;
  bytes: number;
  external: boolean;
}

const Stat: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div className="border border-nexus-hairline bg-nexus-surface px-4 py-3">
    <div className="text-2xl font-bold text-nexus-text">{value}</div>
    <div className="mt-0.5 text-[10px] uppercase tracking-wider text-nexus-subtle">{label}</div>
  </div>
);

export const Ndr: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [talkers, setTalkers] = useState<Talker[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const s = await runToolJson<any>("ndr_stats");
      setStats(s || null);
      const d = await runToolJson<any>("ndr_talkers");
      setTalkers(d?.talkers || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const kb = (b: number) => (b ? `${Math.round(b / 1024)} KB` : "—");

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.network className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">NDR — Network Detection</h1>
          <p className="text-sm text-nexus-muted">
            Deteksi beaconing/C2, port-scan & koneksi ke IOC dari telemetri koneksi nyata.
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

      <div className="grid grid-cols-2 gap-3">
        <Stat label="Flows (24h)" value={stats?.observations ?? 0} />
        <Stat label="Destinations" value={stats?.distinct_dst ?? 0} />
      </div>

      <div className="border border-nexus-hairline bg-nexus-surface">
        <div className="border-b border-nexus-hairline px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-nexus-subtle">
          Top external talkers
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Destination</th>
              <th className="px-4 py-2.5">Connections</th>
              <th className="px-4 py-2.5">Bytes</th>
            </tr>
          </thead>
          <tbody>
            {talkers.map((t, k) => (
              <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="px-4 py-2.5 font-mono text-nexus-text">{t.dst}</td>
                <td className="px-4 py-2.5 text-nexus-muted">{t.connections}</td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-subtle">{kb(t.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!talkers.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada observasi koneksi. Agent mengirim snapshot koneksi otomatis."}
          </p>
        )}
      </div>
    </div>
  );
};

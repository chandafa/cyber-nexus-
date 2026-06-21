// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/Ueba.tsx — UEBA: baseline perilaku + skor anomali entitas.
// Memanggil runner: ueba_scores / ueba_train / ueba_scan (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Score {
  entity: string;
  score: number;
  band: string;
  reasons: { detail: string; signal: string }[];
  ts_iso: string;
}

const bandColor = (b: string) =>
  b === "high" ? "text-nexus-danger" : b === "medium" ? "text-nexus-warning" : "text-nexus-muted";

export const Ueba: React.FC = () => {
  const [rows, setRows] = useState<Score[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<any>("ueba_scores", ["--limit", "100"]);
      setRows(d?.scores || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const train = useCallback(async () => {
    setBusy(true);
    setMsg("");
    try {
      const d = await runToolJson<any>("ueba_train");
      setMsg(`Baseline terlatih untuk ${d?.trained ?? 0} entitas.`);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const scan = useCallback(async () => {
    setBusy(true);
    setMsg("");
    try {
      const d = await runToolJson<any>("ueba_scan");
      setMsg(`Scan: ${d?.scored ?? 0} entitas dinilai, ${d?.emitted ?? 0} anomali tinggi di-emit.`);
      await load();
    } catch (e: any) {
      setError(String(e?.message || e));
      setBusy(false);
    }
  }, [load]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.human className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">UEBA — Entity Risk</h1>
          <p className="text-sm text-nexus-muted">
            Skor anomali perilaku per entitas vs baseline (volume, luar jam, tipe baru, outlier peer).
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={train}
            disabled={busy}
            className="flex items-center gap-1.5 border border-nexus-border px-3 py-1.5 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
          >
            <Ic.activity className="h-4 w-4" /> Train
          </button>
          <button
            onClick={scan}
            disabled={busy}
            className="flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-3 py-1.5 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
          >
            <Ic.refresh className="h-4 w-4" /> Scan
          </button>
        </div>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}
      {msg && <p className="text-xs text-nexus-accent">{msg}</p>}

      <div className="border border-nexus-hairline bg-nexus-surface">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Entity</th>
              <th className="px-4 py-2.5">Risk</th>
              <th className="px-4 py-2.5">Band</th>
              <th className="px-4 py-2.5">Reasons</th>
              <th className="px-4 py-2.5">Time</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, k) => (
              <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="px-4 py-2.5 text-nexus-muted">{r.entity}</td>
                <td className={`px-4 py-2.5 font-semibold ${bandColor(r.band)}`}>{r.score}</td>
                <td className={`px-4 py-2.5 font-medium uppercase ${bandColor(r.band)}`}>{r.band}</td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-muted">
                  {(r.reasons || []).map((x) => x.detail || x.signal).join("; ")}
                </td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-subtle">{r.ts_iso}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada skor. Train baseline lalu Scan (butuh manager + agent berisi data)."}
          </p>
        )}
      </div>
    </div>
  );
};

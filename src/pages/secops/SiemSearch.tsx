// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/SiemSearch.tsx — SIEM: pencarian NQL atas event/alert store.
// Memanggil runner: secops_search / ai_nl (Pro-gated).
import React, { useState, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Row {
  ts_iso: string;
  severity: string;
  event_type: string;
  rule_id: string;
  type: string;
  title: string;
  agent_id: string;
}

const sevColor = (s: string) =>
  s === "critical" || s === "high"
    ? "text-nexus-danger"
    : s === "medium"
    ? "text-nexus-warning"
    : "text-nexus-muted";

export const SiemSearch: React.FC = () => {
  const [index, setIndex] = useState("events");
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [count, setCount] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const search = useCallback(
    async (q?: string, idx?: string) => {
      setBusy(true);
      setError("");
      try {
        const d = await runToolJson<any>("secops_search", [
          "--index",
          idx ?? index,
          "--q",
          q ?? query,
          "--limit",
          "200",
        ]);
        if (d?.ok === false) throw new Error(d.error || "kueri gagal");
        setRows(d?.results || []);
        setCount(d?.count ?? (d?.results || []).length);
      } catch (e: any) {
        setError(String(e?.message || e));
      } finally {
        setBusy(false);
      }
    },
    [index, query]
  );

  const toNql = useCallback(async () => {
    const text = window.prompt("Tulis dalam bahasa biasa (mis. 'gagal login hari ini'):");
    if (!text) return;
    try {
      const d = await runToolJson<any>("ai_nl", ["--q", text]);
      const nql = d?.nql || text;
      const idx = d?.index || "events";
      setQuery(nql);
      setIndex(idx);
      search(nql, idx);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }, [search]);

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.search className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">SIEM — Search (NQL)</h1>
          <p className="text-sm text-nexus-muted">
            Cari event/alert dengan bahasa kueri Nexus — mis. <code className="text-nexus-accent">severity&gt;=high last:24h</code>.
          </p>
        </div>
      </header>

      <div className="flex flex-wrap items-center gap-2">
        <select
          value={index}
          onChange={(e) => setIndex(e.target.value)}
          className="border border-nexus-border bg-nexus-surface px-2 py-2 text-sm text-nexus-text"
        >
          <option value="events">events</option>
          <option value="alerts">alerts</option>
        </select>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search()}
          placeholder="severity>=high last:24h"
          className="flex-1 border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-sm text-nexus-text"
        />
        <button
          onClick={() => search()}
          disabled={busy}
          className="flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-3 py-2 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
        >
          <Ic.search className="h-4 w-4" /> Search
        </button>
        <button
          onClick={toNql}
          className="flex items-center gap-1.5 border border-nexus-border px-3 py-2 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text"
          title="Terjemahkan bahasa biasa → NQL (AI lokal)"
        >
          <Ic.activity className="h-4 w-4" /> Plain → NQL
        </button>
      </div>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}

      {count !== null && (
        <p className="text-xs text-nexus-subtle">{count} hasil</p>
      )}

      <div className="border border-nexus-hairline bg-nexus-surface">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Time</th>
              <th className="px-4 py-2.5">Severity</th>
              <th className="px-4 py-2.5">Type</th>
              <th className="px-4 py-2.5">Title</th>
              <th className="px-4 py-2.5">Agent</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, k) => (
              <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="whitespace-nowrap px-4 py-2.5 text-[11px] text-nexus-subtle">{r.ts_iso}</td>
                <td className={`px-4 py-2.5 font-medium uppercase ${sevColor(r.severity)}`}>{r.severity}</td>
                <td className="px-4 py-2.5 text-nexus-muted">{r.event_type || r.rule_id || r.type}</td>
                <td className="px-4 py-2.5 text-nexus-text">{r.title}</td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-subtle">{(r.agent_id || "").slice(0, 14)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Tak ada hasil. Jalankan manager + agent agar data masuk, lalu cari."}
          </p>
        )}
      </div>
    </div>
  );
};

// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/ThreatIntel.tsx — Threat Intelligence: IOC store + feed import.
// Memanggil runner: ti_stats / ti_iocs / ti_import (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Ioc {
  type: string;
  value: string;
  threat: string;
  severity: string;
  source: string;
}

const sevColor = (s: string) =>
  s === "critical" || s === "high"
    ? "text-nexus-danger"
    : s === "medium"
    ? "text-nexus-warning"
    : "text-nexus-muted";

const Stat: React.FC<{ label: string; value: React.ReactNode; danger?: boolean }> = ({
  label,
  value,
  danger,
}) => (
  <div className="border border-nexus-hairline bg-nexus-surface px-4 py-3">
    <div className={`text-2xl font-bold ${danger ? "text-nexus-danger" : "text-nexus-text"}`}>{value}</div>
    <div className="mt-0.5 text-[10px] uppercase tracking-wider text-nexus-subtle">{label}</div>
  </div>
);

export const ThreatIntel: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [iocs, setIocs] = useState<Ioc[]>([]);
  const [feedUrl, setFeedUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const s = await runToolJson<any>("ti_stats");
      setStats(s || null);
      const d = await runToolJson<any>("ti_iocs", ["--limit", "300"]);
      setIocs(d?.iocs || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const importFeed = useCallback(async () => {
    if (!feedUrl.trim()) return;
    setBusy(true);
    setError("");
    try {
      await runToolJson<any>("ti_import", ["--url", feedUrl.trim(), "--fmt", "text"]);
      setFeedUrl("");
      await load();
    } catch (e: any) {
      setError(String(e?.message || e));
      setBusy(false);
    }
  }, [feedUrl, load]);

  useEffect(() => {
    load();
  }, [load]);

  const byType = stats?.by_type || {};

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.exploit className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">Threat Intelligence</h1>
          <p className="text-sm text-nexus-muted">
            Database IOC + pencocokan pada telemetri nyata. Impor feed (abuse.ch / MISP / OTX).
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

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="IOCs" value={stats?.total_iocs ?? 0} />
        <Stat label="Matches" value={stats?.total_matches ?? 0} danger />
        <Stat label="IP" value={byType.ip ?? 0} />
        <Stat label="Domain" value={byType.domain ?? 0} />
      </div>

      <div className="flex gap-2">
        <input
          value={feedUrl}
          onChange={(e) => setFeedUrl(e.target.value)}
          placeholder="URL feed IOC (teks, satu indikator per baris)…"
          className="flex-1 border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-sm text-nexus-text placeholder:text-nexus-subtle focus:border-nexus-accent focus:outline-none"
        />
        <button
          onClick={importFeed}
          disabled={busy || !feedUrl.trim()}
          className="flex items-center gap-1.5 border border-nexus-border px-3 py-2 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
        >
          <Ic.download className="h-4 w-4" /> Import
        </button>
      </div>

      <div className="border border-nexus-hairline bg-nexus-surface">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Type</th>
              <th className="px-4 py-2.5">Indicator</th>
              <th className="px-4 py-2.5">Threat</th>
              <th className="px-4 py-2.5">Severity</th>
              <th className="px-4 py-2.5">Source</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((i, k) => (
              <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="px-4 py-2.5 text-nexus-subtle">{i.type}</td>
                <td className="px-4 py-2.5 font-mono text-nexus-text">{i.value}</td>
                <td className="px-4 py-2.5 text-nexus-muted">{i.threat}</td>
                <td className={`px-4 py-2.5 font-medium uppercase ${sevColor(i.severity)}`}>{i.severity}</td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-subtle">{i.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!iocs.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada IOC. Impor feed (abuse.ch / MISP / OTX) untuk mulai."}
          </p>
        )}
      </div>
    </div>
  );
};

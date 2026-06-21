// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/XdrIncidents.tsx — XDR: insiden terkorelasi (kill-chain).
// Memanggil runner: xdr_incidents / xdr_incident / xdr_correlate (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Incident {
  id: string;
  rule_id: string;
  name: string;
  entity: string;
  level: number;
  severity: string;
  status: string;
  count: number;
  last_iso: string;
  mitre: string[];
}

const sevColor = (s: string) =>
  s === "critical" || s === "high"
    ? "text-nexus-danger"
    : s === "medium"
    ? "text-nexus-warning"
    : "text-nexus-muted";

export const XdrIncidents: React.FC = () => {
  const [items, setItems] = useState<Incident[]>([]);
  const [detail, setDetail] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<any>("xdr_incidents", ["--limit", "200"]);
      setItems(d?.incidents || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const correlate = useCallback(async () => {
    setBusy(true);
    try {
      await runToolJson<any>("xdr_correlate", ["--lookback", "86400"]);
      await load();
    } catch (e: any) {
      setError(String(e?.message || e));
      setBusy(false);
    }
  }, [load]);

  const openDetail = useCallback(async (id: string) => {
    try {
      const d = await runToolJson<any>("xdr_incident", ["--id", id]);
      setDetail(d?.incident || null);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.suite className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">XDR — Correlated Incidents</h1>
          <p className="text-sm text-nexus-muted">
            Banyak alert lintas-waktu digabung menjadi satu insiden ber-kill-chain.
          </p>
        </div>
        <button
          onClick={correlate}
          disabled={busy}
          className="flex items-center gap-1.5 border border-nexus-border px-3 py-1.5 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
        >
          <Ic.refresh className="h-4 w-4" /> Correlate
        </button>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}

      <div className="border border-nexus-hairline bg-nexus-surface">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Incident</th>
              <th className="px-4 py-2.5">Severity</th>
              <th className="px-4 py-2.5">Entity</th>
              <th className="px-4 py-2.5">Alerts</th>
              <th className="px-4 py-2.5">Last</th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => (
              <tr
                key={i.id}
                onClick={() => openDetail(i.id)}
                className="cursor-pointer border-b border-nexus-hairline/60 hover:bg-nexus-panel/50"
              >
                <td className="px-4 py-2.5 text-nexus-text">
                  {i.name}
                  <div className="text-[10px] text-nexus-subtle">
                    {i.rule_id} · {(i.mitre || []).join(", ")}
                  </div>
                </td>
                <td className={`px-4 py-2.5 font-medium uppercase ${sevColor(i.severity)}`}>
                  {i.severity} <span className="text-nexus-subtle">L{i.level}</span>
                </td>
                <td className="px-4 py-2.5 text-nexus-muted">{i.entity}</td>
                <td className="px-4 py-2.5 text-nexus-muted">{i.count}</td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-subtle">{i.last_iso}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!items.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada insiden XDR. Jalankan manager + agent agar data masuk, lalu Correlate."}
          </p>
        )}
      </div>

      {detail && (
        <div className="border border-nexus-hairline bg-nexus-surface p-4">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="font-semibold text-nexus-text">{detail.name}</h2>
            <button onClick={() => setDetail(null)} className="text-nexus-subtle hover:text-nexus-text">
              <Ic.close className="h-4 w-4" />
            </button>
          </div>
          <p className="mb-3 text-xs text-nexus-subtle">
            {detail.entity} · MITRE {(detail.mitre || []).join(", ")}
          </p>
          <div className="space-y-1">
            {(detail.timeline || []).map((s: any, k: number) => (
              <div key={k} className="border-b border-nexus-hairline/60 py-1.5 text-sm text-nexus-muted">
                <span className="text-nexus-subtle">[{(s.ts_iso || "").slice(11, 16)}]</span>{" "}
                <span className="text-nexus-text">{s.title}</span>{" "}
                <span className="text-[10px] text-nexus-subtle">{s.rule_id}</span>
              </div>
            ))}
          </div>
          {detail.recommendation && (
            <p className="mt-3 text-xs text-nexus-muted">{detail.recommendation}</p>
          )}
        </div>
      )}
    </div>
  );
};

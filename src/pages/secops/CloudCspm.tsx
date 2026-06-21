// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/CloudCspm.tsx — Cloud Security Posture Management (CSPM).
// Memanggil runner: cloud_posture / cloud_findings (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Finding {
  title: string;
  check_id: string;
  compliance: string;
  severity: string;
  resource: string;
  provider: string;
  remediation: string;
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

export const CloudCspm: React.FC = () => {
  const [posture, setPosture] = useState<any>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const p = await runToolJson<any>("cloud_posture");
      setPosture(p || null);
      const d = await runToolJson<any>("cloud_findings", ["--limit", "300"]);
      setFindings(d?.findings || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const byProvider = posture?.by_provider || {};

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.cloud className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">Cloud Security (CSPM)</h1>
          <p className="text-sm text-nexus-muted">
            Temuan salah-konfigurasi cloud (CIS) dari evaluasi / import Prowler.
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
        <Stat label="Posture" value={posture?.overall ?? 100} danger={(posture?.overall ?? 100) < 50} />
        <Stat label="Open findings" value={posture?.open_findings ?? 0} danger />
        {Object.entries(byProvider).map(([k, v]) => (
          <Stat key={k} label={k} value={v as React.ReactNode} />
        ))}
      </div>

      <div className="border border-nexus-hairline bg-nexus-surface">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Check</th>
              <th className="px-4 py-2.5">Severity</th>
              <th className="px-4 py-2.5">Resource</th>
              <th className="px-4 py-2.5">Provider</th>
              <th className="px-4 py-2.5">Remediation</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, k) => (
              <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="px-4 py-2.5 text-nexus-text">
                  {f.title}
                  <div className="text-[10px] text-nexus-subtle">
                    {f.check_id} · {f.compliance}
                  </div>
                </td>
                <td className={`px-4 py-2.5 font-medium uppercase ${sevColor(f.severity)}`}>{f.severity}</td>
                <td className="px-4 py-2.5 text-nexus-muted">{f.resource}</td>
                <td className="px-4 py-2.5 text-nexus-subtle">{f.provider}</td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-muted">{f.remediation}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!findings.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada temuan cloud. Jalankan cloud scan / import Prowler via API."}
          </p>
        )}
      </div>
    </div>
  );
};

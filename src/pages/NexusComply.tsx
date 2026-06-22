// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusComply.tsx — Nexus Comply: pemetaan kepatuhan UU PDP / ISO 27001.
// Memanggil runner: fleet_comply_frameworks / fleet_comply_report. Pro-gated.
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Framework {
  id: string;
  name: string;
  controls: number;
}
interface Gap {
  id: string;
  ref: string;
  title: string;
  recommendation: string;
}
type Status = "covered" | "gap" | "manual";
interface Control {
  id: string;
  ref: string;
  title: string;
  theme: string;
  nexus: string[];
  status: Status;
  recommendation: string;
}
interface Report {
  ok: boolean;
  framework: string;
  name: string;
  summary: {
    total: number;
    covered: number;
    gap: number;
    manual: number;
    coverage_percent: number;
  };
  gaps: Gap[];
  controls: Control[];
}

const statusChip: Record<Status, string> = {
  covered: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  gap: "border-nexus-danger/40 bg-nexus-danger/10 text-nexus-danger",
  manual: "border-nexus-border bg-nexus-panel text-nexus-muted",
};

export const NexusComply: React.FC = () => {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [framework, setFramework] = useState<string>("uu-pdp");
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const loadFrameworks = useCallback(async () => {
    try {
      const d = await runToolJson<any>("fleet_comply_frameworks");
      setFrameworks(d?.frameworks || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  }, []);

  const loadReport = useCallback(async (fw: string) => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<Report>("fleet_comply_report", buildArgs({ framework: fw }));
      if ((d as any)?.ok === false) throw new Error((d as any).error || "gagal memuat laporan");
      setReport(d);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    loadFrameworks();
  }, [loadFrameworks]);

  useEffect(() => {
    loadReport(framework);
  }, [framework, loadReport]);

  const s = report?.summary;

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.mitigation className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">
            Nexus Comply — Pemetaan Kepatuhan
          </h1>
          <p className="text-sm text-nexus-muted">
            Petakan kontrol UU PDP / ISO 27001 ke fitur Nexus: lihat cakupan, celah,
            dan rekomendasi remediasi.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
            className="border border-nexus-border bg-nexus-surface px-2 py-2 text-sm text-nexus-text"
          >
            {(frameworks.length
              ? frameworks.map((f) => ({ id: f.id, name: f.name }))
              : [
                  { id: "uu-pdp", name: "UU PDP" },
                  { id: "iso27001", name: "ISO 27001" },
                ]
            ).map((f) => (
              <option key={f.id} value={f.id}>
                {f.name}
              </option>
            ))}
          </select>
          <button
            onClick={() => loadReport(framework)}
            disabled={busy}
            className="flex items-center gap-1.5 border border-nexus-border px-3 py-1.5 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
          >
            <Ic.refresh className="h-4 w-4" /> Refresh
          </button>
        </div>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}

      {/* Coverage headline */}
      <div className="flex flex-col gap-4 border border-nexus-hairline bg-nexus-surface p-5 sm:flex-row sm:items-center">
        <div className="text-center sm:w-40">
          <div className="text-4xl font-bold text-nexus-accent">
            {s ? `${Math.round(s.coverage_percent)}%` : "—"}
          </div>
          <div className="text-[11px] uppercase tracking-wider text-nexus-subtle">Cakupan</div>
          <div className="mt-1 text-[11px] text-nexus-muted">{report?.name || ""}</div>
        </div>
        <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat label="Total" value={s?.total ?? "—"} />
          <Stat label="Covered" value={s?.covered ?? "—"} cls="text-emerald-400" />
          <Stat label="Gap" value={s?.gap ?? "—"} cls="text-nexus-danger" />
          <Stat label="Manual" value={s?.manual ?? "—"} cls="text-nexus-muted" />
        </div>
      </div>

      {/* Controls table */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-nexus-text">
          Kontrol ({report?.controls.length ?? 0})
        </h2>
        <div className="border border-nexus-hairline bg-nexus-surface">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                <th className="px-4 py-2.5">Ref</th>
                <th className="px-4 py-2.5">Judul</th>
                <th className="px-4 py-2.5">Tema</th>
                <th className="px-4 py-2.5">Fitur Nexus</th>
                <th className="px-4 py-2.5">Status</th>
              </tr>
            </thead>
            <tbody>
              {(report?.controls || []).map((c) => (
                <tr key={c.id} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50 align-top">
                  <td className="px-4 py-2.5 font-mono text-[11px] text-nexus-muted">{c.ref}</td>
                  <td className="px-4 py-2.5 text-nexus-text">{c.title}</td>
                  <td className="px-4 py-2.5 text-[11px] text-nexus-muted">{c.theme}</td>
                  <td className="px-4 py-2.5 text-[11px] text-nexus-muted">
                    {(c.nexus || []).join(", ") || "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-block border px-2 py-0.5 text-[10px] font-semibold uppercase ${statusChip[c.status] || statusChip.manual}`}
                    >
                      {c.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!report?.controls.length && (
            <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
              {busy ? "Memuat…" : "Tak ada kontrol untuk framework ini."}
            </p>
          )}
        </div>
      </section>

      {/* Gaps & recommendations */}
      {!!report?.gaps.length && (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-nexus-text">
            Celah & Rekomendasi ({report.gaps.length})
          </h2>
          <div className="space-y-2">
            {report.gaps.map((g) => (
              <div key={g.id} className="border border-nexus-danger/30 bg-nexus-danger/5 px-4 py-3">
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-[11px] text-nexus-danger">{g.ref}</span>
                  <span className="text-sm font-medium text-nexus-text">{g.title}</span>
                </div>
                <p className="mt-1 text-[12px] text-nexus-muted">{g.recommendation}</p>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
};

const Stat: React.FC<{ label: string; value: React.ReactNode; cls?: string }> = ({ label, value, cls }) => (
  <div className="border border-nexus-hairline bg-nexus-panel/40 px-4 py-3 text-center">
    <div className={`text-xl font-bold ${cls || "text-nexus-text"}`}>{value}</div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
  </div>
);

export default NexusComply;

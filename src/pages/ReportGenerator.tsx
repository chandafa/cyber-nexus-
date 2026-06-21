// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/ReportGenerator.tsx — SDD bagian 10 & 8.3.
import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Ic } from "../lib/icons";
import { Select } from "../components/Select";
import { useScanStore } from "../app/store/scan.store";
import { generateReport, getSession, isTauri, openPath, revealPath } from "../lib/tauri";
import { getOutputDir, notifySaved } from "../lib/output";
import { SeverityBadge } from "../components/SeverityBadge";
import { severityCounts } from "../lib/parser";
import { formatDate } from "../lib/utils";

const TEMPLATES = [
  { id: "executive", label: "Executive Summary", desc: "Ringkasan non-teknis untuk manajemen" },
  { id: "technical", label: "Technical Detail", desc: "Semua temuan dengan bukti teknis" },
  { id: "full", label: "Full Report", desc: "Gabungan + appendix raw output" },
] as const;

export const ReportGenerator: React.FC = () => {
  const [params] = useSearchParams();
  const { history, refreshHistory } = useScanStore();
  const [sessionId, setSessionId] = useState(params.get("session") || "");
  const [template, setTemplate] = useState<"executive" | "technical" | "full">("full");
  const [preview, setPreview] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [output, setOutput] = useState<{ output: string; is_pdf: boolean } | null>(null);

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  useEffect(() => {
    if (sessionId && isTauri()) {
      getSession(sessionId).then(setPreview).catch(() => setPreview(null));
      setOutput(null);
    }
  }, [sessionId]);

  const generate = async () => {
    if (!sessionId) return;
    // Minta folder output (sekali; setelah itu diingat).
    const dir = await getOutputDir();
    if (!dir) return; // dibatalkan
    setBusy(true);
    setOutput(null);
    try {
      const stamp = new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
      const outPath = dir.replace(/[\\/]+$/, "") + `/nexus_report_${template}_${stamp}.pdf`;
      const res = await generateReport(sessionId, template, outPath);
      setOutput(res);
      notifySaved(res.output);
    } catch (e) {
      alert("Gagal generate laporan: " + e);
    } finally {
      setBusy(false);
    }
  };

  const counts = preview ? severityCounts(preview.vulnerabilities || []) : null;

  return (
    <div className="p-6">
      <header className="mb-5 flex items-center gap-3">
        <div className="rounded-xl bg-nexus-accent/15 p-2.5">
          <Ic.report className="h-6 w-6 text-nexus-accent" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-nexus-text">Report Generator</h1>
          <p className="text-sm text-nexus-muted">Buat laporan PDF profesional dari hasil scan</p>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[400px_1fr]">
        <div className="space-y-4">
          <div className="nx-card">
            <label className="nx-label">Pilih Sesi</label>
            <Select
              value={sessionId}
              onChange={setSessionId}
              placeholder="— pilih sesi —"
              options={history.map((s) => ({
                value: s.id,
                label: `${s.module} · ${s.target || "-"} · ${formatDate(s.started_at)}`,
              }))}
            />
          </div>

          <div className="nx-card">
            <label className="nx-label">Template Laporan</label>
            <div className="space-y-2">
              {TEMPLATES.map((t) => (
                <label
                  key={t.id}
                  className={`block cursor-pointer rounded-lg border p-3 ${
                    template === t.id
                      ? "border-nexus-accent bg-nexus-accent/10"
                      : "border-nexus-border"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <input
                      type="radio"
                      name="tmpl"
                      checked={template === t.id}
                      onChange={() => setTemplate(t.id)}
                      className="accent-nexus-accent"
                    />
                    <span className="text-sm font-semibold text-nexus-text">{t.label}</span>
                  </div>
                  <p className="ml-6 text-xs text-nexus-muted">{t.desc}</p>
                </label>
              ))}
            </div>
          </div>

          <button className="nx-btn-primary w-full" onClick={generate} disabled={!sessionId || busy}>
            {busy ? (
              <Ic.refresh className="h-4 w-4 animate-spin" />
            ) : (
              <Ic.download className="h-4 w-4" />
            )}
            Export Laporan
          </button>

          {output && (
            <div className="nx-card border-green-500/30">
              <p className="text-xs text-nexus-muted">Laporan dibuat:</p>
              <p className="break-all font-mono text-xs text-green-300">{output.output}</p>
              {isTauri() && (
                <div className="mt-2 flex gap-2">
                  <button
                    className="nx-btn-primary flex-1 text-xs"
                    onClick={() =>
                      openPath(output.output).catch((e) => alert("Gagal membuka file: " + e))
                    }
                  >
                    <Ic.folder className="h-3.5 w-3.5" /> Buka File
                  </button>
                  <button
                    className="nx-btn-ghost text-xs"
                    onClick={() => revealPath(output.output).catch(() => {})}
                    title="Buka folder"
                  >
                    <Ic.folder className="h-3.5 w-3.5" />
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Preview */}
        <div className="nx-card min-h-[400px]">
          {!preview ? (
            <p className="text-sm text-nexus-muted">Pilih sesi untuk melihat pratinjau.</p>
          ) : (
            <div className="space-y-4">
              <div className="border-b border-nexus-border pb-3">
                <h2 className="text-lg font-bold text-nexus-text">
                  Nexus Security Report — {preview.target || "N/A"}
                </h2>
                <p className="text-xs text-nexus-muted">
                  Modul {preview.module} · {formatDate(preview.started_at)} · Template {template}
                </p>
              </div>

              {counts && (
                <div className="grid grid-cols-5 gap-2">
                  {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                    <div key={s} className="rounded-lg border border-nexus-border p-2 text-center">
                      <div className="text-lg font-bold">{counts[s]}</div>
                      <SeverityBadge severity={s} />
                    </div>
                  ))}
                </div>
              )}

              {preview.ports?.length > 0 && (
                <Section title={`Port Terbuka (${preview.ports.length})`}>
                  {preview.ports.map((p: any, i: number) => (
                    <div key={i} className="flex gap-3 font-mono text-xs text-nexus-muted">
                      <span className="text-nexus-text">{p.port}/{p.protocol}</span>
                      <span>{p.service}</span>
                      <span>{p.version}</span>
                    </div>
                  ))}
                </Section>
              )}

              {preview.vulnerabilities?.length > 0 && (
                <Section title={`Kerentanan (${preview.vulnerabilities.length})`}>
                  {preview.vulnerabilities.map((v: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={v.severity} />
                      <span className="text-nexus-text">{v.title}</span>
                      <span className="text-nexus-muted">{v.vuln_id}</span>
                    </div>
                  ))}
                </Section>
              )}

              {preview.anomalies?.length > 0 && (
                <Section title={`Anomali Log (${preview.anomalies.length})`}>
                  {preview.anomalies.map((a: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={a.severity} />
                      <span className="text-nexus-text">{a.attack_type}</span>
                      <span className="font-mono text-nexus-muted">{a.source_ip}</span>
                    </div>
                  ))}
                </Section>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div>
    <h3 className="mb-2 text-sm font-semibold text-nexus-accent2">{title}</h3>
    <div className="space-y-1">{children}</div>
  </div>
);

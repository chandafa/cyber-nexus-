// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/AiTriage.tsx — AI Triage LOKAL (tanpa API/token).
// Memanggil runner: ai_status / ai_list / ai_triage (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface Triage {
  incident_id: string;
  entity: string;
  priority: string;
  score: number;
  fp_likelihood: number;
  confidence: number;
  summary: string;
  recommendations: { actions?: string[] };
}

const priColor = (p: string) =>
  p === "P1" ? "text-nexus-danger" : p === "P2" ? "text-nexus-warning" : "text-nexus-muted";
const priBorder = (p: string) =>
  p === "P1" ? "border-nexus-danger" : p === "P2" ? "border-nexus-warning" : "border-nexus-border";

export const AiTriage: React.FC = () => {
  const [items, setItems] = useState<Triage[]>([]);
  const [model, setModel] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const m = await runToolJson<any>("ai_status");
      setModel(m || null);
      const d = await runToolJson<any>("ai_list", ["--limit", "100"]);
      setItems(d?.triage || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const triage = useCallback(async () => {
    setBusy(true);
    try {
      await runToolJson<any>("ai_triage", ["--status", "open"]);
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
          <Ic.activity className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">AI Triage (local)</h1>
          <p className="text-sm text-nexus-muted">Local engine — no API, no token cost.</p>
        </div>
        <button
          onClick={triage}
          disabled={busy}
          className="flex items-center gap-1.5 border border-nexus-border px-3 py-1.5 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
        >
          <Ic.refresh className="h-4 w-4" /> Triage open incidents
        </button>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}

      <p className="text-xs text-nexus-subtle">
        model: {model?.trained ? "trained" : "collecting"} · {model?.samples ?? 0} samples
      </p>

      <div className="space-y-3">
        {items.map((t) => (
          <div key={t.incident_id} className={`border-l-2 border border-nexus-hairline bg-nexus-surface p-4 ${priBorder(t.priority)}`}>
            <div className="mb-1.5 flex items-center gap-3">
              <span className={`border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wider ${priColor(t.priority)}`}>
                {t.priority}
              </span>
              <span className="font-semibold text-nexus-text">{t.entity}</span>
              <span className="ml-auto text-[11px] text-nexus-subtle">
                score {t.score} · FP {t.fp_likelihood}% · conf {t.confidence}%
              </span>
            </div>
            <p className="text-sm leading-relaxed text-nexus-muted">{t.summary}</p>
            {!!t.recommendations?.actions?.length && (
              <ul className="mt-2 list-disc space-y-1 pl-5 text-[13px] text-nexus-muted">
                {t.recommendations.actions.map((a, k) => (
                  <li key={k}>{a}</li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>

      {!items.length && (
        <p className="border border-nexus-hairline bg-nexus-surface px-4 py-8 text-center text-sm italic text-nexus-subtle">
          {busy ? "Memuat…" : "Belum ada hasil triase. Buat insiden XDR lalu klik “Triage open incidents”."}
        </p>
      )}
    </div>
  );
};

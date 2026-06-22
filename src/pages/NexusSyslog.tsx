// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusSyslog.tsx — Nexus Edge: ingest syslog agentless (RFC3164/5424).
// Memanggil runner: fleet_syslog_ingest. Pro-gated.
import React, { useState, useCallback } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface IngestResult {
  ok: boolean;
  stored: number;
  alerts: number;
}

export const NexusSyslog: React.FC = () => {
  const [host, setHost] = useState("");
  const [lines, setLines] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<IngestResult | null>(null);

  const ingest = useCallback(async () => {
    setError("");
    setResult(null);
    const payload = lines.replace(/\r\n/g, "\n").trim();
    if (!host.trim()) {
      setError("Masukkan host/IP perangkat sumber.");
      return;
    }
    if (!payload) {
      setError("Tempel minimal satu baris syslog.");
      return;
    }
    setBusy(true);
    try {
      const d = await runToolJson<IngestResult>(
        "fleet_syslog_ingest",
        buildArgs({ lines: payload, host })
      );
      if ((d as any)?.ok === false) throw new Error((d as any).error || "gagal ingest");
      setResult(d);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, [host, lines]);

  const lineCount = lines.replace(/\r\n/g, "\n").split("\n").filter((l) => l.trim()).length;

  return (
    <div className="mx-auto max-w-4xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.network className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">
            Nexus Edge — Ingest Syslog Agentless
          </h1>
          <p className="text-sm text-nexus-muted">
            Terima log dari perangkat yang tak bisa menjalankan agent (router, firewall, IoT).
            Tempel baris syslog RFC3164/5424; Nexus menyimpan & menjalankan deteksi.
          </p>
        </div>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}

      <div className="space-y-4 border border-nexus-hairline bg-nexus-surface p-5">
        <div>
          <label className="mb-1 block text-[11px] uppercase tracking-wider text-nexus-subtle">
            Host / IP perangkat
          </label>
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="192.168.1.1"
            className="w-full border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-sm text-nexus-text"
          />
        </div>

        <div>
          <div className="mb-1 flex items-center justify-between">
            <label className="text-[11px] uppercase tracking-wider text-nexus-subtle">
              Baris syslog (RFC3164 / RFC5424)
            </label>
            <span className="text-[11px] text-nexus-subtle">{lineCount} baris</span>
          </div>
          <textarea
            value={lines}
            onChange={(e) => setLines(e.target.value)}
            spellCheck={false}
            placeholder={"<134>1 2026-06-22T10:00:00Z fw01 kernel - - - DROP IN=eth0 SRC=10.0.0.5 DST=10.0.0.1\n<38>Jun 22 10:00:01 router sshd[1234]: Failed password for admin from 203.0.113.9"}
            className="h-56 w-full resize-none border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-[12px] text-nexus-text"
          />
        </div>

        <button
          onClick={ingest}
          disabled={busy}
          className="flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-4 py-2 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
        >
          <Ic.download className="h-4 w-4" /> Ingest
        </button>

        {result && (
          <div className="grid grid-cols-2 gap-2">
            <Stat label="Tersimpan" value={result.stored} />
            <Stat
              label="Alerts"
              value={result.alerts}
              cls={result.alerts > 0 ? "text-nexus-danger" : "text-emerald-400"}
            />
          </div>
        )}
      </div>

      <p className="text-[12px] text-nexus-subtle">
        Cocok untuk perangkat tanpa agent: arahkan syslog perangkat ke kolektor Anda lalu
        teruskan baris-barisnya ke sini, atau tempel ekspor log secara manual. Setiap baris
        dinormalisasi menjadi event dan dievaluasi oleh rule engine yang sama dengan telemetri agent.
      </p>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: React.ReactNode; cls?: string }> = ({ label, value, cls }) => (
  <div className="border border-nexus-hairline bg-nexus-panel/40 px-4 py-3 text-center">
    <div className={`text-xl font-bold ${cls || "text-nexus-text"}`}>{value}</div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
  </div>
);

export default NexusSyslog;

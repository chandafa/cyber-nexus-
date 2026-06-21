// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/SecurityScore.tsx — SDD v2 §5.15.
import React, { useRef } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";

const GRADE_COLOR: Record<string, string> = {
  A: "#22c55e",
  B: "#84cc16",
  C: "#eab308",
  D: "#f97316",
  F: "#ef4444",
};

const CAT_LABELS: Record<string, string> = {
  network_exposure: "Network Exposure",
  vulnerability: "Vulnerability",
  ssl_tls: "SSL/TLS Health",
  password_policy: "Password Policy",
  hardening: "System Hardening",
};

export const SecurityScore: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);

  const run = () =>
    consoleRef.current?.start({ command: "security_score", args: [], module: "score", target: "agregat" });

  return (
    <ModuleScaffold
      title="Security Score Dashboard"
      description="Skor keamanan agregat (0-100) dari semua hasil scan"
      icon={Ic.score}
      consoleRef={consoleRef}
      module="score"
      renderResult={(r) => {
        const color = GRADE_COLOR[r.grade] || "#8b7bff";
        return (
          <div className="space-y-5">
            <div className="flex items-center gap-6">
              <div
                className="flex h-32 w-32 shrink-0 flex-col items-center justify-center rounded-full border-4"
                style={{ borderColor: color }}
              >
                <div className="text-3xl font-bold text-nexus-text">{r.overall_score}</div>
                <div className="text-xs text-nexus-muted">/ 100</div>
              </div>
              <div>
                <div className="text-5xl font-bold" style={{ color }}>
                  {r.grade}
                </div>
                <div className="text-sm text-nexus-muted">Grade keseluruhan</div>
              </div>
            </div>
            <div className="space-y-3">
              {Object.entries(r.breakdown || {}).map(([k, v]) => (
                <div key={k}>
                  <div className="mb-1 flex justify-between text-xs">
                    <span className="text-nexus-text">{CAT_LABELS[k] || k}</span>
                    <span className="text-nexus-muted">{Math.round(v as number)}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-nexus-border">
                    <div
                      className="h-full rounded-full bg-nexus-accent"
                      style={{ width: `${v}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      }}
      form={
        <div className="space-y-4">
          <p className="text-sm text-nexus-muted">
            Menghitung skor agregat dari hasil Port Scanner, Vulnerability Scanner, SSL/TLS Auditor,
            Password Auditor, dan Lynis hardening yang tersimpan.
          </p>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Hitung Skor
          </button>
          <div className="rounded border border-nexus-border bg-nexus-bg p-3 text-xs text-nexus-muted">
            Bobot: Network 25% · Vuln 30% · SSL/TLS 15% · Password 10% · Hardening 20%
          </div>
        </div>
      }
    />
  );
};

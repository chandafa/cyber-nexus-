// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/ScanDiff.tsx — SDD v2 §5.16.
import React, { useEffect, useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { Select } from "../components/Select";
import { buildArgs } from "../lib/tauri";
import { useScanStore } from "../app/store/scan.store";
import { formatDate } from "../lib/utils";

export const ScanDiff: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const { history, refreshHistory } = useScanStore();
  const [oldS, setOldS] = useState("");
  const [newS, setNewS] = useState("");

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  const opts = history.map((s) => ({
    value: s.id,
    label: `${s.module} · ${s.target || "-"} · ${formatDate(s.started_at)}`,
  }));

  const run = () =>
    consoleRef.current?.start({
      command: "scan_diff",
      args: buildArgs({ old_session: oldS, new_session: newS }),
      module: "diff",
    });

  return (
    <ModuleScaffold
      title="Scan Diff / Compare"
      description="Bandingkan dua hasil scan antar waktu"
      icon={Ic.diff}
      consoleRef={consoleRef}
      module="diff"
      renderResult={(r) => (
        <div className="space-y-4 text-sm">
          <Section title="Port" color="text-nexus-green">
            <DiffList label="Baru terbuka" items={(r.ports?.newly_opened || []).map((p: any) => `${p.port}/${p.protocol} ${p.version || ""}`)} tone="text-severity-high" />
            <DiffList label="Tertutup" items={(r.ports?.newly_closed || []).map((p: any) => `${p.port}/${p.protocol}`)} tone="text-nexus-green" />
            <DiffList label="Versi berubah" items={(r.ports?.version_changes || []).map((p: any) => `${p.port}: ${p.old_version} → ${p.new_version}`)} tone="text-severity-medium" />
          </Section>
          <Section title="Vulnerability" color="text-severity-critical">
            <DiffList label="Temuan baru" items={(r.vulns?.new_findings || []).map((v: any) => `${v.vuln_id || v.title}`)} tone="text-severity-critical" />
            <DiffList label="Sudah diperbaiki" items={(r.vulns?.fixed_findings || []).map((v: any) => `${v.vuln_id || v.title}`)} tone="text-nexus-green" />
            <p className="text-xs text-nexus-muted">Masih ada: {r.vulns?.still_present_count ?? 0}</p>
          </Section>
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Sesi Lama</label>
            <Select value={oldS} onChange={setOldS} options={opts} placeholder="pilih sesi lama" />
          </div>
          <div>
            <label className="nx-label">Sesi Baru</label>
            <Select value={newS} onChange={setNewS} options={opts} placeholder="pilih sesi baru" />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.diff className="h-4 w-4" /> Bandingkan
          </button>
          <p className="text-xs text-nexus-muted">Kosongkan untuk melihat contoh diff (demo).</p>
        </div>
      }
    />
  );
};

const Section: React.FC<{ title: string; color: string; children: React.ReactNode }> = ({ title, color, children }) => (
  <div className="nx-card">
    <h3 className={`mb-2 text-sm font-semibold ${color}`}>{title}</h3>
    <div className="space-y-2">{children}</div>
  </div>
);

const DiffList: React.FC<{ label: string; items: string[]; tone: string }> = ({ label, items, tone }) => (
  <div>
    <div className="text-xs text-nexus-muted">{label} ({items.length})</div>
    {items.length === 0 ? (
      <div className="text-xs text-nexus-subtle">—</div>
    ) : (
      <ul className="font-mono text-xs">
        {items.map((i, k) => (
          <li key={k} className={tone}>
            {i}
          </li>
        ))}
      </ul>
    )}
  </div>
);

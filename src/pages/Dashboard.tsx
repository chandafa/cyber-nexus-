// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/Dashboard.tsx — SDD §9.
// Design Thinking: ringkasan status yang menenangkan + jalur cepat ke modul.
import React, { useEffect } from "react";
import { Link } from "react-router-dom";
import { Ic, type IconComp } from "../lib/icons";
import { useSettingsStore } from "../app/store/settings.store";
import { useScanStore } from "../app/store/scan.store";
import { StatusBadge } from "../components/StatusBadge";
import { formatDate } from "../lib/utils";

const MODULES: { to: string; label: string; icon: IconComp; desc: string }[] = [
  { to: "/port-scanner", label: "Port Scanner", icon: Ic.port, desc: "Nmap port & service scan" },
  { to: "/network-scanner", label: "Network Scanner", icon: Ic.network, desc: "Live packet capture" },
  { to: "/vuln-scanner", label: "Vuln Scanner", icon: Ic.vuln, desc: "Nikto / Gobuster / Nuclei" },
  { to: "/password-auditor", label: "Password Auditor", icon: Ic.password, desc: "Hydra / Hashcat" },
  { to: "/log-analyzer", label: "Log Analyzer", icon: Ic.log, desc: "Anomaly detection" },
  { to: "/network-mapper", label: "Network Mapper", icon: Ic.mapper, desc: "Topology visualization" },
  { to: "/defense-monitor", label: "Defense Monitor", icon: Ic.defense, desc: "Hardening audit" },
  { to: "/report", label: "Report Generator", icon: Ic.report, desc: "PDF reports" },
];

export const Dashboard: React.FC = () => {
  const { deps, refreshDeps, missingRequired } = useSettingsStore();
  const { history, refreshHistory } = useScanStore();

  useEffect(() => {
    refreshDeps();
    refreshHistory();
  }, [refreshDeps, refreshHistory]);

  const depList = Object.entries(deps);
  const installed = depList.filter(([, v]) => v.installed).length;
  const missing = missingRequired();

  return (
    <div className="mx-auto max-w-6xl animate-fade-in p-7">
      <header className="mb-7">
        <p className="text-sm text-nexus-muted">Selamat datang kembali 👋</p>
        <h1 className="mt-1 text-2xl font-bold tracking-tight text-nexus-text">Dashboard</h1>
        <p className="mt-1 text-sm text-nexus-muted">
          Antarmuka terpadu tools keamanan jaringan — pilih modul untuk memulai.
        </p>
      </header>

      {/* Stat cards */}
      <div className="mb-7 grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatCard
          icon={Ic.toolsCheck}
          tone="accent"
          value={`${installed}/${depList.length || "–"}`}
          label="Tools terpasang"
        />
        <StatCard icon={Ic.activity} tone="teal" value={String(history.length)} label="Total sesi scan" />
        <StatCard
          icon={Ic.alert}
          tone={missing.length ? "danger" : "ok"}
          value={String(missing.length)}
          label="Required tools kurang"
        />
      </div>

      {/* Module grid */}
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-nexus-subtle">Modul</h2>
      <div className="mb-9 grid grid-cols-2 gap-3.5 md:grid-cols-4">
        {MODULES.map((m) => (
          <Link
            key={m.to}
            to={m.to}
            className="group border border-nexus-hairline bg-nexus-surface p-4 transition-colors duration-100 hover:border-nexus-accent/50 hover:bg-nexus-panel"
          >
            <div className="mb-3 inline-flex bg-nexus-accent/15 p-2">
              <m.icon className="h-5 w-5 text-nexus-accent transition-colors group-hover:text-nexus-accent2" />
            </div>
            <div className="text-sm font-semibold text-nexus-text">{m.label}</div>
            <div className="mt-0.5 text-xs text-nexus-muted">{m.desc}</div>
          </Link>
        ))}
      </div>

      {/* Recent sessions */}
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-nexus-subtle">
        Sesi Terbaru
      </h2>
      <div className="overflow-hidden rounded-2xl border border-nexus-hairline bg-nexus-surface shadow-soft">
        {history.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-6 py-12 text-center">
            <Ic.history className="h-9 w-9 text-nexus-subtle" />
            <p className="text-sm text-nexus-muted">Belum ada sesi scan. Mulai dari salah satu modul di atas.</p>
          </div>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-nexus-subtle">
              <tr>
                <th className="px-5 py-3 font-medium">Modul</th>
                <th className="px-5 py-3 font-medium">Target</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Waktu</th>
              </tr>
            </thead>
            <tbody>
              {history.slice(0, 6).map((s) => (
                <tr key={s.id} className="border-t border-nexus-hairline">
                  <td className="px-5 py-3 capitalize text-nexus-text">{s.module}</td>
                  <td className="px-5 py-3 font-mono text-nexus-muted">{s.target || "-"}</td>
                  <td className="px-5 py-3">
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="px-5 py-3 text-nexus-muted">{formatDate(s.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

const TONES: Record<string, { bg: string; fg: string }> = {
  accent: { bg: "bg-nexus-accent/15", fg: "text-nexus-accent" },
  teal: { bg: "bg-nexus-accent2/12", fg: "text-nexus-accent2" },
  ok: { bg: "bg-nexus-green/12", fg: "text-nexus-green" },
  danger: { bg: "bg-severity-critical/12", fg: "text-severity-critical" },
};

const StatCard: React.FC<{ icon: IconComp; tone: string; value: string; label: string }> = ({
  icon: Icon,
  tone,
  value,
  label,
}) => {
  const t = TONES[tone] || TONES.accent;
  return (
    <div className="flex items-center gap-4 rounded-2xl border border-nexus-hairline bg-nexus-surface p-5 shadow-soft">
      <div className={`rounded-xl p-3 ${t.bg}`}>
        <Icon className={`h-6 w-6 ${t.fg}`} />
      </div>
      <div>
        <div className="text-2xl font-bold tracking-tight text-nexus-text">{value}</div>
        <div className="text-xs text-nexus-muted">{label}</div>
      </div>
    </div>
  );
};

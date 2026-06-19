// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/DefenseSuite.tsx — SDD v2 §5.19 (firewall auto-rule, patch advisory, mitigasi).
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { ResultTable } from "../components/ResultTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { runToolJson, isTauri } from "../lib/tauri";

const MITIGATIONS = [
  ["Port tidak perlu terbuka", "Tutup via firewall, matikan service, atau bind ke localhost"],
  ["SSH PermitRootLogin yes", "Set 'no', gunakan sudo, restart sshd"],
  ["Password lemah", "Wajibkan 12+ karakter, aktifkan MFA, pakai password manager"],
  ["TLS 1.0/1.1 aktif", "Disable protokol lama, hanya izinkan TLS 1.2+"],
  ["CVE pada package/image", "Update ke fixed_version, rebuild image"],
  ["WiFi WEP/Open", "Migrasi ke WPA2-AES/WPA3, passphrase 16+ karakter"],
];

export const DefenseSuite: React.FC = () => {
  const [fw, setFw] = useState<any[]>([]);
  const [patches, setPatches] = useState<any[]>([]);
  const [tab, setTab] = useState<"firewall" | "patch" | "mitigation">("firewall");
  const [loading, setLoading] = useState(false);

  const analyze = async () => {
    if (!isTauri()) return;
    setLoading(true);
    try {
      const [f, p] = await Promise.all([
        runToolJson<any>("firewall_advisor", []),
        runToolJson<any>("patch_advisor", []),
      ]);
      setFw(f.suggestions || []);
      setPatches(p.advisories || []);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    analyze();
  }, []);

  const tabs = [
    { id: "firewall", label: `Firewall (${fw.length})` },
    { id: "patch", label: `Patch (${patches.length})` },
    { id: "mitigation", label: "Mitigasi" },
  ] as const;

  return (
    <div className="mx-auto max-w-6xl animate-fade-in p-6">
      <header className="mb-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="bg-nexus-accent/15 p-2">
            <Ic.suite className="h-5 w-5 text-nexus-accent" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-nexus-text">Defense & Mitigation Suite</h1>
            <p className="text-xs text-nexus-muted">Saran firewall, patch advisory & checklist mitigasi</p>
          </div>
        </div>
        <button className="nx-btn-primary" onClick={analyze} disabled={loading}>
          <Ic.refresh className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Analisis
        </button>
      </header>

      <div className="mb-4 flex gap-1 border-b border-nexus-hairline">
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`px-4 py-2 text-sm ${
              tab === t.id ? "border-b-2 border-nexus-accent text-nexus-text" : "text-nexus-muted"
            }`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "firewall" && (
        <ResultTable
          csvName="firewall_rules.csv"
          rows={fw.map((s) => ({
            port: `${s.port}/${s.protocol}`,
            service: s.service,
            command: s.ufw_command,
            iptables: s.iptables_command,
            reasoning: s.reasoning,
          }))}
          empty="Tidak ada saran. Jalankan Port Scanner dulu."
          columns={[
            { key: "port", header: "Port" },
            { key: "service", header: "Service" },
            { key: "command", header: "ufw" },
            { key: "iptables", header: "iptables" },
          ]}
        />
      )}

      {tab === "patch" && (
        <ResultTable
          csvName="patch_advisories.csv"
          rows={patches}
          empty="Tidak ada advisory."
          columns={[
            { key: "max_severity", header: "Sev", render: (p) => <SeverityBadge severity={p.max_severity} /> },
            { key: "component", header: "Komponen" },
            { key: "current_version", header: "Versi" },
            { key: "recommended_version", header: "Rekomendasi" },
            { key: "issues", header: "Isu", render: (p) => (p.issues || []).join(", ") },
          ]}
        />
      )}

      {tab === "mitigation" && (
        <div className="space-y-2">
          {MITIGATIONS.map(([finding, step], i) => (
            <div key={i} className="flex items-start gap-3 border border-nexus-hairline bg-nexus-surface p-3">
              <Ic.mitigation className="mt-0.5 h-5 w-5 shrink-0 text-nexus-accent2" />
              <div>
                <div className="text-sm font-medium text-nexus-text">{finding}</div>
                <div className="text-xs text-nexus-muted">{step}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

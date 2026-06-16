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
  const [tab, setTab] = useState<"firewall" | "patch" | "mitigation" | "nexus">("firewall");
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
    { id: "nexus", label: "Nexus Agent" },
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

      {tab === "nexus" && (
        <div className="nx-card p-5 space-y-4">
          <div className="flex items-start gap-3">
            <Ic.server className="h-6 w-6 text-nexus-accent shrink-0 mt-0.5" />
            <div className="space-y-2 flex-1">
              <h3 className="text-sm font-semibold text-nexus-text font-mono">
                Deploy Hardening & Monitoring melalui Nexus Agent
              </h3>
              <p className="text-xs text-nexus-muted leading-relaxed font-mono">
                Untuk menerapkan mitigasi pertahanan kernel eBPF secara remote, jalankan daemon <code className="font-mono text-nexus-text bg-nexus-panel px-1 py-0.5 rounded">nexus-agent</code> pada VPS atau server target Anda. Agent akan terhubung secara persisten ke Manager ini untuk menyalurkan telemetry keamanan dan menerima rules.
              </p>

              <div className="pt-2 space-y-3 font-mono text-xs">
                <div className="bg-nexus-panel p-3 rounded border border-nexus-border/50">
                  <div className="text-[10px] text-nexus-subtle mb-1 uppercase font-bold">Perintah Deployment Satu Baris:</div>
                  <div className="flex items-center justify-between gap-2 bg-nexus-surface/50 p-2 border border-nexus-hairline rounded">
                    <code className="text-nexus-text text-[10px] break-all select-all font-mono">
                      curl -sSL http://YOUR_MANAGER_LAN_IP:1515/install | sudo bash
                    </code>
                    <button
                      onClick={() => navigator.clipboard.writeText("curl -sSL http://YOUR_MANAGER_LAN_IP:1515/install | sudo bash")}
                      className="nx-btn-ghost p-1 shrink-0"
                      title="Salin"
                    >
                      <Ic.copy className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                
                <div className="text-[10.5px] text-nexus-muted">
                  Setelah agen terpasang dan statusnya aktif, Anda dapat memantau telemetri kernel, daftar IP terblokir, dan log execve syscall langsung melalui menu <a href="#/nexus-agents" className="text-nexus-accent hover:underline font-semibold">Nexus Agent Manager</a>.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

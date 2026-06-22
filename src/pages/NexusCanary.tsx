// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusCanary.tsx — Honeytokens: mint & pantau canary token (credential,
// aws_key, url, dns, file, env) untuk deteksi intrusi dini.
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Token {
  id: string;
  type: string;
  label: string;
  marker: string;
  triggered: number;
  last_triggered: string | null;
  canary_url: string;
}

interface Stats {
  tokens: number;
  total_triggers: number;
  tripped_tokens: number;
}

type CanaryType = "credential" | "aws_key" | "url" | "dns" | "file" | "env";
const TYPES: CanaryType[] = ["credential", "aws_key", "url", "dns", "file", "env"];

export const NexusCanary: React.FC = () => {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [type, setType] = useState<CanaryType>("credential");
  const [label, setLabel] = useState("");
  const [minting, setMinting] = useState(false);

  const load = async () => {
    setBusy(true);
    setError("");
    try {
      const l = await runToolJson<any>("fleet_canary_list");
      if (l?.ok === false) throw new Error(l.error || "gagal memuat token");
      setTokens(l?.tokens || []);
      const s = await runToolJson<any>("fleet_canary_stats");
      if (s?.ok !== false) {
        setStats({
          tokens: s?.tokens ?? (l?.tokens || []).length,
          total_triggers: s?.total_triggers ?? 0,
          tripped_tokens: s?.tripped_tokens ?? 0,
        });
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const mint = async () => {
    setMinting(true);
    setError("");
    setNotice("");
    try {
      const r = await runToolJson<any>("fleet_canary_mint", buildArgs({ type, label: label.trim() || type }));
      if (r?.ok === false) throw new Error(r.error || "gagal mint token");
      setNotice(`Token "${r.id}" (${r.type}) dibuat — marker: ${r.marker}`);
      setLabel("");
      load();
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setMinting(false);
    }
  };

  const del = async (id: string) => {
    if (!window.confirm("Hapus canary token ini?")) return;
    setError("");
    try {
      const r = await runToolJson<any>("fleet_canary_del", buildArgs({ id }));
      if (r?.ok === false) throw new Error(r.error || "gagal menghapus");
      load();
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  };

  const copy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setNotice("URL canary disalin ke clipboard.");
  };

  return (
    <div className="mx-auto max-w-5xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.lock className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">Canary Honeytokens</h1>
          <p className="text-sm text-nexus-muted">
            Tanam token jebakan — ketika diakses penyerang, Nexus langsung memicu alert.
          </p>
        </div>
        <button onClick={load} disabled={busy} className="nx-btn-ghost text-xs">
          <Ic.refresh className="h-3.5 w-3.5" /> Muat ulang
        </button>
      </header>

      {error && (
        <div className="border border-severity-critical/40 bg-severity-critical/10 px-4 py-2 text-sm text-severity-critical">
          {error}
        </div>
      )}
      {notice && (
        <div className="border border-nexus-green/40 bg-nexus-green/10 px-4 py-2 text-sm text-nexus-green">
          {notice}
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3 text-center">
        <Stat label="Tokens" value={stats?.tokens ?? tokens.length} />
        <Stat
          label="Total triggers"
          value={stats?.total_triggers ?? 0}
          cls={(stats?.total_triggers ?? 0) > 0 ? "text-red-400" : "text-nexus-text"}
        />
        <Stat
          label="Tripped tokens"
          value={stats?.tripped_tokens ?? 0}
          cls={(stats?.tripped_tokens ?? 0) > 0 ? "text-orange-400" : "text-emerald-400"}
        />
      </div>

      {/* Mint form */}
      <section className="border border-nexus-hairline bg-nexus-surface p-4 space-y-3">
        <h2 className="text-[11px] font-semibold uppercase tracking-wider text-nexus-subtle">Mint token baru</h2>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="nx-label">Tipe</label>
            <select value={type} onChange={(e) => setType(e.target.value as CanaryType)} className="nx-input w-44">
              {TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="nx-label">Label</label>
            <input className="nx-input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="mis. prod-aws-readonly" />
          </div>
          <button className="nx-btn-primary text-xs" onClick={mint} disabled={minting}>
            <Ic.check className="h-3.5 w-3.5" /> {minting ? "Minting…" : "Mint"}
          </button>
        </div>
      </section>

      {/* Token table */}
      <section className="border border-nexus-hairline bg-nexus-surface">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Tipe</th>
              <th className="px-4 py-2.5">Label</th>
              <th className="px-4 py-2.5">Marker</th>
              <th className="px-4 py-2.5">Triggers</th>
              <th className="px-4 py-2.5">Canary URL</th>
              <th className="px-4 py-2.5 text-right">Aksi</th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="px-4 py-2.5 font-mono text-[11px] uppercase text-nexus-accent">{t.type}</td>
                <td className="px-4 py-2.5 text-nexus-text">
                  {t.label}
                  {t.last_triggered && (
                    <div className="text-[10px] text-nexus-subtle">last: {t.last_triggered}</div>
                  )}
                </td>
                <td className="px-4 py-2.5 font-mono text-[10px] text-nexus-subtle">{t.marker}</td>
                <td className="px-4 py-2.5">
                  <span className={`font-bold ${t.triggered > 0 ? "text-red-400" : "text-nexus-muted"}`}>{t.triggered}</span>
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1.5">
                    <code className="max-w-[220px] truncate text-[11px] text-nexus-text bg-nexus-bg px-2 py-1 border border-nexus-hairline rounded">
                      {t.canary_url || "—"}
                    </code>
                    {t.canary_url && (
                      <button className="text-nexus-muted hover:text-nexus-accent" title="Salin URL" onClick={() => copy(t.canary_url)}>
                        <Ic.copy className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </td>
                <td className="px-4 py-2.5 text-right">
                  <button className="text-red-400 hover:brightness-110 text-[11px]" onClick={() => del(t.id)}>
                    Hapus
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!tokens.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada honeytoken. Mint satu di atas dan tanam di asset sensitif."}
          </p>
        )}
      </section>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: any; cls?: string }> = ({ label, value, cls }) => (
  <div className="border border-nexus-hairline bg-nexus-panel/40 py-3">
    <div className={`text-xl font-bold ${cls || "text-nexus-text"}`}>{value}</div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
  </div>
);

export default NexusCanary;

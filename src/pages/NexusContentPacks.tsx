// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusContentPacks.tsx — Nexus Hub: katalog content pack (rules/IOC/playbook).
// Memanggil runner: fleet_pack_catalog / install / export / import. Pro-gated.
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Pack {
  id: string;
  name: string;
  description: string;
  iocs: number;
  playbooks: number;
}
interface Applied {
  rules: number;
  iocs: number;
  playbooks: number;
}
interface Bundle {
  format: string;
  rules: any[];
  iocs: any[];
  playbooks: any[];
}

export const NexusContentPacks: React.FC = () => {
  const [packs, setPacks] = useState<Pack[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [importText, setImportText] = useState("");
  const [imported, setImported] = useState<Applied | null>(null);

  const loadCatalog = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<any>("fleet_pack_catalog");
      setPacks(d?.packs || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    loadCatalog();
  }, [loadCatalog]);

  const install = useCallback(async (p: Pack) => {
    setMsg("");
    setError("");
    setBusy(true);
    try {
      const d = await runToolJson<any>("fleet_pack_install", buildArgs({ id: p.id }));
      if (d?.ok === false) throw new Error(d.error || "gagal memasang pack");
      const a: Applied = d?.applied || { rules: 0, iocs: 0, playbooks: 0 };
      setMsg(`Pack "${p.name}" dipasang: ${a.rules} rules, ${a.iocs} IOC, ${a.playbooks} playbook.`);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const doExport = useCallback(async () => {
    setMsg("");
    setError("");
    setBusy(true);
    try {
      const d = await runToolJson<Bundle>("fleet_pack_export");
      if ((d as any)?.ok === false) throw new Error((d as any).error || "gagal mengekspor");
      setBundle(d);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const doImport = useCallback(async () => {
    setMsg("");
    setError("");
    setImported(null);
    let parsed: any;
    try {
      parsed = JSON.parse(importText);
    } catch (e: any) {
      setError(`JSON tidak valid: ${e?.message || e}`);
      return;
    }
    setBusy(true);
    try {
      const d = await runToolJson<any>("fleet_pack_import", buildArgs({ pack: JSON.stringify(parsed) }));
      if (d?.ok === false) throw new Error(d.error || "gagal mengimpor pack");
      const a: Applied = d?.applied || { rules: 0, iocs: 0, playbooks: 0 };
      setImported(a);
      setMsg(`Pack diimpor: ${a.rules} rules, ${a.iocs} IOC, ${a.playbooks} playbook.`);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, [importText]);

  const copy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setMsg("Bundle disalin ke clipboard.");
  };

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.container className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">
            Nexus Hub — Content Packs
          </h1>
          <p className="text-sm text-nexus-muted">
            Pasang paket konten siap-pakai (detection rules, IOC, playbook), atau
            ekspor/impor bundle Anda sendiri.
          </p>
        </div>
        <button
          onClick={loadCatalog}
          disabled={busy}
          className="flex items-center gap-1.5 border border-nexus-border px-3 py-1.5 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
        >
          <Ic.refresh className="h-4 w-4" /> Refresh
        </button>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}
      {msg && <p className="text-xs text-nexus-accent">{msg}</p>}

      {/* Catalog */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-nexus-text">Katalog ({packs.length})</h2>
        {packs.length ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {packs.map((p) => (
              <div key={p.id} className="flex flex-col border border-nexus-hairline bg-nexus-surface p-4">
                <h3 className="text-sm font-semibold text-nexus-text">{p.name}</h3>
                <p className="mt-1 flex-1 text-[12px] text-nexus-muted">{p.description}</p>
                <div className="mt-3 flex items-center gap-3 text-[11px] text-nexus-subtle">
                  <span>{p.iocs} IOC</span>
                  <span>·</span>
                  <span>{p.playbooks} playbook</span>
                </div>
                <button
                  onClick={() => install(p)}
                  disabled={busy}
                  className="mt-3 flex items-center justify-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-3 py-1.5 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
                >
                  <Ic.download className="h-4 w-4" /> Pasang
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="border border-nexus-hairline bg-nexus-surface">
            <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
              {busy ? "Memuat…" : "Tak ada content pack di katalog."}
            </p>
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Export */}
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-nexus-text">Ekspor Bundle</h2>
          <div className="space-y-3 border border-nexus-hairline bg-nexus-surface p-4">
            <button
              onClick={doExport}
              disabled={busy}
              className="flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-3 py-2 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
            >
              <Ic.save className="h-4 w-4" /> Ekspor Konten Saat Ini
            </button>
            {bundle ? (
              <>
                <div className="grid grid-cols-3 gap-2">
                  <Stat label="Rules" value={bundle.rules?.length ?? 0} />
                  <Stat label="IOC" value={bundle.iocs?.length ?? 0} />
                  <Stat label="Playbooks" value={bundle.playbooks?.length ?? 0} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-nexus-subtle">
                    format: <span className="font-mono text-nexus-muted">{bundle.format}</span>
                  </span>
                  <button
                    onClick={() => copy(JSON.stringify(bundle, null, 2))}
                    className="flex items-center gap-1 text-[11px] text-nexus-muted hover:text-nexus-accent"
                  >
                    <Ic.copy className="h-3.5 w-3.5" /> Salin JSON
                  </button>
                </div>
                <textarea
                  readOnly
                  value={JSON.stringify(bundle, null, 2)}
                  spellCheck={false}
                  className="h-40 w-full resize-none border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-[11px] text-nexus-muted"
                />
              </>
            ) : (
              <p className="text-[12px] italic text-nexus-subtle">
                {busy ? "Mengekspor…" : "Klik Ekspor untuk membuat bundle dari rules/IOC/playbook saat ini."}
              </p>
            )}
          </div>
        </section>

        {/* Import */}
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-nexus-text">Impor Bundle</h2>
          <div className="space-y-3 border border-nexus-hairline bg-nexus-surface p-4">
            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              spellCheck={false}
              placeholder='{"format": "nexus-pack/1", "rules": [], "iocs": [], "playbooks": []}'
              className="h-40 w-full resize-none border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-[11px] text-nexus-text"
            />
            <button
              onClick={doImport}
              disabled={busy || !importText.trim()}
              className="flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-3 py-2 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
            >
              <Ic.download className="h-4 w-4" /> Impor Bundle
            </button>
            {imported && (
              <div className="grid grid-cols-3 gap-2">
                <Stat label="Rules" value={imported.rules} />
                <Stat label="IOC" value={imported.iocs} />
                <Stat label="Playbooks" value={imported.playbooks} />
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: React.ReactNode; cls?: string }> = ({ label, value, cls }) => (
  <div className="border border-nexus-hairline bg-nexus-panel/40 px-4 py-3 text-center">
    <div className={`text-xl font-bold ${cls || "text-nexus-text"}`}>{value}</div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
  </div>
);

export default NexusContentPacks;

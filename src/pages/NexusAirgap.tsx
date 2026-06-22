// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusAirgap.tsx — Air-gapped mode + offline threat-intel bundle
// export/import (sneakernet IOC sync untuk lingkungan tanpa internet).
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface AirgapStatus {
  ok: boolean;
  air_gapped: boolean;
  note: string;
}

interface Bundle {
  format: string;
  count: number;
  iocs: any[];
}

export const NexusAirgap: React.FC = () => {
  const [status, setStatus] = useState<AirgapStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [exporting, setExporting] = useState(false);

  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);

  const loadStatus = async () => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<AirgapStatus>("fleet_airgap_status");
      setStatus({
        ok: (d as any)?.ok ?? true,
        air_gapped: !!(d as any)?.air_gapped,
        note: (d as any)?.note || "",
      });
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    loadStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggle = async () => {
    const next = !(status?.air_gapped ?? false);
    setToggling(true);
    setError("");
    setNotice("");
    try {
      const r = await runToolJson<any>("fleet_airgap_set", buildArgs({ on: next ? "true" : "false" }));
      if (r?.ok === false) throw new Error(r.error || "gagal mengubah mode");
      setNotice(next ? "Air-gapped mode AKTIF — semua koneksi keluar dimatikan." : "Air-gapped mode NONAKTIF.");
      loadStatus();
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setToggling(false);
    }
  };

  const doExport = async () => {
    setExporting(true);
    setError("");
    setNotice("");
    try {
      const d = await runToolJson<Bundle>("fleet_ti_export");
      if ((d as any)?.ok === false) throw new Error((d as any).error || "ekspor gagal");
      setBundle({
        format: (d as any)?.format || "nexus-ti-bundle/1",
        count: (d as any)?.count ?? ((d as any)?.iocs || []).length,
        iocs: (d as any)?.iocs || [],
      });
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setExporting(false);
    }
  };

  const copyBundle = () => {
    if (!bundle) return;
    navigator.clipboard?.writeText(JSON.stringify(bundle, null, 2));
    setNotice("Bundle TI disalin ke clipboard.");
  };

  const doImport = async () => {
    let parsed: any;
    try {
      parsed = JSON.parse(importText);
    } catch {
      setError("Teks bundle bukan JSON yang valid.");
      return;
    }
    setImporting(true);
    setError("");
    setNotice("");
    try {
      const r = await runToolJson<any>("fleet_ti_import_bundle", buildArgs({ bundle: JSON.stringify(parsed) }));
      if (r?.ok === false) throw new Error(r.error || "impor gagal");
      setNotice(`Bundle TI diimpor (${r?.imported ?? r?.count ?? "?"} IOC).`);
      setImportText("");
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setImporting(false);
    }
  };

  const on = status?.air_gapped ?? false;

  return (
    <div className="mx-auto max-w-5xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.network className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">Air-Gapped Mode</h1>
          <p className="text-sm text-nexus-muted">
            Operasikan Nexus tanpa internet &amp; sinkronkan threat-intel via bundle offline (sneakernet).
          </p>
        </div>
        <button onClick={loadStatus} disabled={busy} className="nx-btn-ghost text-xs">
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

      {/* Toggle */}
      <section className="border border-nexus-hairline bg-nexus-surface p-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold text-nexus-text">
              <span className={`h-2 w-2 rounded-full ${on ? "bg-orange-400" : "bg-emerald-400"}`} />
              Air-gapped: {on ? "ON" : "OFF"}
            </div>
            {status?.note && <p className="mt-1 text-[11px] text-nexus-subtle">{status.note}</p>}
          </div>
          <button
            onClick={toggle}
            disabled={toggling}
            className={on ? "nx-btn-ghost text-xs" : "nx-btn-primary text-xs"}
          >
            <Ic.lock className="h-3.5 w-3.5" />
            {toggling ? "Menyimpan…" : on ? "Matikan air-gap" : "Aktifkan air-gap"}
          </button>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Export */}
        <section className="border border-nexus-hairline bg-nexus-surface p-4 space-y-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-nexus-subtle">Export TI bundle</h2>
          <p className="text-[11px] text-nexus-muted">
            Hasilkan bundle IOC untuk dibawa ke jaringan terisolasi.
          </p>
          <button className="nx-btn-primary text-xs" onClick={doExport} disabled={exporting}>
            <Ic.download className="h-3.5 w-3.5" /> {exporting ? "Mengekspor…" : "Export bundle"}
          </button>

          {bundle && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs text-nexus-subtle">
                <span className="nx-chip">{bundle.format}</span>
                <span className="nx-chip">IOC: <b className="text-nexus-text">{bundle.count}</b></span>
                <button className="ml-auto text-nexus-accent hover:brightness-110 text-[11px] inline-flex items-center gap-1" onClick={copyBundle}>
                  <Ic.copy className="h-3.5 w-3.5" /> Salin JSON
                </button>
              </div>
              <textarea
                readOnly
                className="nx-input font-mono text-[11px] h-44 resize-none"
                value={JSON.stringify(bundle, null, 2)}
                spellCheck={false}
              />
            </div>
          )}
        </section>

        {/* Import */}
        <section className="border border-nexus-hairline bg-nexus-surface p-4 space-y-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-nexus-subtle">Import TI bundle</h2>
          <p className="text-[11px] text-nexus-muted">
            Tempel JSON bundle dari mesin lain, lalu impor untuk memperbarui IOC lokal.
          </p>
          <textarea
            className="nx-input font-mono text-[11px] h-44 resize-none"
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            spellCheck={false}
            placeholder='{"format":"nexus-ti-bundle/1","count":0,"iocs":[]}'
          />
          <button className="nx-btn-primary text-xs" onClick={doImport} disabled={importing || !importText.trim()}>
            <Ic.download className="h-3.5 w-3.5" /> {importing ? "Mengimpor…" : "Import bundle"}
          </button>
        </section>
      </div>
    </div>
  );
};

export default NexusAirgap;

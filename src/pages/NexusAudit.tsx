// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusAudit.tsx — Tamper-evident audit log: rantai hash yang dapat
// diverifikasi integritasnya (deteksi modifikasi/penghapusan entri).
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Entry {
  ts_iso: string;
  actor: string;
  action: string;
  detail: any;
  hash: string;
}

interface Verify {
  ok: boolean;
  entries: number;
  tampered_at_id: number | string | null;
  tip_hash: string;
}

export const NexusAudit: React.FC = () => {
  const [audit, setAudit] = useState<Entry[]>([]);
  const [verify, setVerify] = useState<Verify | null>(null);
  const [busy, setBusy] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState("");

  const load = async () => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<any>("fleet_audit", buildArgs({ limit: 200 }));
      if (d?.ok === false) throw new Error(d.error || "gagal memuat audit log");
      setAudit(d?.audit || d?.entries || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const runVerify = async () => {
    setVerifying(true);
    setError("");
    try {
      const d = await runToolJson<any>("fleet_audit_verify");
      setVerify({
        ok: d?.ok ?? false,
        entries: d?.entries ?? 0,
        tampered_at_id: d?.tampered_at_id ?? null,
        tip_hash: d?.tip_hash || "",
      });
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="mx-auto max-w-5xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.log className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">Audit Log</h1>
          <p className="text-sm text-nexus-muted">
            Catatan aksi tamper-evident — setiap entri di-hash berantai sehingga modifikasi terdeteksi.
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

      {/* Verify panel */}
      <section className="border border-nexus-hairline bg-nexus-surface p-4 space-y-3">
        <div className="flex items-center gap-3">
          <button className="nx-btn-primary text-xs" onClick={runVerify} disabled={verifying}>
            <Ic.defense className="h-3.5 w-3.5" /> {verifying ? "Memverifikasi…" : "Verifikasi integritas rantai"}
          </button>
          <p className="text-[11px] text-nexus-subtle">
            Menghitung ulang seluruh rantai hash dan membandingkan dengan tip yang tersimpan.
          </p>
        </div>

        {verify && (
          verify.ok && verify.tampered_at_id == null ? (
            <div className="border border-emerald-500/40 bg-emerald-950/30 px-4 py-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-emerald-300">
                <Ic.check className="h-4 w-4" /> Rantai utuh — tidak ada tampering
              </div>
              <div className="mt-1.5 grid grid-cols-1 gap-1 text-[11px] text-emerald-200/80 md:grid-cols-2">
                <span>Entri terverifikasi: <b className="text-emerald-200">{verify.entries}</b></span>
                <span className="truncate">Tip hash: <code className="font-mono">{verify.tip_hash}</code></span>
              </div>
            </div>
          ) : (
            <div className="border border-red-500/50 bg-red-950/30 px-4 py-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-red-300">
                <Ic.warning className="h-4 w-4" /> TAMPERED — rantai rusak pada id {String(verify.tampered_at_id ?? "?")}
              </div>
              <div className="mt-1.5 grid grid-cols-1 gap-1 text-[11px] text-red-200/80 md:grid-cols-2">
                <span>Entri diperiksa: <b className="text-red-200">{verify.entries}</b></span>
                <span className="truncate">Tip hash: <code className="font-mono">{verify.tip_hash}</code></span>
              </div>
            </div>
          )
        )}
      </section>

      {/* Audit table */}
      <section className="border border-nexus-hairline bg-nexus-surface">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Waktu</th>
              <th className="px-4 py-2.5">Aktor</th>
              <th className="px-4 py-2.5">Aksi</th>
              <th className="px-4 py-2.5">Detail</th>
              <th className="px-4 py-2.5">Hash</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((e, i) => (
              <tr key={i} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-[11px] text-nexus-subtle">{e.ts_iso}</td>
                <td className="px-4 py-2.5 font-mono text-[11px] text-nexus-text">{e.actor || "—"}</td>
                <td className="px-4 py-2.5 font-mono text-[11px] text-nexus-accent">{e.action || "—"}</td>
                <td className="px-4 py-2.5 text-[11px] text-nexus-muted truncate max-w-[280px]">
                  {typeof e.detail === "string" ? e.detail : e.detail != null ? JSON.stringify(e.detail) : "—"}
                </td>
                <td className="px-4 py-2.5 font-mono text-[10px] text-nexus-subtle truncate max-w-[140px]">{e.hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!audit.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada entri audit."}
          </p>
        )}
      </section>
    </div>
  );
};

export default NexusAudit;

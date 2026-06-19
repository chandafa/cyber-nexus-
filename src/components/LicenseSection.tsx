// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/LicenseSection.tsx — aktivasi & status lisensi (Settings).
import React, { useEffect, useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { useLicenseStore } from "../app/store/license.store";
import { expiryLabel, PRO_FEATURES } from "../lib/license";
import { useToastStore } from "../app/store/toast.store";

const TIER_STYLE: Record<string, string> = {
  free: "border-nexus-border text-nexus-muted",
  pro: "border-nexus-accent/50 bg-nexus-accent/10 text-nexus-accent",
  enterprise: "border-violet-400/50 bg-violet-400/10 text-violet-300",
};

export const LicenseSection: React.FC = () => {
  const { status, loaded, busy, load, redeem, validate, apply, clear } = useLicenseStore();
  const toast = useToastStore((s) => s.show);
  const [code, setCode] = useState("");
  const [manualOpen, setManualOpen] = useState(false);
  const [token, setToken] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!loaded) load();
  }, [loaded, load]);

  const activate = async () => {
    const c = code.trim().toUpperCase();
    if (!c) {
      toast("Masukkan kode aktivasi.", { kind: "error" });
      return;
    }
    const res = await redeem(c);
    if (res.ok) {
      toast(`Aktivasi berhasil — edisi ${String(res.tier).toUpperCase()} aktif.`, { kind: "success" });
      setCode("");
    } else {
      toast(res.error || "Aktivasi gagal.", { kind: "error" });
    }
  };

  const applyManual = async (value: string) => {
    const t = value.trim();
    if (!t) {
      toast("Token kosong.", { kind: "error" });
      return;
    }
    const res = await apply(t);
    if (res.ok) {
      toast(`Lisensi ${String(res.tier).toUpperCase()} aktif.`, { kind: "success" });
      setToken("");
    } else {
      toast(res.error || "Token tidak valid.", { kind: "error" });
    }
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => applyManual(String(reader.result || ""));
    reader.onerror = () => toast("Gagal membaca file lisensi.", { kind: "error" });
    reader.readAsText(f);
  };

  const onClear = async () => {
    if (!window.confirm("Hapus lisensi dan kembali ke edisi Free?")) return;
    await clear();
    toast("Lisensi dihapus — kembali ke Free.", { kind: "success" });
  };

  const recheck = async () => {
    await validate();
    toast("Status lisensi diperbarui.", { kind: "info" });
  };

  const copyDevice = () => {
    navigator.clipboard?.writeText(status.device_id || "");
    toast("Device ID disalin.", { kind: "success" });
  };

  const tier = (status.tier || "free").toLowerCase();
  const tierCls = TIER_STYLE[tier] || TIER_STYLE.free;

  return (
    <div className="nx-card">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="nx-section flex items-center gap-2">
          <Ic.lock className="h-4 w-4 text-nexus-accent" /> Lisensi & Edisi
        </h2>
        <span className={`border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider ${tierCls}`}>
          {tier}
        </span>
      </div>

      {/* ringkasan status */}
      <div className="mb-4 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
        <Stat label="Status" value={status.valid ? "Aktif" : "Tidak aktif"} />
        <Stat label="Pemegang" value={status.licensee || "—"} />
        <Stat
          label="Sisa"
          value={
            status.valid && status.days_left != null
              ? `${status.days_left} hari`
              : status.valid
                ? "∞"
                : "—"
          }
        />
        <Stat label="Kedaluwarsa" value={status.valid ? expiryLabel(status.expires) : "—"} />
      </div>

      {/* Device ID — penting untuk lisensi terkunci-device */}
      <div className="mb-4">
        <div className="nx-label mb-1.5">Device ID perangkat ini</div>
        <div className="flex gap-2">
          <input className="nx-input font-mono text-xs" readOnly value={status.device_id || "—"} />
          <button className="nx-btn-ghost shrink-0 px-3" onClick={copyDevice} title="Salin">
            <Ic.copy className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* fitur Pro */}
      <div className="mb-4">
        <div className="nx-label mb-2">Fitur Pro</div>
        <div className="flex flex-wrap gap-2">
          {Object.entries(PRO_FEATURES)
            .filter(([k]) => k !== "unlimited_agents")
            .map(([key, label]) => {
              const on = status.valid && status.features.includes(key);
              return (
                <span
                  key={key}
                  className={`inline-flex items-center gap-1.5 border px-2 py-1 text-[11px] ${
                    on
                      ? "border-nexus-accent/40 bg-nexus-accent/10 text-nexus-text"
                      : "border-nexus-border text-nexus-subtle"
                  }`}
                >
                  {on ? <Ic.check className="h-3.5 w-3.5 text-nexus-accent" /> : <Ic.lock className="h-3.5 w-3.5" />}
                  {label}
                </span>
              );
            })}
        </div>
      </div>

      {status.valid ? (
        <div className="flex flex-wrap items-center gap-2">
          <button className="nx-btn-ghost" onClick={recheck} disabled={busy}>
            <Ic.refresh className={`h-4 w-4 ${busy ? "animate-spin" : ""}`} /> Periksa status
          </button>
          <button className="nx-btn-ghost" onClick={onClear} disabled={busy}>
            <Ic.close className="h-4 w-4" /> Hapus lisensi
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {/* AKTIVASI VIA KODE (utama) */}
          <div>
            <label className="nx-label">Kode aktivasi</label>
            <div className="flex gap-2">
              <input
                className="nx-input font-mono uppercase tracking-wider"
                placeholder="NEXUS-XXXXX-XXXXX-XXXXX-XXXXX"
                value={code}
                onChange={(e) => setCode(e.target.value.toUpperCase())}
                onKeyDown={(e) => e.key === "Enter" && activate()}
              />
              <button className="nx-btn-primary shrink-0" onClick={activate} disabled={busy}>
                {busy ? <Ic.refresh className="h-4 w-4 animate-spin" /> : <Ic.check className="h-4 w-4" />}
                Aktifkan
              </button>
            </div>
          </div>

          {status.api_configured === false && (
            <p className="flex items-start gap-2 border border-severity-medium/30 bg-severity-medium/10 p-2.5 text-[11px] leading-relaxed text-yellow-200">
              <Ic.alert className="mt-0.5 h-4 w-4 shrink-0" />
              Server aktivasi belum dikonfigurasi pada build ini. Kode online belum bisa dipakai
              sampai vendor mengatur URL server lisensi.
            </p>
          )}

          <p className="text-[11px] leading-relaxed text-nexus-subtle">
            Kode bersifat <b>sekali pakai</b> & terkunci ke perangkat ini. Edisi Free mencakup modul
            dasar (maks. 2 agent). Beli kode untuk membuka fitur Pro selama 30 hari.
          </p>

          {/* TOKEN MANUAL (enterprise/offline) — sekunder */}
          <button
            className="text-[11px] text-nexus-muted underline-offset-2 hover:text-nexus-text hover:underline"
            onClick={() => setManualOpen((o) => !o)}
          >
            {manualOpen ? "− Sembunyikan" : "+ Punya token manual? (enterprise / offline)"}
          </button>
          {manualOpen && (
            <div className="space-y-2 border-t border-nexus-border pt-3">
              <textarea
                className="nx-input h-16 resize-none font-mono text-xs"
                placeholder="Tempel token lisensi manual…"
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
              <div className="flex flex-wrap items-center gap-2">
                <button className="nx-btn-ghost" onClick={() => applyManual(token)} disabled={busy}>
                  <Ic.check className="h-4 w-4" /> Terapkan token
                </button>
                <button className="nx-btn-ghost" onClick={() => fileRef.current?.click()} disabled={busy}>
                  <Ic.folder className="h-4 w-4" /> Unggah file .license
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      <input ref={fileRef} type="file" accept=".license,.txt,.key" className="hidden" onChange={onFile} />
    </div>
  );
};

const Stat: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="border border-nexus-border p-2.5">
    <div className="text-[10px] uppercase tracking-wider text-nexus-subtle">{label}</div>
    <div className="mt-0.5 truncate font-medium text-nexus-text" title={value}>
      {value}
    </div>
  </div>
);

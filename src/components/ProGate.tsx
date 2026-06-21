// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/ProGate.tsx — gerbang fitur/halaman Pro (UX) + guard rute.
// Enforcement keras tetap di backend (runner.py + core/desktop_license.py);
// ini menyembunyikan/mengunci UI agar jelas mana yang berbayar.
import React from "react";
import { Outlet, useNavigate } from "react-router-dom";
import { Ic } from "../lib/icons";
import { useLicenseStore } from "../app/store/license.store";
import { PRO_FEATURES } from "../lib/license";

function LockScreen({ label, tier }: { label: string; tier: string }) {
  const navigate = useNavigate();
  return (
    <div className="mx-auto flex min-h-full max-w-xl flex-col items-center justify-center p-6 text-center animate-fade-in">
      <div className="mb-4 bg-nexus-accent/10 p-4">
        <Ic.lock className="h-9 w-9 text-nexus-accent" />
      </div>
      <span className="mb-3 inline-flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider text-nexus-accent">
        Fitur Pro
      </span>
      <h1 className="text-2xl font-bold text-nexus-text">{label} terkunci</h1>
      <p className="mt-2 max-w-md text-sm leading-relaxed text-nexus-muted">
        Modul ini butuh lisensi <b>Pro</b> atau <b>Enterprise</b>. Edisi kamu saat ini:{" "}
        <span className="font-semibold uppercase text-nexus-text">{tier}</span>. Unggah file lisensi
        (.license) atau tempel token-nya untuk membukanya.
      </p>
      <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
        <button className="nx-btn-primary" onClick={() => navigate("/settings")}>
          <Ic.lock className="h-4 w-4" /> Buka Settings → Lisensi
        </button>
        <a
          className="nx-btn-ghost"
          href="https://pypi.org/project/nexus-fleet/"
          target="_blank"
          rel="noreferrer"
        >
          Pelajari edisi
        </a>
      </div>
    </div>
  );
}

function Checking() {
  return (
    <div className="flex h-full items-center justify-center p-6 text-nexus-muted">
      <Ic.refresh className="mr-2 h-4 w-4 animate-spin" /> Memeriksa lisensi…
    </div>
  );
}

/**
 * Bungkus konten Pro. `feature` = cek fitur spesifik; tanpa `feature` =
 * cukup punya lisensi valid apa pun.
 */
export const ProGate: React.FC<{
  feature?: string;
  title?: string;
  children: React.ReactNode;
}> = ({ feature, title, children }) => {
  const loaded = useLicenseStore((s) => s.loaded);
  const status = useLicenseStore((s) => s.status);
  const has = useLicenseStore((s) => s.has);

  if (!loaded) return <Checking />;

  const ok = feature ? has(feature) : !!status.valid;
  if (ok) return <>{children}</>;

  const label = title || (feature ? PRO_FEATURES[feature] || feature : "Modul Pro");
  return <LockScreen label={label} tier={status.tier} />;
};

/** Guard rute: render halaman bila berlisensi, jika tidak tampilkan layar terkunci. */
export const ProRouteGuard: React.FC = () => {
  const loaded = useLicenseStore((s) => s.loaded);
  const status = useLicenseStore((s) => s.status);

  if (!loaded) return <Checking />;
  if (status.valid) return <Outlet />;
  return <LockScreen label="Modul Pro" tier={status.tier} />;
};

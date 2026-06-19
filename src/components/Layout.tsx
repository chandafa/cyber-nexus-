// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/Layout.tsx — layout utama tiga-panel (SDD bagian 9.1).
import React, { useEffect } from "react";
import { Outlet, useNavigate } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { InstallModal } from "./InstallModal";
import { ToastHost } from "./Toast";
import { useSettingsStore } from "../app/store/settings.store";
import { useLicenseStore } from "../app/store/license.store";
import { isTauri } from "../lib/tauri";

export const Layout: React.FC = () => {
  const navigate = useNavigate();
  const { loadSettings, loaded, onboardingComplete, refreshWsl, refreshDeps } =
    useSettingsStore();
  const loadLicense = useLicenseStore((s) => s.load);
  const validateLicense = useLicenseStore((s) => s.validate);

  useEffect(() => {
    loadSettings();
    // Saat aplikasi dibuka: nyalakan WSL lebih awal & deteksi tool terpasang
    // (termasuk yang tersedia via WSL) secara otomatis.
    if (isTauri()) {
      refreshWsl();
      refreshDeps();
    }
    // Muat edisi/lisensi untuk gerbang fitur Pro, lalu validasi ulang ke server
    // (deteksi revoke/expired) best-effort.
    loadLicense().then(() => validateLicense());
  }, [loadSettings, refreshWsl, refreshDeps, loadLicense, validateLicense]);

  useEffect(() => {
    if (loaded && isTauri() && !onboardingComplete()) {
      navigate("/setup", { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loaded]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-nexus-bg">
      <Sidebar />
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {!isTauri() && (
          <div className="bg-severity-medium/20 px-4 py-1.5 text-center text-xs text-yellow-200">
            Mode preview browser — backend Tauri tidak aktif. Jalankan{" "}
            <code className="font-mono">npm run tauri:dev</code> untuk fungsi penuh.
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-auto">
          <Outlet />
        </div>
      </main>
      <InstallModal />
      <ToastHost />
    </div>
  );
};

// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/InstallModal.tsx
// Modal progres instalasi (streaming). Karena install jalan di thread latar,
// UI tetap responsif walau choco/UAC berlangsung lama.
import React from "react";
import { Ic } from "../lib/icons";
import { ScanConsole } from "./ScanConsole";
import { StatusBadge } from "./StatusBadge";
import { useSettingsStore } from "../app/store/settings.store";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";

export const InstallModal: React.FC = () => {
  const open = useSettingsStore((s) => s.installModalOpen);
  const close = useSettingsStore((s) => s.closeInstallModal);
  const scan = useScanRuntimeStore((s) => s.scans["install"]);
  // ScanConsole butuh ref; modul install tidak memakai start dari sini.
  const dummyRef = React.useRef<any>(null);

  if (!open) return null;

  const running = scan?.running ?? false;
  const result = scan?.result;
  const installed: string[] = result
    ? Object.entries(result.results || {})
        .filter(([, v]) => v)
        .map(([k]) => k)
    : [];
  const manual: string[] = result?.manual || [];
  const linuxOnly: string[] = result?.linux_only || [];
  const rebootRequired: boolean = result?.reboot_required === true;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-6">
      <div className="flex h-[80vh] w-full max-w-3xl flex-col border border-nexus-border bg-nexus-surface shadow-menu">
        <div className="flex items-center justify-between border-b border-nexus-hairline px-4 py-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-nexus-text">
            <Ic.install className="h-4 w-4 text-nexus-accent" /> Instalasi Tools
            <StatusBadge status={scan?.status ?? "running"} />
          </div>
          <button
            className="nx-btn-ghost px-3 py-1.5 text-xs"
            onClick={close}
            disabled={running}
            title={running ? "Tunggu instalasi selesai" : "Tutup"}
          >
            {running ? "Menginstall…" : "Tutup & Perbarui"}
          </button>
        </div>

        {result && (
          <div className="space-y-1 border-b border-nexus-hairline px-4 py-2 text-xs">
            {installed.length > 0 && (
              <div className="text-nexus-green">✓ Terpasang: {installed.join(", ")}</div>
            )}
            {linuxOnly.length > 0 && (
              <div className="text-nexus-muted">
                ⓘ Opsional (hanya Linux/WSL, bukan error): {linuxOnly.join(", ")}
              </div>
            )}
            {manual.length > 0 && (
              <div className="text-severity-medium">⚠ Perlu manual: {manual.join(", ")}</div>
            )}
            {rebootRequired && (
              <div className="text-severity-medium">
                ⟳ WSL terpasang — <b>RESTART komputer</b>, lalu buka Nexus & klik tombol WSL sekali
                lagi untuk menyelesaikan setup.
              </div>
            )}
          </div>
        )}

        <div className="min-h-0 flex-1">
          <ScanConsole ref={dummyRef} module="install" />
        </div>

        <div className="border-t border-nexus-hairline px-4 py-2 text-[11px] text-nexus-muted">
          Jika muncul prompt UAC (Administrator), izinkan agar Chocolatey bisa memasang. Tool
          tanpa-admin (binary resmi GitHub / pip) terpasang otomatis ke{" "}
          <code className="font-mono">~/.nexus/tools/bin</code>.
        </div>
      </div>
    </div>
  );
};

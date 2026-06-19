// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/lib/security.ts
// Hardening UI: mempersulit pengguna awam melihat/inspeksi source aplikasi.
//
// PENTING (jujur soal batasannya): ini DETERRENT, bukan proteksi mutlak. Bundle
// frontend tetap ada di dalam aplikasi dan bisa diekstrak oleh yang gigih.
// Lapisan utamanya ada di build RILIS: Tauri TIDAK menyertakan web inspector
// kecuali feature `devtools` diaktifkan (kita tidak mengaktifkannya), sehingga
// inspector benar-benar tidak tersedia di aplikasi rilis.
//
// Guard di bawah hanya AKTIF DI PRODUKSI (import.meta.env.PROD) supaya devtools
// tetap bisa dipakai saat pengembangan (`npm run tauri dev`).

export function installSecurityGuards(): void {
  if (!import.meta.env.PROD) return; // dev: biarkan devtools untuk ngoding

  // 1. Nonaktifkan menu klik-kanan (menghilangkan entri "Inspect"/"View source").
  window.addEventListener(
    "contextmenu",
    (e) => e.preventDefault(),
    { capture: true },
  );

  // 2. Blokir shortcut pembuka devtools & view-source.
  window.addEventListener(
    "keydown",
    (e) => {
      const k = e.key.toLowerCase();
      const blocked =
        e.key === "F12" ||
        // Ctrl/Cmd+Shift+I / J / C → devtools / inspect element
        ((e.ctrlKey || e.metaKey) && e.shiftKey && (k === "i" || k === "j" || k === "c")) ||
        // Ctrl/Cmd+U → view-source
        ((e.ctrlKey || e.metaKey) && k === "u");
      if (blocked) {
        e.preventDefault();
        e.stopPropagation();
      }
    },
    { capture: true },
  );
}

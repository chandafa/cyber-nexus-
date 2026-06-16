// src/lib/icons.tsx
// Registry ikon terpusat memakai Solar icon set (via Iconify), didaftarkan
// secara OFFLINE agar sesuai prinsip offline-first SDD §12 (tanpa fetch jaringan).
import React from "react";
import { Icon, addCollection } from "@iconify/react";
// Subset Solar (hanya ikon yang dipakai) — di-generate dari icons.tsx.
// Lihat scripts: ekstrak dari @iconify-json/solar. Offline & ringan.
import solarSubset from "./solar-subset.json";

// Daftarkan koleksi Solar (subset) sekali saat modul dimuat (offline).
addCollection(solarSubset as any);

export type IconComp = React.FC<{ className?: string; style?: React.CSSProperties }>;

const mk =
  (name: string): IconComp =>
  ({ className, style }) =>
    <Icon icon={name} className={className} style={style} />;

/** Ikon Solar terpilih, dipakai di seluruh aplikasi. */
export const Ic = {
  // Modul / navigasi
  dashboard: mk("solar:widget-5-bold-duotone"),
  port: mk("solar:radar-2-bold-duotone"),
  network: mk("solar:transmission-bold-duotone"),
  vuln: mk("solar:bug-bold-duotone"),
  password: mk("solar:key-bold-duotone"),
  log: mk("solar:document-text-bold-duotone"),
  mapper: mk("solar:routing-2-bold-duotone"),
  defense: mk("solar:shield-check-bold-duotone"),
  report: mk("solar:clipboard-list-bold-duotone"),
  history: mk("solar:history-2-bold-duotone"),
  settings: mk("solar:settings-bold-duotone"),
  logo: mk("solar:shield-star-bold-duotone"),

  // Statistik / status
  toolsCheck: mk("solar:checklist-minimalistic-bold-duotone"),
  activity: mk("solar:pulse-bold-duotone"),
  alert: mk("solar:shield-warning-bold-duotone"),
  server: mk("solar:server-bold-duotone"),
  info: mk("solar:info-circle-bold-duotone"),

  // Kontrol
  play: mk("solar:play-bold"),
  stop: mk("solar:stop-bold"),
  trash: mk("solar:trash-bin-trash-bold"),
  refresh: mk("solar:refresh-bold"),
  download: mk("solar:download-minimalistic-bold"),
  search: mk("solar:magnifer-bold"),
  folder: mk("solar:folder-with-files-bold-duotone"),
  copy: mk("solar:copy-bold"),
  arrowRight: mk("solar:arrow-right-linear"),
  save: mk("solar:diskette-bold"),
  hashId: mk("solar:magnifer-zoom-in-bold-duotone"),
  terminal: mk("solar:command-bold-duotone"),
  sort: mk("solar:sort-vertical-bold"),

  // Indikator
  check: mk("solar:check-circle-bold"),
  checkSmall: mk("solar:check-read-bold"),
  close: mk("solar:close-circle-bold"),
  warning: mk("solar:danger-triangle-bold"),
  lock: mk("solar:lock-keyhole-bold-duotone"),

  // Tema & dropdown & instalasi
  sun: mk("solar:sun-2-bold"),
  moon: mk("solar:moon-bold"),
  chevronDown: mk("solar:alt-arrow-down-linear"),
  install: mk("solar:download-minimalistic-linear"),

  // Sidebar collapse/expand
  collapse: mk("solar:sidebar-minimalistic-linear"),
  expand: mk("solar:hamburger-menu-linear"),

  // Modul SDD v2
  ssl: mk("solar:lock-keyhole-minimalistic-bold-duotone"),
  exploit: mk("solar:bug-minimalistic-bold-duotone"),
  api: mk("solar:code-scan-bold-duotone"),
  container: mk("solar:box-minimalistic-bold-duotone"),
  cloud: mk("solar:cloud-bold-duotone"),
  wireless: mk("solar:wi-fi-router-minimalistic-bold-duotone"),
  asset: mk("solar:server-square-bold-duotone"),
  score: mk("solar:diagram-up-bold-duotone"),
  diff: mk("solar:transfer-horizontal-bold-duotone"),
  scheduler: mk("solar:calendar-bold-duotone"),
  attack: mk("solar:bolt-bold-duotone"),
  suite: mk("solar:shield-network-bold-duotone"),
  mitigation: mk("solar:clipboard-check-bold-duotone"),
  wordlistMgr: mk("solar:book-2-bold-duotone"),
  human: mk("solar:book-2-bold-duotone"),
};

export type IcName = keyof typeof Ic;

// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/lib/theme.ts — manajemen tema (gelap/terang + varian warna).
export interface ThemeDef {
  id: string;
  label: string;
  swatch: string; // warna preview (bg + accent)
  accent: string;
}

export const THEMES: ThemeDef[] = [
  { id: "dark", label: "Dark", swatch: "#1e1e1e", accent: "#8b7bff" },
  { id: "light", label: "Light", swatch: "#f3f3f3", accent: "#6f42c1" },
  { id: "blue", label: "Dark Blue", swatch: "#0d1426", accent: "#60a5fa" },
  { id: "red", label: "Dark Red", swatch: "#1a0e10", accent: "#f87171" },
  { id: "black", label: "Dark Black", swatch: "#000000", accent: "#8b7bff" },
  { id: "green", label: "Matrix Green", swatch: "#08120c", accent: "#34d399" },
  { id: "purple", label: "Deep Purple", swatch: "#171026", accent: "#a78bfa" },
  { id: "nord", label: "Nord", swatch: "#2e3440", accent: "#88c0d0" },
];

const THEME_IDS = THEMES.map((t) => t.id);

export function applyTheme(theme: string) {
  const id = THEME_IDS.includes(theme) ? theme : "dark";
  const root = document.documentElement;
  root.classList.remove(...THEMES.map((t) => `theme-${t.id}`));
  root.classList.add(`theme-${id}`);
}

export function nextTheme(current: string | undefined): string {
  const i = THEME_IDS.indexOf(current || "dark");
  return THEME_IDS[(i + 1) % THEME_IDS.length];
}

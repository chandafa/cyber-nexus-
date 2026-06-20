// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// icons.js — ikon gaya Solar (Linear), di-inline sebagai SVG agar dashboard
// tetap berjalan offline di LAN (tanpa CDN/Iconify). currentColor mengikuti tema.
const ICON_PATHS = {
  overview:
    '<path d="M3 7a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/><path d="M13 5h6a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2h-6V5Z"/><path d="M13 15h6a2 2 0 0 1 2 2v0a2 2 0 0 1-2 2h-6v-4Z"/><path d="M3 17a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v0a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v0Z"/>',
  agents:
    '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  alerts:
    '<path d="M10.3 4.3 2.7 17.5A2 2 0 0 0 4.4 20.5h15.2a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 16.5h.01"/>',
  events:
    '<path d="M12 4a5 5 0 0 0-5 5v3l-1.5 3h13L17 12V9a5 5 0 0 0-5-5Z"/><path d="M10 19a2 2 0 0 0 4 0"/>',
  incidents:
    '<path d="M12 3 4 6v5c0 5 3.4 8 8 10 4.6-2 8-5 8-10V6l-8-3Z"/><path d="M12 8v4M12 15.5h.01"/>',
  policy:
    '<path d="M12 3 4 6v6c0 4.4 3.2 7.6 8 9 4.8-1.4 8-4.6 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>',
  license:
    '<circle cx="8" cy="12" r="4"/><path d="M11 12h9M17 12v3M20 12v3"/>',
  help:
    '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.4 2.3c-.8.3-.9.8-.9 1.7M12 16.5h.01"/>',
  language:
    '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 16 0 18M12 3c-2.5 2.5-2.5 16 0 18"/>',
  sun:
    '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/>',
  moon:
    '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5Z"/>',
  refresh:
    '<path d="M4 12a8 8 0 0 1 13.5-5.8L20 8M20 4v4h-4"/><path d="M20 12a8 8 0 0 1-13.5 5.8L4 16M4 20v-4h4"/>',
  bolt:
    '<path d="M13 3 4 14h6l-1 7 9-11h-6l1-7Z"/>',
  trash:
    '<path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12"/>',
  plug:
    '<path d="M9 3v5M15 3v5M7 8h10v3a5 5 0 0 1-10 0V8ZM12 16v5"/>',
  online:
    '<circle cx="12" cy="12" r="9"/><path d="m8 12 2.5 2.5L16 9"/>',
  offline:
    '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
  logo:
    '<path d="M12 2 22 12 12 22 2 12 12 2Z"/><path d="M12 7 17 12 12 17 7 12 12 7Z"/>',
  search:
    '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  save:
    '<path d="M5 4h11l3 3v13H5V4Z"/><path d="M8 4v5h7V4M8 20v-6h8v6"/>',
};

/** Kembalikan markup SVG ikon Solar-style (24px, currentColor). */
function icon(name, size = 20) {
  const p = ICON_PATHS[name] || ICON_PATHS.help;
  return `<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"
    aria-hidden="true">${p}</svg>`;
}

/** Ganti semua <i data-icon="name"></i> jadi SVG inline. */
function hydrateIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((el) => {
    const size = parseInt(el.getAttribute("data-size") || "20", 10);
    el.innerHTML = icon(el.getAttribute("data-icon"), size);
  });
}

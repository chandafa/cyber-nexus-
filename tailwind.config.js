/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      // Warna memakai CSS variable (channel RGB) agar mendukung tema gelap & terang
      // serta utilitas opacity (mis. bg-nexus-accent/15).
      colors: {
        nexus: {
          bg: "rgb(var(--nx-bg) / <alpha-value>)",
          surface: "rgb(var(--nx-surface) / <alpha-value>)",
          panel: "rgb(var(--nx-panel) / <alpha-value>)",
          elevated: "rgb(var(--nx-elevated) / <alpha-value>)",
          border: "rgb(var(--nx-border) / <alpha-value>)",
          hairline: "rgb(var(--nx-hairline) / <alpha-value>)",
          accent: "rgb(var(--nx-accent) / <alpha-value>)",
          accent2: "rgb(var(--nx-accent2) / <alpha-value>)",
          green: "rgb(var(--nx-green) / <alpha-value>)",
          text: "rgb(var(--nx-text) / <alpha-value>)",
          muted: "rgb(var(--nx-muted) / <alpha-value>)",
          subtle: "rgb(var(--nx-subtle) / <alpha-value>)",
        },
        severity: {
          critical: "rgb(var(--sev-critical) / <alpha-value>)",
          high: "rgb(var(--sev-high) / <alpha-value>)",
          medium: "rgb(var(--sev-medium) / <alpha-value>)",
          low: "rgb(var(--sev-low) / <alpha-value>)",
          info: "rgb(var(--sev-info) / <alpha-value>)",
        },
      },
      // Minimalis ala VS Code: sudut nyaris kotak.
      borderRadius: {
        none: "0",
        sm: "2px",
        DEFAULT: "2px",
        md: "2px",
        lg: "3px",
        xl: "3px",
        "2xl": "3px",
        full: "9999px",
      },
      boxShadow: {
        soft: "none",
        glow: "none",
        menu: "0 4px 14px rgba(0,0,0,0.35)",
      },
      fontFamily: {
        // Inter (bundled, offline) — bersih & minimalis.
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "Consolas", "monospace"],
      },
      fontSize: {
        xs: ["11px", "1.5"],
        sm: ["12.5px", "1.5"],
        base: ["13.5px", "1.55"],
      },
      keyframes: {
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.18s ease-out",
      },
    },
  },
  plugins: [],
};

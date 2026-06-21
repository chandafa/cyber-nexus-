import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// Tauri expects a fixed port, fail if that port is not available
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // prevent vite from obscuring rust errors
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // tell vite to ignore watching `src-tauri`, python-runtime, and python folders
      ignored: [
        "**/src-tauri/**",
        "**/python-runtime/**",
        "**/python/**"
      ],
    },
  },
  // to access the Tauri environment variables set by the CLI with information about the current target
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    // Tauri uses Chromium on Windows and WebKit on macOS and Linux
    target: process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari13",
    minify: !process.env.TAURI_ENV_DEBUG ? "esbuild" : false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
  },
});

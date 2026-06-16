// src/app/store/settings.store.ts
import { create } from "zustand";
import {
  getSettings,
  setSetting as apiSetSetting,
  checkDependencies,
  wslStatus as apiWslStatus,
  setBackend as apiSetBackend,
  setRealMode as apiSetRealMode,
  isTauri,
  type ToolStatus,
  type WslStatus,
  type Backend,
} from "../../lib/tauri";
import { applyTheme } from "../../lib/theme";
import { useScanRuntimeStore } from "./scanRuntime.store";

interface SettingsState {
  settings: Record<string, string>;
  deps: Record<string, ToolStatus>;
  loading: boolean;
  loaded: boolean;
  installModalOpen: boolean;
  wsl: WslStatus | null;
  wslLoading: boolean;
  loadSettings: () => Promise<void>;
  refreshDeps: () => Promise<void>;
  update: (key: string, value: string) => Promise<void>;
  install: (tools: string[]) => void;
  closeInstallModal: () => void;
  onboardingComplete: () => boolean;
  missingRequired: () => string[];
  missingAny: () => string[];
  // --- backend WSL ---
  refreshWsl: () => Promise<void>;
  chooseBackend: (backend: Backend, distro?: string) => Promise<void>;
  provisionWsl: (tools: string[]) => void;
  setRealMode: (noDemo: boolean) => Promise<void>;
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
  settings: {},
  deps: {},
  loading: false,
  loaded: false,
  installModalOpen: false,
  wsl: null,
  wslLoading: false,

  loadSettings: async () => {
    if (!isTauri()) {
      const settings = { onboarding_complete: "false", theme: "dark" };
      applyTheme("dark");
      set({ settings, loaded: true });
      return;
    }
    try {
      const settings = await getSettings();
      applyTheme(settings.theme || "dark");
      set({ settings, loaded: true });
    } catch (e) {
      console.error("loadSettings", e);
      set({ loaded: true });
    }
  },

  refreshDeps: async () => {
    if (!isTauri()) return;
    set({ loading: true });
    try {
      const { results } = await checkDependencies();
      set({ deps: results, loading: false });
    } catch (e) {
      console.error("refreshDeps", e);
      set({ loading: false });
    }
  },

  update: async (key, value) => {
    set((s) => ({ settings: { ...s.settings, [key]: value } }));
    if (key === "theme") applyTheme(value);
    if (isTauri()) {
      try {
        await apiSetSetting(key, value);
      } catch (e) {
        console.error("setSetting", e);
      }
    }
  },

  // Instalasi STREAMING & non-blocking (lewat jalur scan di thread latar),
  // sehingga UAC/choco yang lama tidak membekukan UI (fix force-close).
  install: (tools) => {
    if (!isTauri() || tools.length === 0) return;
    useScanRuntimeStore.getState().start({
      module: "install",
      command: "install_tools",
      args: ["--tools", tools.join(",")],
      target: tools.join(", "),
    });
    set({ installModalOpen: true });
  },

  closeInstallModal: () => {
    set({ installModalOpen: false });
    get().refreshDeps();
    get().refreshWsl();
  },

  // ----------------------------------------------------------- backend WSL
  refreshWsl: async () => {
    if (!isTauri()) return;
    set({ wslLoading: true });
    try {
      const wsl = await apiWslStatus();
      set({ wsl, wslLoading: false });
    } catch (e) {
      console.error("refreshWsl", e);
      set({ wslLoading: false });
    }
  },

  chooseBackend: async (backend, distro = "") => {
    // Optimistic update agar UI langsung responsif.
    set((s) => ({ wsl: s.wsl ? { ...s.wsl, backend, active_distro: distro || s.wsl.active_distro } : s.wsl }));
    if (!isTauri()) return;
    try {
      await apiSetBackend(backend, distro);
      await get().refreshWsl();
      await get().refreshDeps();
    } catch (e) {
      console.error("chooseBackend", e);
    }
  },

  setRealMode: async (noDemo) => {
    set((s) => ({ wsl: s.wsl ? { ...s.wsl, no_demo: noDemo } : s.wsl }));
    if (!isTauri()) return;
    try {
      await apiSetRealMode(noDemo);
      await get().refreshWsl();
    } catch (e) {
      console.error("setRealMode", e);
    }
  },

  // Provisioning WSL (install + konfigurasi otomatis) lalu pasang tools — streaming
  // lewat modal yang sama, agar UAC/installer yang lama tidak membekukan UI.
  provisionWsl: (tools) => {
    if (!isTauri()) return;
    useScanRuntimeStore.getState().start({
      module: "install",
      command: "wsl_provision",
      args: tools.length ? ["--tools", tools.join(",")] : [],
      target: "WSL",
    });
    set({ installModalOpen: true });
  },

  onboardingComplete: () => get().settings.onboarding_complete === "true",

  missingRequired: () => {
    const deps = get().deps;
    return Object.entries(deps)
      .filter(([, v]) => v.required && !v.installed)
      .map(([k]) => k);
  },

  missingAny: () => {
    const deps = get().deps;
    return Object.entries(deps)
      .filter(([, v]) => !v.installed)
      .map(([k]) => k);
  },
}));

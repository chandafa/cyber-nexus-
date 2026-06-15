// src/components/Sidebar.tsx — navigasi kiri dengan collapse + theme picker.
import React, { useEffect, useRef, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { Ic, type IconComp } from "../lib/icons";
import { useSettingsStore } from "../app/store/settings.store";
import { THEMES } from "../lib/theme";
import { cn } from "../lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: IconComp;
  end?: boolean;
}

const GROUPS: { title: string; icon: IconComp; items: NavItem[] }[] = [
  {
    title: "Umum",
    icon: Ic.dashboard,
    items: [
      { to: "/", label: "Dashboard", icon: Ic.dashboard, end: true },
      { to: "/security-score", label: "Security Score", icon: Ic.score },
      { to: "/terminal", label: "Terminal", icon: Ic.terminal },
    ],
  },
  {
    title: "Recon & Scan",
    icon: Ic.port,
    items: [
      { to: "/port-scanner", label: "Port Scanner", icon: Ic.port },
      { to: "/network-scanner", label: "Network Scanner", icon: Ic.network },
      { to: "/network-mapper", label: "Network Mapper", icon: Ic.mapper },
      { to: "/dns-recon", label: "Subdomain / DNS Recon", icon: Ic.mapper },
      { to: "/asset-inventory", label: "Asset Inventory", icon: Ic.asset },
    ],
  },
  {
    title: "Web & API",
    icon: Ic.api,
    items: [
      { to: "/vuln-scanner", label: "Vulnerability Scanner", icon: Ic.vuln },
      { to: "/ssl-auditor", label: "SSL/TLS Auditor", icon: Ic.ssl },
      { to: "/api-tester", label: "API Tester", icon: Ic.api },
      { to: "/dir-fuzzer", label: "Directory Fuzzer", icon: Ic.search },
    ],
  },
  {
    title: "Offensive",
    icon: Ic.attack,
    items: [
      { to: "/password-auditor", label: "Password Auditor", icon: Ic.password },
      { to: "/hash-tool", label: "Hash Identifier & Cracker", icon: Ic.hashId },
      { to: "/exploit-lookup", label: "Exploit Lookup", icon: Ic.exploit },
      { to: "/attack-simulation", label: "Attack Simulation", icon: Ic.attack },
      { to: "/listener", label: "Reverse Shell / Listener", icon: Ic.exploit },
      { to: "/wireless-auditor", label: "Wireless Auditor", icon: Ic.wireless },
    ],
  },
  {
    title: "Cloud & Container",
    icon: Ic.cloud,
    items: [
      { to: "/container-scanner", label: "Container Scanner", icon: Ic.container },
      { to: "/cloud-checker", label: "Cloud Checker", icon: Ic.cloud },
    ],
  },
  {
    title: "Analisis",
    icon: Ic.log,
    items: [
      { to: "/log-analyzer", label: "Log Analyzer", icon: Ic.log },
      { to: "/scan-diff", label: "Scan Diff", icon: Ic.diff },
    ],
  },
  {
    title: "Defense & Laporan",
    icon: Ic.defense,
    items: [
      { to: "/defense-monitor", label: "Defense Monitor", icon: Ic.defense },
      { to: "/defense-suite", label: "Defense Suite", icon: Ic.suite },
      { to: "/report", label: "Report Generator", icon: Ic.report },
    ],
  },
  {
    title: "Sistem",
    icon: Ic.settings,
    items: [
      { to: "/history", label: "History", icon: Ic.history },
      { to: "/scheduler", label: "Scheduler", icon: Ic.scheduler },
      { to: "/wordlist-manager", label: "Wordlist Manager", icon: Ic.wordlistMgr },
      { to: "/settings", label: "Settings", icon: Ic.settings },
    ],
  },
];

export const Sidebar: React.FC = () => {
  const theme = useSettingsStore((s) => s.settings.theme) || "dark";
  const collapsed = useSettingsStore((s) => s.settings.sidebar_collapsed) === "true";
  const update = useSettingsStore((s) => s.update);
  const [pickerOpen, setPickerOpen] = useState(false);
  const pickerRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  // Grup yang memuat rute aktif (untuk auto-expand accordion).
  const activeGroup = GROUPS.find((g) =>
    g.items.some((i) => (i.to === "/" ? location.pathname === "/" : location.pathname.startsWith(i.to)))
  )?.title;
  const [openGroups, setOpenGroups] = useState<string[]>(
    activeGroup ? [activeGroup] : [GROUPS[0].title]
  );
  useEffect(() => {
    if (activeGroup) setOpenGroups((g) => (g.includes(activeGroup) ? g : [...g, activeGroup]));
  }, [activeGroup]);
  const toggleGroup = (t: string) =>
    setOpenGroups((g) => (g.includes(t) ? g.filter((x) => x !== t) : [...g, t]));

  useEffect(() => {
    if (!pickerOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) setPickerOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [pickerOpen]);

  const current = THEMES.find((t) => t.id === theme) || THEMES[0];

  const linkCls = ({ isActive }: { isActive: boolean }) =>
    cn(
      "group flex items-center rounded-sm text-sm transition-colors duration-100",
      collapsed ? "justify-center px-0 py-2.5" : "gap-3 px-3 py-2",
      isActive
        ? "bg-nexus-accent/15 text-nexus-text font-medium"
        : "text-nexus-muted hover:bg-nexus-panel hover:text-nexus-text"
    );

  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r border-nexus-hairline bg-nexus-surface transition-[width] duration-150",
        collapsed ? "w-14" : "w-60"
      )}
    >
      {/* Header + collapse toggle */}
      <div className={cn("flex items-center py-3.5", collapsed ? "justify-center px-0" : "gap-2.5 px-4")}>
        <div className="bg-nexus-accent/15 p-1.5">
          <Ic.logo className="h-5 w-5 text-nexus-accent" />
        </div>
        {!collapsed && (
          <div className="flex-1">
            <div className="text-base font-bold leading-none tracking-tight text-nexus-text">NEXUS</div>
            <div className="mt-1 text-[10px] uppercase tracking-[0.18em] text-nexus-subtle">
              Security Agent
            </div>
          </div>
        )}
        {!collapsed && (
          <button
            className="text-nexus-subtle hover:text-nexus-text"
            onClick={() => update("sidebar_collapsed", "true")}
            title="Ciutkan sidebar"
          >
            <Ic.collapse className="h-4 w-4" />
          </button>
        )}
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto overflow-x-hidden px-2 py-2">
        {/* Collapsed → ikon datar; Expanded → accordion grup (kurangi scroll) */}
        {collapsed
          ? GROUPS.flatMap((g) => g.items).map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end} className={linkCls} title={n.label}>
                {({ isActive }) => (
                  <n.icon
                    className={cn(
                      "h-[18px] w-[18px] shrink-0 transition-colors",
                      isActive ? "text-nexus-accent" : "text-nexus-subtle group-hover:text-nexus-muted"
                    )}
                  />
                )}
              </NavLink>
            ))
          : GROUPS.map((group) => {
              const open = openGroups.includes(group.title);
              return (
                <div key={group.title}>
                  <button
                    onClick={() => toggleGroup(group.title)}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-sm px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] transition-colors hover:bg-nexus-panel/50",
                      group.title === activeGroup ? "text-nexus-muted" : "text-nexus-subtle"
                    )}
                  >
                    <group.icon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        group.title === activeGroup ? "text-nexus-accent" : "text-nexus-subtle"
                      )}
                    />
                    <span className="flex-1 text-left">{group.title}</span>
                    <Ic.chevronDown
                      className={cn("h-3.5 w-3.5 transition-transform", open ? "rotate-180" : "")}
                    />
                  </button>
                  {open && (
                    <div className="space-y-0.5 pb-1.5 pt-0.5">
                      {group.items.map((n) => (
                        <NavLink key={n.to} to={n.to} end={n.end} className={linkCls}>
                          {({ isActive }) => (
                            <>
                              <n.icon
                                className={cn(
                                  "h-[18px] w-[18px] shrink-0 transition-colors",
                                  isActive ? "text-nexus-accent" : "text-nexus-subtle group-hover:text-nexus-muted"
                                )}
                              />
                              <span className="truncate">{n.label}</span>
                            </>
                          )}
                        </NavLink>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
      </nav>

      {/* Footer: expand (when collapsed) + theme picker */}
      <div
        ref={pickerRef}
        className={cn(
          "relative border-t border-nexus-hairline py-2.5",
          collapsed ? "flex flex-col items-center gap-2 px-0" : "flex items-center justify-between px-3"
        )}
      >
        {collapsed ? (
          <button
            className="text-nexus-subtle hover:text-nexus-text"
            onClick={() => update("sidebar_collapsed", "false")}
            title="Perluas sidebar"
          >
            <Ic.expand className="h-4 w-4" />
          </button>
        ) : (
          <span className="text-[10px] text-nexus-subtle">v1.0 · ethical use</span>
        )}

        <button
          className={cn(
            "flex items-center gap-1.5 border border-nexus-border text-[11px] text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text",
            collapsed ? "h-7 w-7 justify-center p-0" : "px-2 py-1"
          )}
          onClick={() => setPickerOpen((o) => !o)}
          title="Ganti tema"
        >
          <span className="h-3.5 w-3.5 rounded-full border border-nexus-border" style={{ background: current.accent }} />
          {!collapsed && current.label}
        </button>

        {pickerOpen && (
          <div
            className={cn(
              "absolute bottom-11 z-50 w-44 border border-nexus-border bg-nexus-panel p-1 shadow-menu animate-fade-in",
              collapsed ? "left-12" : "right-2"
            )}
          >
            <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-nexus-subtle">
              Tema
            </div>
            {THEMES.map((t) => (
              <button
                key={t.id}
                onClick={() => {
                  update("theme", t.id);
                  setPickerOpen(false);
                }}
                className={cn(
                  "flex w-full items-center gap-2 px-2 py-1.5 text-left text-[12px] transition-colors",
                  t.id === theme ? "bg-nexus-accent/15 text-nexus-text" : "text-nexus-muted hover:bg-nexus-elevated hover:text-nexus-text"
                )}
              >
                <span className="flex h-4 w-4 shrink-0 items-center overflow-hidden rounded-sm border border-nexus-border" style={{ background: t.swatch }}>
                  <span className="ml-auto h-full w-1/2" style={{ background: t.accent }} />
                </span>
                <span className="flex-1">{t.label}</span>
                {t.id === theme && <Ic.checkSmall className="h-3.5 w-3.5 text-nexus-accent" />}
              </button>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
};

// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/WAF.tsx — WAF control page with VHost, Custom Rules, and Tooltips (MVP)
// src/pages/WAF.tsx — WAF control page with VHost, Custom Rules, Tooltips and Download Logs (MVP)
import React, { useRef, useState, useEffect } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { buildArgs, runToolJson, isTauri } from "../lib/tauri";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";
import { exportTextFile } from "../lib/output";
import { open } from "@tauri-apps/plugin-dialog";

// Lightweight pure CSS-driven Info Tooltip (left-aligned to prevent clipping)
const HelpTip: React.FC<{ text: string }> = ({ text }) => {
  return (
    <span className="relative group inline-block ml-1 cursor-pointer select-none text-nexus-muted hover:text-nexus-accent">
      <span className="text-xs">ⓘ</span>
      <span className="absolute bottom-full right-0 mb-2 hidden group-hover:inline-block w-48 p-2 text-[10.5px] font-normal normal-case leading-normal text-nexus-text bg-nexus-elevated border border-nexus-border rounded shadow-md z-50 text-left">
        {text}
        <span className="absolute top-full right-2 border-4 border-transparent border-t-nexus-elevated"></span>
      </span>
    </span>
  );
};

interface LogEvent {
  ts: string;
  ip: string;
  rule: string;
  path: string;
  payload?: string;
  country_code?: string;
  country_name?: string;
}

const getFlagEmoji = (countryCode?: string) => {
  if (!countryCode || countryCode === "-") return "🌐";
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map(char => 127397 + char.charCodeAt(0));
  try {
    return String.fromCodePoint(...codePoints);
  } catch {
    return "🌐";
  }
};

const WafDashboard: React.FC<{ logs: LogEvent[]; stats: any | null }> = ({ logs, stats }) => {
  const totalRequests = stats?.total_requests ?? logs.length;
  const blockedRequests = stats?.blocked_attacks ?? logs.filter(l => !l.rule.startsWith("allow:") && !l.rule.startsWith("detect:")).length;
  const allowedRequests = totalRequests - blockedRequests;
  const allowRate = totalRequests ? Math.round((allowedRequests / totalRequests) * 100) : 100;

  let threatLevel = "Aman (SECURE)";
  let threatColor = "text-green-400";
  if (blockedRequests > 10) {
    threatLevel = "KRITIS (CRITICAL)";
    threatColor = "text-red-500 animate-pulse font-bold";
  } else if (blockedRequests > 3) {
    threatLevel = "TINGGI (HIGH)";
    threatColor = "text-orange-500 font-bold";
  } else if (blockedRequests > 0) {
    threatLevel = "SEDANG (MEDIUM)";
    threatColor = "text-yellow-400";
  }

  // Categories aggregation
  const categories = stats?.categories ?? {
    sql_injection: 0,
    xss: 0,
    path_traversal: 0,
    cmd_injection: 0,
    scanner_detected: 0,
    custom: 0,
  };

  if (!stats) {
    logs.forEach(l => {
      if (l.rule.startsWith("allow:") || l.rule.startsWith("detect:")) return;
      if (l.rule === "sql_injection") categories.sql_injection++;
      else if (l.rule === "xss") categories.xss++;
      else if (l.rule === "path_traversal") categories.path_traversal++;
      else if (l.rule === "cmd_injection") categories.cmd_injection++;
      else if (l.rule === "scanner_detected") categories.scanner_detected++;
      else categories.custom++;
    });
  }

  // Client IP Stats aggregation
  let ipStats: any[] = [];
  if (stats?.ip_stats) {
    ipStats = stats.ip_stats.slice(0, 6);
  } else {
    const ipStatsMap: Record<string, { ip: string; countryCode: string; countryName: string; total: number; blocked: number; lastSeen: string }> = {};
    logs.forEach(l => {
      if (!ipStatsMap[l.ip]) {
        ipStatsMap[l.ip] = {
          ip: l.ip,
          countryCode: l.country_code || "ID",
          countryName: l.country_name || "Indonesia",
          total: 0,
          blocked: 0,
          lastSeen: l.ts
        };
      }
      const stat = ipStatsMap[l.ip];
      stat.total++;
      if (!l.rule.startsWith("allow:") && !l.rule.startsWith("detect:")) {
        stat.blocked++;
      }
    });
    ipStats = Object.values(ipStatsMap).sort((a, b) => b.total - a.total).slice(0, 6);
  }

  // SVG Map coordinates
  const countryCoords: Record<string, { x: number; y: number }> = {
    ID: { x: 780, y: 310 }, // Target node (Indonesia)
    US: { x: 180, y: 150 },
    SG: { x: 740, y: 280 },
    NL: { x: 480, y: 110 },
    DE: { x: 500, y: 120 },
    CN: { x: 730, y: 180 },
    RU: { x: 670, y: 100 },
    JP: { x: 830, y: 160 },
    GB: { x: 450, y: 100 },
    FR: { x: 470, y: 130 },
    BR: { x: 350, y: 310 },
    AU: { x: 840, y: 350 },
  };

  // Generate background dot grid
  const spacing = 15;
  const gridDots: { x: number; y: number }[] = [];
  for (let x = spacing; x < 1000; x += spacing) {
    for (let y = spacing; y < 400; y += spacing) {
      let isLand = false;
      // Procedural continent boundary check
      if (x > 100 && x < 380 && y > 60 && y < 190) {
        if (!(x > 320 && y > 160)) isLand = true; // North America
      } else if (x > 250 && x < 400 && y >= 190 && y < 380) {
        if (y < 220 || x < 250 + (y - 190) * 0.7) isLand = true; // South America
      } else if (x >= 400 && x < 620 && y > 50 && y < 350) {
        if (y < 160) {
          if (x > 440) isLand = true; // Europe
        } else {
          if (x > 450 && x < 450 + (350 - y) * 0.8) isLand = true; // Africa
        }
      } else if (x >= 600 && x < 950 && y > 40 && y < 280) {
        if (!(x > 880 && y < 100)) isLand = true; // Asia
      } else if (x >= 700 && x < 950 && y >= 280 && y < 390) {
        isLand = true; // Indonesia / Australia
      }
      if (isLand) {
        gridDots.push({ x, y });
      }
    }
  }

  // Find active attacking countries in recent logs/stats
  const activeArcsMap: Record<string, { from: string; count: number }> = {};
  if (stats?.ip_stats) {
    stats.ip_stats.forEach((item: any) => {
      const cc = item.country_code;
      if (cc && cc !== "ID" && item.blocked > 0 && countryCoords[cc]) {
        if (!activeArcsMap[cc]) {
          activeArcsMap[cc] = { from: cc, count: 0 };
        }
        activeArcsMap[cc].count += item.blocked;
      }
    });
  } else {
    logs.forEach(l => {
      if (!l.rule.startsWith("allow:") && !l.rule.startsWith("detect:")) {
        const cc = l.country_code || "US";
        if (cc !== "ID" && countryCoords[cc]) {
          if (!activeArcsMap[cc]) {
            activeArcsMap[cc] = { from: cc, count: 0 };
          }
          activeArcsMap[cc].count++;
        }
      }
    });
  }
  const activeArcs = Object.values(activeArcsMap);

  return (
    <div className="p-4 space-y-4 bg-nexus-surface h-full overflow-auto">
      <style>{`
        @keyframes dash {
          to {
            stroke-dashoffset: -20;
          }
        }
        .animate-dash {
          animation: dash 1s linear infinite;
        }
      `}</style>

      {/* Threat map visualization */}
      <div className="bg-nexus-panel border border-nexus-hairline rounded-xl p-4 relative overflow-hidden h-[260px] flex flex-col justify-end">
        <div className="absolute top-3 left-3 text-[10px] text-nexus-muted uppercase tracking-wider font-semibold font-mono">Real-Time Threat Map</div>
        <div className="absolute top-3 right-3 flex items-center gap-1.5 text-[10.5px] font-mono">
          <span className="h-2 w-2 rounded-full bg-nexus-accent animate-ping" />
          <span className="text-nexus-text">Target: Jakarta, ID</span>
        </div>

        <svg className="w-full h-[200px]" viewBox="0 0 1000 400">
          <defs>
            <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ef4444" />
              <stop offset="100%" stopColor="#8b5cf6" />
            </linearGradient>
          </defs>

          {/* Dotted grid continents */}
          {gridDots.map((d, i) => (
            <circle key={i} cx={d.x} cy={d.y} r={1.5} className="fill-nexus-muted/20" />
          ))}

          {/* Attacking arcs */}
          {activeArcs.map((arc, i) => {
            const from = countryCoords[arc.from];
            const to = countryCoords.ID;
            const cx = (from.x + to.x) / 2;
            const cy = Math.min(from.y, to.y) - 60;
            const pathD = `M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}`;
            return (
              <g key={i}>
                <path
                  d={pathD}
                  fill="none"
                  stroke="url(#arcGrad)"
                  strokeWidth="1.5"
                  strokeDasharray="5 3"
                  className="animate-dash"
                  style={{ strokeDashoffset: 100 }}
                />
                <path
                  d={pathD}
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="1"
                  opacity="0.2"
                />
                <circle cx={from.x} cy={from.y} r={5} className="fill-red-500 animate-ping" />
                <circle cx={from.x} cy={from.y} r={3} className="fill-red-400" />
                <text x={from.x} y={from.y - 8} className="fill-red-400 text-[10px] font-mono font-bold" textAnchor="middle">
                  {arc.from} ({arc.count})
                </text>
              </g>
            );
          })}

          {/* Target node dot */}
          <circle cx={countryCoords.ID.x} cy={countryCoords.ID.y} r={7} className="fill-nexus-accent animate-pulse" />
          <circle cx={countryCoords.ID.x} cy={countryCoords.ID.y} r={4} className="fill-nexus-accent" />
          <text x={countryCoords.ID.x} y={countryCoords.ID.y + 16} className="fill-nexus-accent font-semibold text-[10px] font-mono" textAnchor="middle">
            ID (Nexus WAF)
          </text>
        </svg>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Metrics and Chart */}
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2.5">
            <div className="bg-nexus-panel border border-nexus-hairline p-3 rounded-lg">
              <div className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Total Requests</div>
              <div className="text-xl font-bold text-nexus-text mt-1">{totalRequests}</div>
            </div>
            <div className="bg-nexus-panel border border-nexus-hairline p-3 rounded-lg">
              <div className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Attacks Blocked</div>
              <div className="text-xl font-bold text-red-400 mt-1">{blockedRequests}</div>
            </div>
            <div className="bg-nexus-panel border border-nexus-hairline p-3 rounded-lg">
              <div className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Allow Rate</div>
              <div className="text-xl font-bold text-green-400 mt-1">{allowRate}%</div>
            </div>
            <div className="bg-nexus-panel border border-nexus-hairline p-3 rounded-lg">
              <div className="text-[10px] text-nexus-muted font-semibold uppercase tracking-wider font-mono">Threat Level</div>
              <div className={`text-xs mt-2 uppercase font-mono ${threatColor}`}>{threatLevel}</div>
            </div>
          </div>

          <div className="bg-nexus-panel border border-nexus-hairline p-4 rounded-xl space-y-3">
            <h4 className="text-xs font-semibold text-nexus-text uppercase tracking-wider font-mono">Attack Category Distribution</h4>
            <div className="space-y-2">
              {[
                { label: "SQL Injection Check", count: categories.sql_injection, color: "bg-red-500" },
                { label: "Cross-Site Scripting (XSS)", count: categories.xss, color: "bg-orange-500" },
                { label: "Path Traversal Patterns", count: categories.path_traversal, color: "bg-yellow-500" },
                { label: "Command Injection Check", count: categories.cmd_injection, color: "bg-blue-500" },
                { label: "Scanner Detection", count: categories.scanner_detected, color: "bg-indigo-500" },
                { label: "Custom Rules / Other", count: categories.custom, color: "bg-purple-500" }
              ].map((c, idx) => {
                const pct = blockedRequests ? Math.round((c.count / blockedRequests) * 100) : 0;
                return (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-nexus-muted">{c.label}</span>
                      <span className="text-nexus-text font-semibold">{c.count} ({pct}%)</span>
                    </div>
                    <div className="w-full bg-nexus-surface h-1.5 rounded-full overflow-hidden">
                      <div className={`h-full ${c.color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* IP Behavior Table */}
        <div className="bg-nexus-panel border border-nexus-hairline p-4 rounded-xl flex flex-col justify-between">
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-nexus-text uppercase tracking-wider font-mono">IP Threat Behavior Analysis</h4>
            <div className="overflow-auto max-h-[290px] border border-nexus-hairline rounded">
              <table className="w-full text-xs text-left">
                <thead className="bg-nexus-surface text-nexus-muted text-[10px] uppercase font-mono">
                  <tr>
                    <th className="p-2">IP Address</th>
                    <th className="p-2">Geo Location</th>
                    <th className="p-2 text-right">Reqs / Blocks</th>
                    <th className="p-2 text-right">Behavior Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-nexus-hairline font-mono">
                  {ipStats.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="text-center py-8 text-nexus-subtle italic">No threat activity detected.</td>
                    </tr>
                  ) : (
                    ipStats.map((stat, i) => {
                      const score = stat.total ? Math.round((stat.blocked / stat.total) * 100) : 0;
                      let scoreColor = "text-green-400";
                      let level = "Safe";
                      if (score > 80) { scoreColor = "text-red-500 font-bold"; level = "Critical"; }
                      else if (score > 40) { scoreColor = "text-orange-400 font-bold"; level = "High"; }
                      else if (score > 10) { scoreColor = "text-yellow-400"; level = "Medium"; }
                      else if (stat.blocked > 0) { scoreColor = "text-yellow-400"; level = "Low"; }

                      return (
                        <tr key={i} className="hover:bg-nexus-surface/40">
                          <td className="p-2 font-semibold text-nexus-text text-[11px]">{stat.ip}</td>
                          <td className="p-2 flex items-center gap-1.5 text-[11px]">
                            <span>{getFlagEmoji(stat.countryCode)}</span>
                            <span className="text-nexus-muted text-[10px]">{stat.countryName}</span>
                          </td>
                          <td className="p-2 text-right text-[11px] text-nexus-text">{stat.total} / <span className="text-red-400">{stat.blocked}</span></td>
                          <td className="p-2 text-right text-[11px]">
                            <span className={scoreColor}>{score}% ({level})</span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
          <div className="text-[10px] text-nexus-muted italic mt-3 font-mono">
            * Score is calculated based on blocked requests ratio and trigger threshold.
          </div>
        </div>
      </div>
    </div>
  );
};

interface WafLogsTabProps {
  logs: LogEvent[];
  onClear: () => void;
  onDownload: () => void;
  onSelectLog: (log: LogEvent) => void;
}

const WafLogsTab: React.FC<WafLogsTabProps> = ({ logs, onClear, onDownload, onSelectLog }) => {
  const [scrollTop, setScrollTop] = useState(0);
  const rowHeight = 28;
  const viewportHeight = 350; // Taller since it is in the main tab area
  const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - 2);
  const endIndex = Math.min(logs.length, Math.floor((scrollTop + viewportHeight) / rowHeight) + 2);
  const visibleLogs = logs.slice(startIndex, endIndex);
  const topPadding = startIndex * rowHeight;
  const bottomPadding = (logs.length - endIndex) * rowHeight;

  return (
    <div className="nx-card p-5 space-y-4">
      <div className="flex justify-between items-center pb-2 border-b border-nexus-hairline">
        <div>
          <h3 className="text-sm font-semibold text-nexus-text font-mono">Daftar Serangan & Deteksi Log</h3>
          <p className="text-[11px] text-nexus-muted mt-0.5">Menampilkan 200 kejadian keamanan terbaru yang diblokir atau dideteksi. Klik salah satu baris untuk melihat detail payload lengkap.</p>
        </div>
        <div className="flex gap-2">
          <button
            className="text-[11px] text-red-400 hover:text-red-500 font-semibold border border-nexus-border hover:border-red-950/40 rounded px-2 py-1 flex items-center gap-1 transition-all"
            onClick={onClear}
          >
            <Ic.trash className="h-3 w-3" /> Hapus Semua Log
          </button>
          <button
            className="text-[11px] text-nexus-accent hover:brightness-115 font-semibold border border-nexus-border hover:border-nexus-accent/30 rounded px-2 py-1 flex items-center gap-1 transition-all"
            onClick={onDownload}
          >
            <Ic.download className="h-3 w-3" /> Unduh CSV
          </button>
        </div>
      </div>
      <div 
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
        className="overflow-auto max-h-[350px] rounded border border-nexus-hairline"
      >
        <table className="w-full table-fixed min-w-[950px] text-xs">
          <thead className="bg-nexus-panel text-left text-xs text-nexus-muted sticky top-0 z-10 border-b border-nexus-hairline">
            <tr>
              <th className="px-2 py-1.5 w-[140px]">Waktu</th>
              <th className="px-2 py-1.5 w-[110px]">IP Klien</th>
              <th className="px-2 py-1.5 w-[80px]">Negara</th>
              <th className="px-2 py-1.5 w-[170px]">Aturan Terpicu</th>
              <th className="px-2 py-1.5">Requested Path</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-nexus-hairline text-nexus-text font-mono">
            {logs.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-6 text-nexus-subtle italic">
                  Belum ada log serangan yang terdeteksi.
                </td>
              </tr>
            ) : (
              <>
                {topPadding > 0 && (
                  <tr style={{ height: `${topPadding}px` }}>
                    <td colSpan={5} style={{ padding: 0 }} />
                  </tr>
                )}
                {visibleLogs.map((l, idx) => {
                  const absoluteIndex = startIndex + idx;
                  const isBlocked = !l.rule.startsWith("allow:") && !l.rule.startsWith("detect:");
                  const isDetected = l.rule.startsWith("detect:");
                  return (
                    <tr
                      key={absoluteIndex}
                      onClick={() => onSelectLog(l)}
                      style={{ height: `${rowHeight}px` }}
                      className={`cursor-pointer hover:bg-nexus-panel/60 transition-colors ${
                        isBlocked
                          ? "bg-red-950/20 text-red-200"
                          : isDetected
                          ? "bg-yellow-950/20 text-yellow-200"
                          : "odd:bg-white/5 even:bg-transparent"
                      }`}
                    >
                      <td className="px-2 py-1 font-mono text-[11px] truncate">{l.ts}</td>
                      <td className="px-2 py-1 text-[11.5px] truncate">{l.ip}</td>
                      <td className="px-2 py-1 text-[11.5px] truncate">
                        <span className="mr-1">{getFlagEmoji(l.country_code)}</span>
                        <span className="text-[10px] text-nexus-muted font-mono">{l.country_code || "ID"}</span>
                      </td>
                      <td className="px-2 py-1 text-[11.5px] font-semibold truncate" title={l.rule}>{l.rule}</td>
                      <td className="px-2 py-1 truncate text-[11px]" title={`Path: ${l.path}\nPayload: ${l.payload || '-'}`}>{l.path}</td>
                    </tr>
                  );
                })}
                {bottomPadding > 0 && (
                  <tr style={{ height: `${bottomPadding}px` }}>
                    <td colSpan={5} style={{ padding: 0 }} />
                  </tr>
                )}
              </>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const WafVhostTab: React.FC<{
  vhosts: any[];
  onDelete: (hostname: string) => void;
  onEdit: (vhost: any) => void;
}> = ({ vhosts, onDelete, onEdit }) => {
  const [search, setSearch] = useState("");

  const filtered = vhosts.filter((vh) =>
    vh.hostname.toLowerCase().includes(search.toLowerCase()) ||
    (vh.backend_host + ":" + vh.backend_port).toLowerCase().includes(search.toLowerCase()) ||
    (vh.root_directory || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-4 bg-nexus-surface h-full overflow-auto">
      <div className="flex justify-between items-center border-b border-nexus-hairline pb-3">
        <div>
          <h3 className="text-base font-semibold text-nexus-text font-mono">Virtual Hosts</h3>
          <p className="text-xs text-nexus-muted">Kelola domain local, default routing, dan port forwarding untuk proxy WAF.</p>
        </div>
        <div className="relative w-64">
          <input
            type="text"
            placeholder="Cari domain atau backend..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-nexus-panel border border-nexus-border rounded-lg pl-8 pr-8 py-1.5 text-xs text-nexus-text placeholder-nexus-subtle focus:outline-none focus:border-nexus-accent font-mono"
          />
          <Ic.search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-nexus-muted" />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-nexus-muted hover:text-nexus-text text-[10px] px-1"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      <div className="bg-nexus-panel border border-nexus-hairline rounded-xl overflow-hidden shadow-sm">
        <table className="w-full text-xs text-left">
          <thead className="bg-nexus-surface text-nexus-muted uppercase font-semibold font-mono border-b border-nexus-hairline text-[10px] tracking-wider">
            <tr>
              <th className="p-3.5">Hostname (Domain)</th>
              <th className="p-3.5">Forward Address</th>
              <th className="p-3.5">RPS Limit</th>
              <th className="p-3.5">Learning Mode</th>
              <th className="p-3.5">Gateway Security</th>
              <th className="p-3.5">Active Rules</th>
              <th className="p-3.5 text-right">Aksi</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-nexus-hairline">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-10 text-nexus-subtle italic">
                  {vhosts.length === 0 ? "Belum ada virtual host yang dikonfigurasi." : "Tidak ada hasil pencocokan."}
                </td>
              </tr>
            ) : (
              filtered.map((vh) => (
                <tr key={vh.id} className="hover:bg-nexus-surface/30 transition-colors">
                  <td className="p-3.5 font-semibold text-nexus-text font-mono">
                    <span className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-nexus-accent" />
                      {vh.hostname}
                      <span className={`px-1.5 py-0.5 rounded-full text-[9px] font-semibold border ${vh.vhost_type === 'static' ? 'bg-purple-950/40 text-purple-300 border-purple-800' : 'bg-blue-950/40 text-blue-300 border-blue-800'}`}>
                        {vh.vhost_type === 'static' ? 'Static' : 'Proxy'}
                      </span>
                    </span>
                  </td>
                  <td className="p-3.5 font-mono text-nexus-muted truncate max-w-xs" title={vh.vhost_type === 'static' ? vh.root_directory : `${vh.backend_host}:${vh.backend_port}`}>
                    {vh.vhost_type === 'static' ? (
                      <span className="flex items-center gap-1.5 text-purple-400">
                        <Ic.folder className="h-3.5 w-3.5" /> {vh.root_directory}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1">
                        <span className="text-nexus-accent font-semibold">→</span> {vh.backend_host}:{vh.backend_port}
                      </span>
                    )}
                  </td>
                  <td className="p-3.5 font-mono text-nexus-text">{vh.max_rps} RPS</td>
                  <td className="p-3.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${vh.learning_mode ? 'bg-yellow-950/40 text-yellow-300 border border-yellow-800' : 'bg-green-950/40 text-green-300 border-green-800'}`}>
                      {vh.learning_mode ? "Learning" : "Blocking"}
                    </span>
                  </td>
                  <td className="p-3.5">
                    <div className="flex flex-wrap gap-1 max-w-[150px]">
                      {vh.blacklist_countries && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-950/40 text-red-300 border border-red-800 font-mono font-semibold" title={`Blokir Negara: ${vh.blacklist_countries}`}>
                          GEO
                        </span>
                      )}
                      {vh.identity_enabled && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-blue-950/40 text-blue-300 border border-blue-800 font-mono font-semibold" title="Identity Gateway Aktif">
                          GATEWAY
                        </span>
                      )}
                      {vh.captcha_enabled && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-yellow-950/40 text-yellow-300 border border-yellow-800 font-mono font-semibold" title="Anti-Bot CAPTCHA Aktif">
                          CAPTCHA
                        </span>
                      )}
                      {vh.obfuscation_enabled && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-purple-950/40 text-purple-300 border border-purple-800 font-mono font-semibold" title="Dynamic HTML/JS Encryption Aktif">
                          OBFUSCATE
                        </span>
                      )}
                      {!vh.blacklist_countries && !vh.identity_enabled && !vh.captcha_enabled && !vh.obfuscation_enabled && (
                        <span className="text-nexus-muted text-[10.5px] italic">-</span>
                      )}
                    </div>
                  </td>
                  <td className="p-3.5">
                    <div className="flex flex-wrap gap-1 max-w-xs">
                      {vh.rules && vh.rules.map((rule: string) => (
                        <span key={rule} className="px-1.5 py-0.5 rounded text-[10px] bg-nexus-surface border border-nexus-hairline text-nexus-muted font-mono font-semibold">
                          {rule}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="p-3.5 text-right">
                    <div className="flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => onEdit(vh)}
                        className="text-nexus-accent hover:text-nexus-accent/80 font-semibold px-2 py-0.5 rounded border border-nexus-border hover:border-nexus-accent bg-nexus-panel/40 hover:bg-nexus-accent/10 transition-all text-[11px]"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => onDelete(vh.hostname)}
                        className="text-red-400 hover:text-red-500 font-bold px-2.5 py-1 rounded border border-red-900/40 hover:border-red-900 bg-red-950/10 hover:bg-red-950/30 transition-all"
                      >
                        <span className="flex items-center gap-1.5">
                          <Ic.trash className="h-3 w-3" /> Hapus
                        </span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const WafRulesTab: React.FC<{
  customRules: any[];
  onDelete: (name: string) => void;
  onToggle: (rule: any) => void;
}> = ({ customRules, onDelete, onToggle }) => {
  const [search, setSearch] = useState("");

  const filtered = customRules.filter((rule) =>
    rule.name.toLowerCase().includes(search.toLowerCase()) ||
    rule.pattern.toLowerCase().includes(search.toLowerCase()) ||
    (rule.description || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-6 space-y-4 bg-nexus-surface h-full overflow-auto">
      <div className="flex justify-between items-center border-b border-nexus-hairline pb-3">
        <div>
          <h3 className="text-base font-semibold text-nexus-text">Custom Regex Rules</h3>
          <p className="text-xs text-nexus-muted">Buat dan kelola pola regex kustom untuk memblokir request spesifik.</p>
        </div>
        <div className="relative w-64">
          <input
            type="text"
            placeholder="Cari rule regex..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-nexus-panel border border-nexus-border rounded-lg pl-8 pr-8 py-1.5 text-xs text-nexus-text placeholder-nexus-subtle focus:outline-none focus:border-nexus-accent font-mono"
          />
          <Ic.search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-nexus-muted" />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-nexus-muted hover:text-nexus-text text-[10px] px-1"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      <div className="bg-nexus-panel border border-nexus-hairline rounded-xl overflow-hidden shadow-sm">
        <table className="w-full text-xs text-left">
          <thead className="bg-nexus-surface text-nexus-muted uppercase font-semibold font-mono border-b border-nexus-hairline text-[10px] tracking-wider">
            <tr>
              <th className="p-3.5">Rule Name</th>
              <th className="p-3.5">Regex Pattern</th>
              <th className="p-3.5">Description</th>
              <th className="p-3.5">Status</th>
              <th className="p-3.5 text-right">Aksi</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-nexus-hairline">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-10 text-nexus-subtle italic">
                  {customRules.length === 0 ? "Belum ada custom rule yang dikonfigurasi." : "Tidak ada hasil pencocokan."}
                </td>
              </tr>
            ) : (
              filtered.map((rule) => (
                <tr key={rule.id} className="hover:bg-nexus-surface/30 transition-colors">
                  <td className="p-3.5 font-semibold text-nexus-text font-mono">
                    <span className="flex items-center gap-2">
                      <span className={`h-2.5 w-2.5 rounded-full ${rule.enabled ? 'bg-green-500 animate-pulse' : 'bg-gray-600'}`} />
                      {rule.name}
                    </span>
                  </td>
                  <td className="p-3.5 font-mono">
                    <span className="bg-nexus-surface border border-nexus-hairline px-2 py-0.5 rounded text-nexus-accent2 font-semibold text-[11px] block max-w-md truncate" title={rule.pattern}>
                      {rule.pattern}
                    </span>
                  </td>
                  <td className="p-3.5 text-nexus-muted max-w-xs truncate" title={rule.description || "-"}>
                    {rule.description || "-"}
                  </td>
                  <td className="p-3.5">
                    <button
                      type="button"
                      onClick={() => onToggle(rule)}
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${rule.enabled ? 'bg-green-950/40 text-green-300 border-green-800 hover:bg-green-950' : 'bg-gray-800 text-gray-400 border-gray-700 hover:bg-gray-700'} transition-all`}
                    >
                      {rule.enabled ? "Active" : "Inactive"}
                    </button>
                  </td>
                  <td className="p-3.5 text-right">
                    <button
                      type="button"
                      onClick={() => onDelete(rule.name)}
                      className="text-red-400 hover:text-red-500 font-bold px-2.5 py-1 rounded border border-red-900/40 hover:border-red-900 bg-red-950/10 hover:bg-red-950/30 transition-all"
                    >
                      <span className="flex items-center gap-1.5">
                        <Ic.trash className="h-3 w-3" /> Hapus
                      </span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const WAF: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  
  // WAF General state
  const [listenPort, setListenPort] = useState("8080");
  const [backendHost, setBackendHost] = useState("127.0.0.1");
  const [backendPort, setBackendPort] = useState("8000");
  const [maxRps, setMaxRps] = useState("10");
  const [maxLogMb, setMaxLogMb] = useState("10");
  const [learningMode, setLearningMode] = useState(false);
  const [allowlistIps, setAllowlistIps] = useState("");
  const [allowlistPaths, setAllowlistPaths] = useState("");
  const [blacklistIps, setBlacklistIps] = useState("");
  const [blacklistCountries, setBlacklistCountries] = useState("");
  const [identityEnabled, setIdentityEnabled] = useState(false);
  const [identityPassword, setIdentityPassword] = useState("");
  const [captchaEnabled, setCaptchaEnabled] = useState(false);
  const [obfuscationEnabled, setObfuscationEnabled] = useState(false);

  // SSL settings
  const [sslEnabled, setSslEnabled] = useState(false);
  const [sslCertType, setSslCertType] = useState("self_signed");
  const [sslCertPath, setSslCertPath] = useState("");
  const [sslKeyPath, setSslKeyPath] = useState("");

  // UI Navigation Tabs
  const [activeTab, setActiveTab] = useState<"general" | "vhosts" | "rules">("general");

  const scan = useScanRuntimeStore((s) => s.scans["waf"]);
  const isRunning = scan?.running ?? false;

  const [logs, setLogs] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [selectedLog, setSelectedLog] = useState<any | null>(null);

  // VHosts state
  const [vhosts, setVhosts] = useState<any[]>([]);
  const [newVhostHost, setNewVhostHost] = useState("");
  const [newVhostBackend, setNewVhostBackend] = useState("127.0.0.1");
  const [newVhostPort, setNewVhostPort] = useState("8000");
  const [newVhostRps, setNewVhostRps] = useState("10");
  const [newVhostLearning, setNewVhostLearning] = useState(false);
  const [newVhostIps, setNewVhostIps] = useState("");
  const [newVhostPaths, setNewVhostPaths] = useState("");
  const [newVhostBlacklistIps, setNewVhostBlacklistIps] = useState("");
  const [newVhostBlacklistCountries, setNewVhostBlacklistCountries] = useState("");
  const [newVhostIdentityEnabled, setNewVhostIdentityEnabled] = useState(false);
  const [newVhostIdentityPassword, setNewVhostIdentityPassword] = useState("");
  const [newVhostCaptchaEnabled, setNewVhostCaptchaEnabled] = useState(false);
  const [newVhostObfuscationEnabled, setNewVhostObfuscationEnabled] = useState(false);
  const [editingVhostId, setEditingVhostId] = useState<number | null>(null);
  const [newVhostType, setNewVhostType] = useState<"proxy" | "static">("proxy");
  const [newVhostRootDir, setNewVhostRootDir] = useState("");
  const [selectedRules, setSelectedRules] = useState<string[]>([
    "sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"
  ]);

  // Custom Rules state
  const [customRules, setCustomRules] = useState<any[]>([]);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRulePattern, setNewRulePattern] = useState("");
  const [newRuleDesc, setNewRuleDesc] = useState("");
  const [newRuleEnabled, setNewRuleEnabled] = useState(true);

  const run = () => {
    consoleRef.current?.start({
      command: "waf",
      args: buildArgs({
        foreground: true,
        listen_port: listenPort,
        backend: backendHost,
        backend_port: backendPort,
        max_rps: maxRps,
        max_log_mb: maxLogMb,
        learning_mode: learningMode,
        allowlist_ips: allowlistIps,
        allowlist_paths: allowlistPaths,
        blacklist_ips: blacklistIps,
        blacklist_countries: blacklistCountries,
        identity_enabled: identityEnabled,
        identity_password: identityPassword,
        captcha_enabled: captchaEnabled,
        obfuscation_enabled: obfuscationEnabled,
        ssl_enabled: sslEnabled,
        ssl_cert_type: sslCertType,
        ssl_cert_path: sslCertPath,
        ssl_key_path: sslKeyPath,
      }),
      module: "waf",
    });
  };

  const stop = () => {
    useScanRuntimeStore.getState().stop("waf");
  };

  // VHost CRUD Operations
  const fetchVhosts = async () => {
    try {
      const res = await runToolJson("waf_get_vhosts");
      if (res && res.status === "ok") {
        const vhList = res.vhosts || [];
        setVhosts(vhList);
        
        // Find default wildcard vhost to populate general WAF configs on page load
        const defaultVh = vhList.find((v: any) => v.hostname === "*");
        if (defaultVh) {
          setBackendHost(defaultVh.backend_host);
          setBackendPort(defaultVh.backend_port);
          setMaxRps(String(defaultVh.max_rps));
          setLearningMode(defaultVh.learning_mode);
          setAllowlistIps(defaultVh.allowlist_ips || "");
          setAllowlistPaths(defaultVh.allowlist_paths || "");
          setBlacklistIps(defaultVh.blacklist_ips || "");
          setBlacklistCountries(defaultVh.blacklist_countries || "");
          setIdentityEnabled(defaultVh.identity_enabled || false);
          setIdentityPassword(defaultVh.identity_password || "");
          setCaptchaEnabled(defaultVh.captcha_enabled || false);
          setObfuscationEnabled(defaultVh.obfuscation_enabled || false);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const browseVhostFolder = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Pilih Folder Website (Static)"
      });
      if (typeof selected === "string") {
        setNewVhostRootDir(selected);
      }
    } catch (err) {
      console.error("Gagal memilih folder:", err);
    }
  };

  const handleSaveVhost = async () => {
    if (!newVhostHost) return;
    try {
      await runToolJson("waf_save_vhost", buildArgs({
        hostname: newVhostHost,
        backend_host: newVhostBackend,
        backend_port: newVhostPort,
        max_rps: newVhostRps,
        learning_mode: newVhostLearning,
        allowlist_ips: newVhostIps,
        allowlist_paths: newVhostPaths,
        blacklist_ips: newVhostBlacklistIps,
        blacklist_countries: newVhostBlacklistCountries,
        identity_enabled: newVhostIdentityEnabled,
        identity_password: newVhostIdentityPassword,
        captcha_enabled: newVhostCaptchaEnabled,
        obfuscation_enabled: newVhostObfuscationEnabled,
        rules_json: JSON.stringify(selectedRules),
        vhost_type: newVhostType,
        root_directory: newVhostRootDir
      }));
      setNewVhostHost("");
      setNewVhostIps("");
      setNewVhostPaths("");
      setNewVhostBlacklistIps("");
      setNewVhostBlacklistCountries("");
      setNewVhostIdentityEnabled(false);
      setNewVhostIdentityPassword("");
      setNewVhostCaptchaEnabled(false);
      setNewVhostObfuscationEnabled(false);
      setNewVhostRootDir("");
      setEditingVhostId(null);
      fetchVhosts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleEditVhost = (vh: any) => {
    setEditingVhostId(vh.id);
    setNewVhostHost(vh.hostname);
    setNewVhostBackend(vh.backend_host);
    setNewVhostPort(String(vh.backend_port));
    setNewVhostRps(String(vh.max_rps));
    setNewVhostLearning(vh.learning_mode);
    setNewVhostIps(vh.allowlist_ips || "");
    setNewVhostPaths(vh.allowlist_paths || "");
    setNewVhostBlacklistIps(vh.blacklist_ips || "");
    setNewVhostBlacklistCountries(vh.blacklist_countries || "");
    setNewVhostIdentityEnabled(vh.identity_enabled || false);
    setNewVhostIdentityPassword(vh.identity_password || "");
    setNewVhostCaptchaEnabled(vh.captcha_enabled || false);
    setNewVhostObfuscationEnabled(vh.obfuscation_enabled || false);
    setNewVhostType(vh.vhost_type || "proxy");
    setNewVhostRootDir(vh.root_directory || "");
    setSelectedRules(vh.rules || []);
  };

  const handleCancelEdit = () => {
    setEditingVhostId(null);
    setNewVhostHost("");
    setNewVhostBackend("127.0.0.1");
    setNewVhostPort("8000");
    setNewVhostRps("10");
    setNewVhostLearning(false);
    setNewVhostIps("");
    setNewVhostPaths("");
    setNewVhostBlacklistIps("");
    setNewVhostBlacklistCountries("");
    setNewVhostIdentityEnabled(false);
    setNewVhostIdentityPassword("");
    setNewVhostCaptchaEnabled(false);
    setNewVhostObfuscationEnabled(false);
    setNewVhostType("proxy");
    setNewVhostRootDir("");
    setSelectedRules(["sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"]);
  };

  const handleDeleteVhost = async (hostname: string) => {
    try {
      await runToolJson("waf_delete_vhost", ["--hostname", hostname]);
      fetchVhosts();
    } catch (err) {
      console.error(err);
    }
  };

  // Custom Rule CRUD Operations
  const fetchCustomRules = async () => {
    try {
      const res = await runToolJson("waf_get_rules");
      if (res && res.status === "ok") {
        setCustomRules(res.rules || []);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveRule = async () => {
    if (!newRuleName || !newRulePattern) return;
    try {
      await runToolJson("waf_save_rule", buildArgs({
        name: newRuleName,
        pattern: newRulePattern,
        description: newRuleDesc,
        enabled: newRuleEnabled
      }));
      setNewRuleName("");
      setNewRulePattern("");
      setNewRuleDesc("");
      fetchCustomRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteRule = async (name: string) => {
    try {
      await runToolJson("waf_delete_rule", ["--name", name]);
      fetchCustomRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleRuleStatus = async (rule: any) => {
    try {
      await runToolJson("waf_save_rule", buildArgs({
        name: rule.name,
        pattern: rule.pattern,
        description: rule.description,
        enabled: !rule.enabled
      }));
      fetchCustomRules();
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await runToolJson("waf_logs", ["--limit", "200"]);
      setLogs(res.logs || []);
      if (res.stats) {
        setStats(res.stats);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const downloadLogsCsv = async () => {
    if (logs.length === 0) return;
    const headers = ["Time", "Client IP", "Triggered Rule", "Requested Path", "Payload Data"];
    const rows = logs.map(l => [
      l.ts,
      l.ip,
      l.rule,
      l.path.replace(/"/g, '""'),
      (l.payload || "").replace(/"/g, '""')
    ]);
    const csvContent = "\uFEFF" 
      + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
    await exportTextFile(`waf_logs_${new Date().toISOString().slice(0,10)}.csv`, csvContent);
  };

  const handleClearLogs = async () => {
    if (!window.confirm("Apakah Anda yakin ingin menghapus semua log WAF? Tindakan ini tidak dapat dibatalkan.")) {
      return;
    }
    try {
      const res = await runToolJson("waf_clear_logs");
      if (res && res.status === "ok") {
        setLogs([]);
        setStats(null);
      }
    } catch (err) {
      console.error("Gagal menghapus log:", err);
    }
  };

  useEffect(() => {
    fetchVhosts();
    fetchCustomRules();
    fetchLogs();
  }, []);

  useEffect(() => {
    let t: any;
    if (isRunning) {
      fetchLogs();
      t = setInterval(fetchLogs, 3000);
    }
    return () => {
      if (t) clearInterval(t);
    };
  }, [isRunning]);

  const toggleRuleSelection = (ruleName: string) => {
    if (selectedRules.includes(ruleName)) {
      setSelectedRules(selectedRules.filter(r => r !== ruleName));
    } else {
      setSelectedRules([...selectedRules, ruleName]);
    }
  };

  const renderForm = () => {
    return (
      <div className="space-y-5">
        {/* Navigation sub-tabs inside form panel */}
        <div className="flex border-b border-nexus-hairline">
          <button
            className={`flex-1 pb-2 text-[12px] font-semibold text-center border-b-2 transition-all ${
              activeTab === "general"
                ? "border-nexus-accent text-nexus-text"
                : "border-transparent text-nexus-muted hover:text-nexus-text"
            }`}
            onClick={() => setActiveTab("general")}
          >
            General & SSL
          </button>
          <button
            className={`flex-1 pb-2 text-[12px] font-semibold text-center border-b-2 transition-all ${
              activeTab === "vhosts"
                ? "border-nexus-accent text-nexus-text"
                : "border-transparent text-nexus-muted hover:text-nexus-text"
            }`}
            onClick={() => setActiveTab("vhosts")}
          >
            Virtual Hosts
          </button>
          <button
            className={`flex-1 pb-2 text-[12px] font-semibold text-center border-b-2 transition-all ${
              activeTab === "rules"
                ? "border-nexus-accent text-nexus-text"
                : "border-transparent text-nexus-muted hover:text-nexus-text"
            }`}
            onClick={() => setActiveTab("rules")}
          >
            Custom Rules
          </button>
        </div>

        {activeTab === "general" && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="nx-label">
                  Proxy Listen Port
                  <HelpTip text="Port tempat WAF mendengarkan request masuk (HTTP/HTTPS). Contoh: 8080." />
                </label>
                <input className="nx-input font-mono" value={listenPort} onChange={(e) => setListenPort(e.target.value)} />
              </div>
              <div>
                <label className="nx-label">
                  Max Log Size (MB)
                  <HelpTip text="Batas kapasitas file database log. Jika terlampaui, 20% log terlama akan dihapus otomatis." />
                </label>
                <input className="nx-input font-mono" value={maxLogMb} onChange={(e) => setMaxLogMb(e.target.value)} />
              </div>
            </div>

            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <h4 className="text-xs font-semibold text-nexus-text">Default Target Routing (Wildcard)</h4>
              <div>
                <label className="nx-label">
                  Default Backend Host
                  <HelpTip text="Alamat IP/Host aplikasi web asli yang ingin Anda proteksi." />
                </label>
                <input className="nx-input font-mono" value={backendHost} onChange={(e) => setBackendHost(e.target.value)} />
              </div>
              <div>
                <label className="nx-label">
                  Default Backend Port
                  <HelpTip text="Port aplikasi web asli Anda. Contoh: 8000." />
                </label>
                <input className="nx-input font-mono" value={backendPort} onChange={(e) => setBackendPort(e.target.value)} />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="nx-label">
                    Default Max RPS
                    <HelpTip text="Batas maksimum request per detik untuk setiap alamat IP client guna mencegah DoS." />
                  </label>
                  <input className="nx-input font-mono" value={maxRps} onChange={(e) => setMaxRps(e.target.value)} />
                </div>
                <div className="flex items-end pb-1.5">
                  <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                    <input
                      type="checkbox"
                      checked={learningMode}
                      onChange={(e) => setLearningMode(e.target.checked)}
                      className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                    />
                    Learning Mode
                    <HelpTip text="Jika aktif, serangan hanya dicatat ke log (detect:) tanpa diblokir (403)." />
                  </label>
                </div>
              </div>
              <div>
                <label className="nx-label">
                  Allowlist IPs
                  <HelpTip text="Daftar IP (dipisah koma) yang diizinkan mem-bypass pemeriksaan keamanan WAF." />
                </label>
                <input
                  className="nx-input font-mono text-xs"
                  value={allowlistIps}
                  onChange={(e) => setAllowlistIps(e.target.value)}
                  placeholder="e.g. 127.0.0.1, 192.168.1.100"
                />
              </div>
              <div>
                <label className="nx-label">
                  Allowlist Paths
                  <HelpTip text="Daftar path URL (dipisah koma) yang dikecualikan dari pemblokiran WAF. Contoh: /assets." />
                </label>
                <input
                  className="nx-input font-mono text-xs"
                  value={allowlistPaths}
                  onChange={(e) => setAllowlistPaths(e.target.value)}
                  placeholder="e.g. /assets, /api/public"
                />
              </div>
              <div>
                <label className="nx-label">
                  Blacklist IPs
                  <HelpTip text="Daftar IP (dipisah koma) yang diblokir aksesnya secara permanen ke WAF." />
                </label>
                <input
                  className="nx-input font-mono text-xs"
                  value={blacklistIps}
                  onChange={(e) => setBlacklistIps(e.target.value)}
                  placeholder="e.g. 192.168.1.55, 45.227.254.10"
                />
              </div>
              <div>
                <label className="nx-label">
                  Blacklist Countries (comma-separated)
                  <HelpTip text="Daftar kode negara (dipisah koma) untuk diblokir aksesnya. Contoh: US, CN, RU." />
                </label>
                <input
                  className="nx-input font-mono text-xs"
                  value={blacklistCountries}
                  onChange={(e) => setBlacklistCountries(e.target.value)}
                  placeholder="e.g. US, CN, RU"
                />
              </div>

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-nexus-hairline/40">
                <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                  <input
                    type="checkbox"
                    checked={captchaEnabled}
                    onChange={(e) => setCaptchaEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  Anti-Bot CAPTCHA
                  <HelpTip text="Tampilkan tantangan matematika jika klien melebihi RPS limit atau memicu rules." />
                </label>

                <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                  <input
                    type="checkbox"
                    checked={obfuscationEnabled}
                    onChange={(e) => setObfuscationEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  HTML/JS Encryption
                  <HelpTip text="Enkripsi file HTML/JS secara dinamis setiap kali halaman diakses untuk mengelabui scraper." />
                </label>
              </div>

              <div className="pt-2 border-t border-nexus-hairline/40 space-y-2">
                <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                  <input
                    type="checkbox"
                    checked={identityEnabled}
                    onChange={(e) => setIdentityEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  Identity Gateway
                  <HelpTip text="Aktifkan autentikasi password global sebelum diperbolehkan mengakses halaman web." />
                </label>

                {identityEnabled && (
                  <div>
                    <label className="nx-label">Gateway Password</label>
                    <input
                      type="password"
                      className="nx-input text-xs"
                      value={identityPassword}
                      onChange={(e) => setIdentityPassword(e.target.value)}
                      placeholder="Masukkan password gateway"
                    />
                  </div>
                )}
              </div>
            </div>

            {/* SSL/TLS termination configs */}
            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-nexus-text">
                  SSL/TLS Termination
                  <HelpTip text="WAF menerima koneksi HTTPS aman, mendekripsinya, lalu meneruskannya secara HTTP biasa ke backend Anda." />
                </h4>
                <label className="relative inline-flex items-center cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={sslEnabled}
                    onChange={(e) => setSslEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  <span className="ml-2 text-xs font-semibold text-nexus-text">Enable HTTPS</span>
                </label>
              </div>

              {sslEnabled && (
                <div className="space-y-3 pt-1 border-t border-nexus-hairline">
                  <div>
                    <label className="nx-label">Certificate Type</label>
                    <select
                      className="nx-input"
                      value={sslCertType}
                      onChange={(e) => setSslCertType(e.target.value)}
                    >
                      <option value="self_signed">Auto Self-Signed (openssl)</option>
                      <option value="custom">Custom Certificate Paths</option>
                    </select>
                  </div>

                  {sslCertType === "custom" && (
                    <div className="space-y-2">
                      <div>
                        <label className="nx-label">Certificate Pem Path</label>
                        <input
                          className="nx-input font-mono text-xs"
                          value={sslCertPath}
                          onChange={(e) => setSslCertPath(e.target.value)}
                          placeholder="C:/certs/fullchain.pem"
                        />
                      </div>
                      <div>
                        <label className="nx-label">Private Key Pem Path</label>
                        <input
                          className="nx-input font-mono text-xs"
                          value={sslKeyPath}
                          onChange={(e) => setSslKeyPath(e.target.value)}
                          placeholder="C:/certs/privkey.pem"
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "vhosts" && (
          <div className="space-y-4">
            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <h4 className="text-xs font-semibold text-nexus-text">
                {editingVhostId !== null ? `Edit Virtual Host: ${newVhostHost}` : "Add / Edit Virtual Host"}
              </h4>
              <div>
                <label className="nx-label">
                  Hostname (Domain)
                  <HelpTip text="Domain pencocokan di header Host (misal: app.local). Gunakan '*' untuk rute default/catch-all." />
                </label>
                <input
                  className="nx-input font-mono"
                  value={newVhostHost}
                  onChange={(e) => setNewVhostHost(e.target.value)}
                  placeholder="e.g. app.local"
                />
              </div>
              <div>
                <label className="nx-label">Target Type</label>
                <select
                  className="nx-input"
                  value={newVhostType}
                  onChange={(e) => setNewVhostType(e.target.value as any)}
                >
                  <option value="proxy">Reverse Proxy (Forward to Port)</option>
                  <option value="static">Static Directory (Serve Folder)</option>
                </select>
              </div>
              {newVhostType === "proxy" ? (
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="nx-label">Backend IP/Host</label>
                    <input className="nx-input font-mono" value={newVhostBackend} onChange={(e) => setNewVhostBackend(e.target.value)} />
                  </div>
                  <div>
                    <label className="nx-label">Backend Port</label>
                    <input className="nx-input font-mono" value={newVhostPort} onChange={(e) => setNewVhostPort(e.target.value)} />
                  </div>
                </div>
              ) : (
                <div>
                  <label className="nx-label">
                    Static Folder Path
                    <HelpTip text="Direktori lokal berisi file HTML/CSS/JS (seperti folder dist/build) untuk di-host secara lokal." />
                  </label>
                  <div className="flex gap-2">
                    <input
                      className="nx-input font-mono text-xs flex-1"
                      value={newVhostRootDir}
                      onChange={(e) => setNewVhostRootDir(e.target.value)}
                      placeholder="e.g. D:/my-site/dist"
                    />
                    {isTauri() && (
                      <button
                        type="button"
                        onClick={browseVhostFolder}
                        className="nx-btn-ghost px-2 py-1 flex items-center justify-center border border-nexus-border"
                      >
                        <Ic.folder className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="nx-label">Max RPS</label>
                  <input className="nx-input font-mono" value={newVhostRps} onChange={(e) => setNewVhostRps(e.target.value)} />
                </div>
                <div className="flex items-end pb-1.5">
                  <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                    <input
                      type="checkbox"
                      checked={newVhostLearning}
                      onChange={(e) => setNewVhostLearning(e.target.checked)}
                      className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                    />
                    Learning Mode
                  </label>
                </div>
              </div>
              <div>
                <label className="nx-label">Allowlist IPs (comma-separated)</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newVhostIps}
                  onChange={(e) => setNewVhostIps(e.target.value)}
                  placeholder="e.g. 192.168.1.50"
                />
              </div>
              <div>
                <label className="nx-label">Allowlist Paths (comma-separated)</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newVhostPaths}
                  onChange={(e) => setNewVhostPaths(e.target.value)}
                  placeholder="e.g. /public"
                />
              </div>
              <div>
                <label className="nx-label">Blacklist IPs (comma-separated)</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newVhostBlacklistIps}
                  onChange={(e) => setNewVhostBlacklistIps(e.target.value)}
                  placeholder="e.g. 45.227.254.10"
                />
              </div>
              <div>
                <label className="nx-label">Blacklist Countries (comma-separated)</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newVhostBlacklistCountries}
                  onChange={(e) => setNewVhostBlacklistCountries(e.target.value)}
                  placeholder="e.g. US, CN"
                />
              </div>

              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-nexus-hairline/40">
                <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                  <input
                    type="checkbox"
                    checked={newVhostCaptchaEnabled}
                    onChange={(e) => setNewVhostCaptchaEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  Anti-Bot CAPTCHA
                </label>

                <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                  <input
                    type="checkbox"
                    checked={newVhostObfuscationEnabled}
                    onChange={(e) => setNewVhostObfuscationEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  HTML/JS Encryption
                </label>
              </div>

              <div className="pt-2 border-t border-nexus-hairline/40 space-y-2">
                <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                  <input
                    type="checkbox"
                    checked={newVhostIdentityEnabled}
                    onChange={(e) => setNewVhostIdentityEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  Identity Gateway
                </label>

                {newVhostIdentityEnabled && (
                  <div>
                    <label className="nx-label">Gateway Password</label>
                    <input
                      type="password"
                      className="nx-input text-xs"
                      value={newVhostIdentityPassword}
                      onChange={(e) => setNewVhostIdentityPassword(e.target.value)}
                      placeholder="Masukkan password gateway"
                    />
                  </div>
                )}
              </div>

              <div>
                <label className="nx-label">Enabled Rule Packages</label>
                <div className="space-y-1.5 max-h-32 overflow-auto border border-nexus-hairline rounded p-2 bg-nexus-surface">
                  {[
                    { key: "sql_injection", label: "SQL Injection Patterns" },
                    { key: "xss", label: "Cross-Site Scripting (XSS)" },
                    { key: "path_traversal", label: "Path Traversal Patterns" },
                    { key: "cmd_injection", label: "Command Injection Check" },
                    { key: "scanner_detected", label: "Scanner Detection heuristic" }
                  ].map((pkg) => (
                    <label key={pkg.key} className="flex items-center gap-2 text-xs cursor-pointer select-none text-nexus-text">
                      <input
                        type="checkbox"
                        checked={selectedRules.includes(pkg.key)}
                        onChange={() => toggleRuleSelection(pkg.key)}
                        className="h-3.5 w-3.5 rounded border-nexus-hairline text-nexus-accent"
                      />
                      {pkg.label}
                    </label>
                  ))}
                  {customRules.map((cr) => (
                    <label key={cr.name} className="flex items-center gap-2 text-xs cursor-pointer select-none text-nexus-text">
                      <input
                        type="checkbox"
                        checked={selectedRules.includes(cr.name)}
                        onChange={() => toggleRuleSelection(cr.name)}
                        className="h-3.5 w-3.5 rounded border-nexus-hairline text-nexus-accent"
                      />
                      <span className="text-nexus-accent font-semibold">{cr.name}</span> (Custom)
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  type="button"
                  className="nx-btn-primary flex-1 py-1"
                  onClick={handleSaveVhost}
                >
                  {editingVhostId !== null ? "Update Host" : "Save Virtual Host"}
                </button>
                {editingVhostId !== null && (
                  <button
                    type="button"
                    className="nx-btn-ghost py-1 px-3 border border-nexus-border hover:bg-nexus-elevated"
                    onClick={handleCancelEdit}
                  >
                    Batal
                  </button>
                )}
              </div>
            </div>

            {/* VHosts List has been moved to main tab area */}
          </div>
        )}

        {activeTab === "rules" && (
          <div className="space-y-4">
            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <h4 className="text-xs font-semibold text-nexus-text">Add Custom Matching Pattern</h4>
              <div>
                <label className="nx-label">Rule Name</label>
                <input
                  className="nx-input font-mono"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  placeholder="e.g. block_admin_path"
                />
              </div>
              <div>
                <label className="nx-label">
                  Regex Pattern
                  <HelpTip text="Ekspresi reguler (Regex) pencocokan input URL, query string, request headers, atau body." />
                </label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newRulePattern}
                  onChange={(e) => setNewRulePattern(e.target.value)}
                  placeholder="e.g. /wp-admin|/administrator"
                />
              </div>
              <div>
                <label className="nx-label">Description</label>
                <input
                  className="nx-input"
                  value={newRuleDesc}
                  onChange={(e) => setNewRuleDesc(e.target.value)}
                  placeholder="Block attempts to access admin panels"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="ruleEnabled"
                  checked={newRuleEnabled}
                  onChange={(e) => setNewRuleEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-nexus-hairline"
                />
                <label htmlFor="ruleEnabled" className="text-xs font-medium text-nexus-text">
                  Enabled by Default
                </label>
              </div>
              <button
                type="button"
                className="nx-btn-primary w-full py-1"
                onClick={handleSaveRule}
              >
                Add Rule
              </button>
            </div>

            {/* Custom Rules List has been moved to main tab area */}
          </div>
        )}

        <div className="space-y-2 pt-2 border-t border-nexus-hairline">
          <button
            className="nx-btn-primary w-full flex items-center justify-center font-semibold"
            onClick={() => (isRunning ? stop() : run())}
          >
            {isRunning ? <Ic.stop className="h-4 w-4 mr-2" /> : <Ic.play className="h-4 w-4 mr-2" />}
            {isRunning ? "Stop WAF Proxy" : "Start WAF Proxy"}
          </button>

          <div className="grid grid-cols-2 gap-2">
            <button className="nx-btn-ghost w-full py-1 text-xs" onClick={downloadLogsCsv}>
              <Ic.download className="h-3.5 w-3.5" /> Download CSV
            </button>
            <button className="nx-btn-ghost w-full py-1 text-xs text-red-400 hover:text-red-500 hover:border-red-900/50" onClick={handleClearLogs}>
              <Ic.trash className="h-3.5 w-3.5" /> Clear Logs
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <>
      <ModuleScaffold
        title="Portable WAF (MVP)"
        description="Reverse-proxy WAF ringan dengan dukungan TLS termination, Virtual Hosts routing, custom regex rule editor, dan rate limiting."
        icon={Ic.defense}
        consoleRef={consoleRef}
        module="waf"
        form={renderForm()}
        customTabs={[
          {
            id: "grafik",
            label: "Grafik & Diagnosa",
            render: () => <WafDashboard logs={logs} stats={stats} />
          },
          {
            id: "logs",
            label: "Log Serangan",
            render: () => <WafLogsTab logs={logs} onClear={handleClearLogs} onDownload={downloadLogsCsv} onSelectLog={setSelectedLog} />
          },
          {
            id: "vhosts",
            label: "Virtual Hosts",
            render: () => <WafVhostTab vhosts={vhosts} onDelete={handleDeleteVhost} onEdit={handleEditVhost} />
          },
          {
            id: "rules",
            label: "Custom Rules",
            render: () => <WafRulesTab customRules={customRules} onDelete={handleDeleteRule} onToggle={handleToggleRuleStatus} />
          }
        ]}
      />

      {selectedLog && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-nexus-elevated border border-nexus-border rounded-xl w-full max-w-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <header className="flex justify-between items-center px-5 py-4 border-b border-nexus-hairline bg-nexus-panel">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-nexus-accent animate-pulse" />
                <h3 className="font-semibold text-nexus-text text-sm font-mono">WAF Incident Log Details</h3>
              </div>
              <button 
                onClick={() => setSelectedLog(null)}
                className="text-nexus-muted hover:text-nexus-text text-xs font-semibold px-2 py-1 rounded bg-nexus-surface border border-nexus-hairline hover:bg-nexus-panel transition-colors"
              >
                ✕ Close
              </button>
            </header>
            
            <div className="p-5 space-y-4 text-xs">
              <div className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-2.5 font-mono">
                <span className="text-nexus-muted font-semibold">Timestamp</span>
                <span className="text-nexus-text">{selectedLog.ts}</span>
                
                <span className="text-nexus-muted font-semibold">Client IP</span>
                <span className="text-nexus-text">{selectedLog.ip}</span>
                
                <span className="text-nexus-muted font-semibold">Origin Geo</span>
                <span className="text-nexus-text flex items-center gap-1.5">
                  <span>{getFlagEmoji(selectedLog.country_code)}</span>
                  <span>{selectedLog.country_name || "Unknown"} ({selectedLog.country_code || "-"})</span>
                </span>
                
                <span className="text-nexus-muted font-semibold">Triggered Rule</span>
                <span className={`font-bold uppercase ${
                  !selectedLog.rule.startsWith("allow:") && !selectedLog.rule.startsWith("detect:")
                    ? "text-red-400"
                    : selectedLog.rule.startsWith("detect:")
                    ? "text-yellow-400"
                    : "text-green-400"
                }`}>
                  {selectedLog.rule}
                </span>
                
                <span className="text-nexus-muted font-semibold">Requested Path</span>
                <div className="text-nexus-accent2 bg-nexus-surface/50 border border-nexus-hairline p-2 rounded break-all max-h-24 overflow-auto font-mono text-[11px] leading-relaxed">
                  {selectedLog.path}
                </div>
                
                <span className="text-nexus-muted font-semibold">Payload Data</span>
                <div className="text-nexus-text bg-nexus-surface/50 border border-nexus-hairline p-2 rounded break-all max-h-24 overflow-auto font-mono text-[11px] leading-relaxed">
                  {selectedLog.payload || "-"}
                </div>
              </div>
            </div>
            
            <footer className="px-5 py-3 border-t border-nexus-hairline bg-nexus-panel flex justify-end gap-2">
              <button
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(JSON.stringify(selectedLog, null, 2));
                  } catch {}
                }}
                className="nx-btn-ghost py-1 px-3 text-xs"
              >
                Copy JSON
              </button>
              <button
                onClick={() => setSelectedLog(null)}
                className="nx-btn-primary py-1 px-4 text-xs font-semibold"
              >
                Done
              </button>
            </footer>
          </div>
        </div>
      )}
    </>
  );
};

export default WAF;

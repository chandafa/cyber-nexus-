// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusAtlas.tsx — Nexus Atlas: graf attack-path & blast radius.
// Memanggil runner: fleet_atlas_* (stats, graph, exposed, blast). Pro-gated.
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Riskiest {
  id: string;
  label: string;
  risk: number;
  alert_count: number;
}
interface GraphNode {
  id: string;
  label: string;
  type: string;
  risk: number;
  alert_count: number;
}
interface GraphEdge {
  src: string;
  dst: string;
  kind: string;
  weight: number;
}
interface ExposedHost {
  id: string;
  label: string;
  risk: number;
  reach_count: number;
  exposure: number;
}
interface BlastResult {
  ok: boolean;
  origin: string;
  reachable: string[];
  reach_count: number;
  score: number;
}

const riskColor = (r: number) =>
  r >= 70 ? "text-nexus-danger" : r >= 40 ? "text-nexus-warning" : "text-nexus-muted";

export const NexusAtlas: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [riskiest, setRiskiest] = useState<Riskiest[]>([]);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [exposed, setExposed] = useState<ExposedHost[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // blast lookup
  const [node, setNode] = useState("");
  const [blast, setBlast] = useState<BlastResult | null>(null);
  const [blastBusy, setBlastBusy] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const s = await runToolJson<any>("fleet_atlas_stats");
      setStats(s);
      setRiskiest(s?.riskiest || []);
      const g = await runToolJson<any>("fleet_atlas_graph");
      setNodes(g?.nodes || []);
      setEdges(g?.edges || []);
      const ex = await runToolJson<any>("fleet_atlas_exposed", buildArgs({ limit: 10 }));
      setExposed(ex?.hosts || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const runBlast = useCallback(async (n?: string) => {
    const target = (n ?? node).trim();
    if (!target) {
      setError("Masukkan id node untuk hitung blast radius.");
      return;
    }
    setBlastBusy(true);
    setError("");
    try {
      const d = await runToolJson<BlastResult>("fleet_atlas_blast", buildArgs({ node: target }));
      if ((d as any)?.ok === false) throw new Error((d as any).error || "gagal hitung blast radius");
      setBlast(d);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBlastBusy(false);
    }
  }, [node]);

  const nodeLabel = (id: string) => nodes.find((n) => n.id === id)?.label || id;

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.mapper className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">
            Nexus Atlas — Attack Path & Blast Radius
          </h1>
          <p className="text-sm text-nexus-muted">
            Graf hubungan aset untuk menemukan jalur serang, host paling terekspos,
            dan dampak (blast radius) bila sebuah node dikompromi.
          </p>
        </div>
        <button
          onClick={load}
          disabled={busy}
          className="flex items-center gap-1.5 border border-nexus-border px-3 py-1.5 text-sm text-nexus-muted transition-colors hover:bg-nexus-panel hover:text-nexus-text disabled:opacity-50"
        >
          <Ic.refresh className="h-4 w-4" /> Refresh
        </button>
      </header>

      {error && (
        <div className="border border-nexus-danger/40 bg-nexus-danger/10 px-4 py-2 text-sm text-nexus-danger">
          {error}
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Nodes" value={stats?.nodes ?? "—"} />
        <Stat label="Edges" value={stats?.edges ?? "—"} />
        <Stat label="Exposed hosts" value={exposed.length} />
        <Stat label="Riskiest" value={riskiest.length} cls="text-nexus-warning" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Exposed hosts */}
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-nexus-text">Host Paling Terekspos</h2>
          <div className="border border-nexus-hairline bg-nexus-surface">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                  <th className="px-4 py-2.5">Host</th>
                  <th className="px-4 py-2.5">Risk</th>
                  <th className="px-4 py-2.5">Reach</th>
                  <th className="px-4 py-2.5">Exposure</th>
                  <th className="px-4 py-2.5"></th>
                </tr>
              </thead>
              <tbody>
                {exposed.map((h) => (
                  <tr key={h.id} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                    <td className="px-4 py-2.5 text-nexus-text">
                      {h.label}
                      <div className="font-mono text-[10px] text-nexus-subtle">{h.id}</div>
                    </td>
                    <td className={`px-4 py-2.5 font-semibold ${riskColor(h.risk)}`}>{h.risk}</td>
                    <td className="px-4 py-2.5 text-nexus-muted">{h.reach_count}</td>
                    <td className="px-4 py-2.5 text-nexus-muted">{h.exposure}</td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => {
                          setNode(h.id);
                          runBlast(h.id);
                        }}
                        className="text-[12px] text-nexus-accent hover:brightness-110"
                      >
                        Blast
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!exposed.length && (
              <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
                {busy ? "Memuat…" : "Belum ada data graf. Jalankan manager + agent agar topologi terbentuk."}
              </p>
            )}
          </div>
        </section>

        {/* Blast radius lookup */}
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-nexus-text">Hitung Blast Radius</h2>
          <div className="space-y-3 border border-nexus-hairline bg-nexus-surface p-4">
            <div className="flex gap-2">
              <input
                value={node}
                onChange={(e) => setNode(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && runBlast()}
                placeholder="id node (mis. host-01)"
                className="flex-1 border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-sm text-nexus-text"
              />
              <button
                onClick={() => runBlast()}
                disabled={blastBusy}
                className="flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-3 py-2 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
              >
                <Ic.attack className="h-4 w-4" /> Hitung
              </button>
            </div>
            {blast ? (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  <Stat label="Reachable" value={blast.reach_count} cls="text-nexus-danger" />
                  <Stat label="Score" value={blast.score} cls="text-nexus-warning" />
                </div>
                <div>
                  <div className="mb-1 text-[11px] uppercase tracking-wider text-nexus-subtle">
                    Dari <span className="font-mono text-nexus-muted">{blast.origin}</span> →{" "}
                    {blast.reachable.length} node terjangkau
                  </div>
                  <div className="max-h-40 overflow-auto border border-nexus-hairline">
                    {blast.reachable.map((id) => (
                      <div
                        key={id}
                        className="border-b border-nexus-hairline/60 px-3 py-1.5 text-[12px] text-nexus-muted last:border-b-0"
                      >
                        <span className="font-mono text-nexus-subtle">{id}</span>{" "}
                        {nodeLabel(id) !== id && <span>— {nodeLabel(id)}</span>}
                      </div>
                    ))}
                    {!blast.reachable.length && (
                      <p className="px-3 py-4 text-center text-[12px] italic text-nexus-subtle">
                        Tak ada node lain yang terjangkau.
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-[12px] italic text-nexus-subtle">
                {blastBusy ? "Menghitung…" : "Pilih host di tabel kiri atau ketik id node, lalu Hitung."}
              </p>
            )}
          </div>
        </section>
      </div>

      {/* Graph summary: nodes + edges */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-nexus-text">Nodes ({nodes.length})</h2>
          <div className="max-h-72 overflow-auto border border-nexus-hairline bg-nexus-surface">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-nexus-surface">
                <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                  <th className="px-4 py-2.5">Node</th>
                  <th className="px-4 py-2.5">Tipe</th>
                  <th className="px-4 py-2.5">Risk</th>
                  <th className="px-4 py-2.5">Alerts</th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((n) => (
                  <tr key={n.id} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                    <td className="px-4 py-2.5 text-nexus-text">
                      {n.label}
                      <div className="font-mono text-[10px] text-nexus-subtle">{n.id}</div>
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-nexus-muted">{n.type}</td>
                    <td className={`px-4 py-2.5 font-semibold ${riskColor(n.risk)}`}>{n.risk}</td>
                    <td className="px-4 py-2.5 text-nexus-muted">{n.alert_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!nodes.length && (
              <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
                {busy ? "Memuat…" : "Belum ada node."}
              </p>
            )}
          </div>
        </section>

        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-nexus-text">Edges ({edges.length})</h2>
          <div className="max-h-72 overflow-auto border border-nexus-hairline bg-nexus-surface">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-nexus-surface">
                <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                  <th className="px-4 py-2.5">Dari</th>
                  <th className="px-4 py-2.5">Ke</th>
                  <th className="px-4 py-2.5">Jenis</th>
                  <th className="px-4 py-2.5">Bobot</th>
                </tr>
              </thead>
              <tbody>
                {edges.map((e, k) => (
                  <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                    <td className="px-4 py-2.5 font-mono text-[11px] text-nexus-muted">{e.src}</td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-nexus-muted">{e.dst}</td>
                    <td className="px-4 py-2.5 text-[11px] text-nexus-muted">{e.kind}</td>
                    <td className="px-4 py-2.5 text-nexus-muted">{e.weight}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!edges.length && (
              <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
                {busy ? "Memuat…" : "Belum ada edge."}
              </p>
            )}
          </div>
        </section>
      </div>
    </div>
  );
};

const Stat: React.FC<{ label: string; value: React.ReactNode; cls?: string }> = ({ label, value, cls }) => (
  <div className="border border-nexus-hairline bg-nexus-panel/40 px-4 py-3 text-center">
    <div className={`text-xl font-bold ${cls || "text-nexus-text"}`}>{value}</div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
  </div>
);

export default NexusAtlas;

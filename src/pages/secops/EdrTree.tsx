// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/secops/EdrTree.tsx — EDR: pohon proses (pid/ppid) + garis keturunan.
// Memanggil runner: edr_hosts / edr_tree (Pro-gated).
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../../lib/icons";
import { runToolJson } from "../../lib/tauri";

interface ProcNode {
  pid: number;
  name: string;
  user: string;
  cmdline: string;
  risk?: string;
  children: ProcNode[];
}

const TreeNode: React.FC<{ node: ProcNode; depth: number }> = ({ node, depth }) => (
  <div>
    <div
      className="flex items-baseline gap-2 py-1 font-mono text-[12.5px]"
      style={{ paddingLeft: depth * 18 }}
    >
      <span className={node.risk ? "font-semibold text-nexus-danger" : "text-nexus-text"}>
        {node.name}
      </span>
      <span className="text-[10px] text-nexus-subtle">#{node.pid}</span>
      {node.risk && (
        <span className="text-[10px] font-semibold uppercase text-nexus-danger">{node.risk}</span>
      )}
      {node.cmdline && (
        <span className="truncate text-[10px] text-nexus-muted">{node.cmdline.slice(0, 90)}</span>
      )}
    </div>
    {(node.children || []).map((c) => (
      <TreeNode key={c.pid} node={c} depth={depth + 1} />
    ))}
  </div>
);

export const EdrTree: React.FC = () => {
  const [hosts, setHosts] = useState<any[]>([]);
  const [host, setHost] = useState("");
  const [tree, setTree] = useState<ProcNode[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const loadHosts = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<any>("edr_hosts");
      const hs = d?.hosts || [];
      setHosts(hs);
      if (hs.length && !host) {
        setHost(hs[0].agent_id);
      }
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, [host]);

  const loadTree = useCallback(async (agentId: string) => {
    if (!agentId) return;
    setBusy(true);
    try {
      const d = await runToolJson<any>("edr_tree", ["--agent_id", agentId]);
      setTree(d?.tree || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    loadHosts();
  }, [loadHosts]);
  useEffect(() => {
    if (host) loadTree(host);
  }, [host, loadTree]);

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.server className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">EDR — Process Tree</h1>
          <p className="text-sm text-nexus-muted">
            Silsilah proses induk→anak. Node merah = garis keturunan mencurigakan.
          </p>
        </div>
        <button
          onClick={loadHosts}
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

      <div className="flex items-center gap-2">
        <select
          value={host}
          onChange={(e) => setHost(e.target.value)}
          className="border border-nexus-border bg-nexus-surface px-2 py-2 text-sm text-nexus-text"
        >
          {!hosts.length && <option value="">(tak ada host)</option>}
          {hosts.map((h) => (
            <option key={h.agent_id} value={h.agent_id}>
              {h.agent_id} ({h.processes})
            </option>
          ))}
        </select>
      </div>

      <div className="overflow-auto border border-nexus-hairline bg-nexus-surface p-4">
        {tree.map((n) => (
          <TreeNode key={n.pid} node={n} depth={0} />
        ))}
        {!tree.length && (
          <p className="py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada inventori proses. Agent mengirim snapshot proses otomatis."}
          </p>
        )}
      </div>
    </div>
  );
};

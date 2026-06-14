// src/pages/History.tsx — SDD bagian 8.3 (SessionHistory).
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Ic } from "../lib/icons";
import { Select } from "../components/Select";
import { useScanStore } from "../app/store/scan.store";
import { StatusBadge } from "../components/StatusBadge";
import { formatDate } from "../lib/utils";
import { deleteSession } from "../lib/tauri";

export const History: React.FC = () => {
  const navigate = useNavigate();
  const { history, refreshHistory, loadingHistory } = useScanStore();
  const [query, setQuery] = useState("");
  const [moduleFilter, setModuleFilter] = useState("");

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  const filtered = history.filter((s) => {
    if (moduleFilter && s.module !== moduleFilter) return false;
    if (query && !`${s.target} ${s.module} ${s.mode}`.toLowerCase().includes(query.toLowerCase()))
      return false;
    return true;
  });

  const modules = Array.from(new Set(history.map((s) => s.module)));

  const handleDelete = async (id: string) => {
    await deleteSession(id);
    refreshHistory();
  };

  return (
    <div className="p-6">
      <header className="mb-5 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-nexus-text">History</h1>
          <p className="text-sm text-nexus-muted">Semua sesi scan tersimpan</p>
        </div>
        <button className="nx-btn-ghost" onClick={refreshHistory}>
          <Ic.refresh className={`h-4 w-4 ${loadingHistory ? "animate-spin" : ""}`} /> Refresh
        </button>
      </header>

      <div className="mb-4 flex gap-3">
        <div className="relative flex-1">
          <Ic.search className="absolute left-3 top-3 h-4 w-4 text-nexus-muted" />
          <input
            className="nx-input pl-9"
            placeholder="Cari target / modul..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <Select
          className="w-52"
          value={moduleFilter}
          onChange={setModuleFilter}
          options={[{ value: "", label: "Semua modul" }, ...modules.map((m) => ({ value: m, label: m }))]}
        />
      </div>

      <div className="nx-card p-0">
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-nexus-muted">
            <tr>
              <th className="px-4 py-3">Modul</th>
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Mulai</th>
              <th className="px-4 py-3 text-right">Aksi</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-nexus-muted">
                  Tidak ada sesi.
                </td>
              </tr>
            ) : (
              filtered.map((s) => (
                <tr key={s.id} className="border-t border-nexus-border/50 hover:bg-nexus-panel/40">
                  <td className="px-4 py-3 capitalize text-nexus-text">{s.module}</td>
                  <td className="px-4 py-3 font-mono text-nexus-muted">{s.target || "-"}</td>
                  <td className="px-4 py-3 text-nexus-muted">{s.mode || "-"}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="px-4 py-3 text-nexus-muted">{formatDate(s.started_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-2">
                      <button
                        className="nx-btn-ghost px-2.5 py-1.5 text-xs"
                        onClick={() => navigate(`/report?session=${s.id}`)}
                        title="Buat laporan"
                      >
                        <Ic.report className="h-3.5 w-3.5" />
                      </button>
                      <button
                        className="nx-btn-ghost px-2.5 py-1.5 text-xs hover:border-red-500/40 hover:text-red-300"
                        onClick={() => handleDelete(s.id)}
                        title="Hapus"
                      >
                        <Ic.trash className="h-3.5 w-3.5" />
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

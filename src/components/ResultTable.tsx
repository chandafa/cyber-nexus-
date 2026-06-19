// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/components/ResultTable.tsx — SDD bagian 9.2.
// Tabel hasil generik dengan sort & export CSV.
import React, { useMemo, useState } from "react";
import { toCSV } from "../lib/parser";
import { exportTextFile } from "../lib/output";
import { Ic } from "../lib/icons";

export interface Column<T> {
  key: keyof T | string;
  header: string;
  render?: (row: T) => React.ReactNode;
  sortable?: boolean;
}

interface Props<T> {
  columns: Column<T>[];
  rows: T[];
  csvName?: string;
  empty?: string;
}

export function ResultTable<T extends Record<string, any>>({
  columns,
  rows,
  csvName,
  empty = "Belum ada hasil.",
}: Props<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [asc, setAsc] = useState(true);

  const sorted = useMemo(() => {
    if (!sortKey) return rows;
    return [...rows].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (av === bv) return 0;
      const cmp = av > bv ? 1 : -1;
      return asc ? cmp : -cmp;
    });
  }, [rows, sortKey, asc]);

  const toggleSort = (key: string) => {
    if (sortKey === key) setAsc(!asc);
    else {
      setSortKey(key);
      setAsc(true);
    }
  };

  return (
    <div className="overflow-hidden rounded-2xl border border-nexus-hairline">
      <div className="flex items-center justify-between border-b border-nexus-hairline bg-nexus-panel/60 px-3.5 py-2.5">
        <span className="text-xs text-nexus-muted">{rows.length} baris</span>
        {csvName && rows.length > 0 && (
          <button
            className="nx-btn-ghost px-2.5 py-1.5 text-xs"
            onClick={() => exportTextFile(csvName, toCSV(sorted))}
          >
            <Ic.download className="h-3.5 w-3.5" /> Export CSV
          </button>
        )}
      </div>
      <div className="max-h-[420px] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-nexus-surface">
            <tr>
              {columns.map((c) => (
                <th
                  key={String(c.key)}
                  className="cursor-pointer px-3 py-2 text-xs font-semibold text-nexus-muted"
                  onClick={() => c.sortable !== false && toggleSort(String(c.key))}
                >
                  <span className="inline-flex items-center gap-1">
                    {c.header}
                    {c.sortable !== false && <Ic.sort className="h-3 w-3 opacity-40" />}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-3 py-8 text-center text-nexus-muted">
                  {empty}
                </td>
              </tr>
            ) : (
              sorted.map((row, i) => (
                <tr key={i} className="border-t border-nexus-border/50 hover:bg-nexus-panel/50">
                  {columns.map((c) => (
                    <td key={String(c.key)} className="px-3 py-2 text-nexus-text">
                      {c.render ? c.render(row) : String(row[c.key as string] ?? "")}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

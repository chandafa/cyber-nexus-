// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/AssetInventory.tsx — SDD v2 §5.14.
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { ResultTable } from "../components/ResultTable";
import { runToolJson, isTauri } from "../lib/tauri";
import { formatDate } from "../lib/utils";

export const AssetInventory: React.FC = () => {
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const load = async (rebuild = false) => {
    if (!isTauri()) return;
    setLoading(true);
    try {
      const res = await runToolJson<any>("asset_inventory", [
        "--submode",
        rebuild ? "rebuild" : "list",
      ]);
      setAssets(res.assets || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(false);
  }, []);

  const newCount = assets.filter((a) => a.is_new).length;

  return (
    <div className="mx-auto max-w-6xl animate-fade-in p-6">
      <header className="mb-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="bg-nexus-accent/15 p-2">
            <Ic.asset className="h-5 w-5 text-nexus-accent" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-nexus-text">Asset Inventory</h1>
            <p className="text-xs text-nexus-muted">
              Semua host yang pernah ditemukan dari scan ({assets.length} aset
              {newCount > 0 ? `, ${newCount} baru` : ""})
            </p>
          </div>
        </div>
        <button className="nx-btn-primary" onClick={() => load(true)} disabled={loading}>
          <Ic.refresh className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Rebuild dari scan
        </button>
      </header>

      <ResultTable
        csvName="assets.csv"
        rows={assets.map((a) => ({
          ip_address: a.ip_address,
          hostname: a.hostname || "-",
          device_type: a.device_type,
          open_ports: a.open_ports,
          os_guess: a.os_guess || "-",
          last_seen: formatDate(a.last_seen),
          baru: a.is_new ? "BARU" : "",
        }))}
        empty="Belum ada aset. Jalankan Port Scanner / Network Mapper, lalu klik Rebuild."
        columns={[
          { key: "ip_address", header: "IP" },
          { key: "hostname", header: "Hostname" },
          { key: "device_type", header: "Tipe" },
          { key: "open_ports", header: "Port" },
          { key: "os_guess", header: "OS" },
          { key: "last_seen", header: "Terakhir" },
          {
            key: "baru",
            header: "",
            render: (a) =>
              a.baru ? (
                <span className="rounded-sm bg-nexus-accent/20 px-1.5 py-0.5 text-[10px] font-semibold text-nexus-accent">
                  BARU
                </span>
              ) : null,
          },
        ]}
      />
    </div>
  );
};

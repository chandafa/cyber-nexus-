// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/Scheduler.tsx — SDD v2 §5.17.
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { Select } from "../components/Select";
import { runToolJson, isTauri } from "../lib/tauri";

const CRON_PRESETS = [
  { value: "0 2 * * *", label: "Harian (02:00)" },
  { value: "0 3 * * 0", label: "Mingguan (Min 03:00)" },
  { value: "0 */6 * * *", label: "Tiap 6 jam" },
  { value: "*/30 * * * *", label: "Tiap 30 menit" },
];
const MODULES = ["port", "vuln", "network", "ssl", "defense"];

export const Scheduler: React.FC = () => {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [target, setTarget] = useState("scanme.nmap.org");
  const [module, setModule] = useState("port");
  const [cron, setCron] = useState("0 2 * * *");
  const [apsAvailable, setApsAvailable] = useState(true);

  const load = async () => {
    if (!isTauri()) return;
    const res = await runToolJson<any>("scheduler", ["--submode", "list"]);
    setSchedules(res.schedules || []);
    setApsAvailable(res.aps_available !== false);
  };

  useEffect(() => {
    load();
  }, []);

  const add = async () => {
    const res = await runToolJson<any>("scheduler", [
      "--submode", "add", "--target", target, "--module", module, "--cron_expr", cron,
    ]);
    setSchedules(res.schedules || []);
  };
  const remove = async (id: string) => {
    const res = await runToolJson<any>("scheduler", ["--submode", "remove", "--job_id", id]);
    setSchedules(res.schedules || []);
  };

  return (
    <div className="mx-auto max-w-5xl animate-fade-in p-6">
      <header className="mb-5 flex items-center gap-3">
        <div className="bg-nexus-accent/15 p-2">
          <Ic.scheduler className="h-5 w-5 text-nexus-accent" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-nexus-text">Scheduler</h1>
          <p className="text-xs text-nexus-muted">Jadwalkan scan otomatis (cron)</p>
        </div>
      </header>

      {!apsAvailable && (
        <p className="mb-4 border border-yellow-500/30 bg-severity-medium/10 px-3 py-2 text-xs text-yellow-200">
          APScheduler belum terpasang (pip install APScheduler) — jadwal tersimpan tapi next-run tidak dihitung.
        </p>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[360px_1fr]">
        <div className="nx-card space-y-3">
          <h2 className="nx-section">Jadwal Baru</h2>
          <div>
            <label className="nx-label">Target</label>
            <input className="nx-input font-mono" value={target} onChange={(e) => setTarget(e.target.value)} />
          </div>
          <div>
            <label className="nx-label">Modul</label>
            <Select value={module} onChange={setModule} options={MODULES} />
          </div>
          <div>
            <label className="nx-label">Jadwal</label>
            <Select value={cron} onChange={setCron} options={CRON_PRESETS} />
            <input
              className="nx-input mt-2 font-mono text-xs"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              placeholder="cron expr (mis. 0 2 * * *)"
            />
          </div>
          <button className="nx-btn-primary w-full" onClick={add}>
            <Ic.scheduler className="h-4 w-4" /> Tambah Jadwal
          </button>
        </div>

        <div className="nx-card p-0">
          <table className="w-full text-left text-sm">
            <thead className="text-xs text-nexus-subtle">
              <tr>
                <th className="px-4 py-2">Modul</th>
                <th className="px-4 py-2">Target</th>
                <th className="px-4 py-2">Cron</th>
                <th className="px-4 py-2">Next run</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {schedules.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-nexus-muted">Belum ada jadwal.</td>
                </tr>
              ) : (
                schedules.map((s) => (
                  <tr key={s.id} className="border-t border-nexus-hairline">
                    <td className="px-4 py-2 capitalize text-nexus-text">{s.module}</td>
                    <td className="px-4 py-2 font-mono text-nexus-muted">{s.target}</td>
                    <td className="px-4 py-2 font-mono text-xs text-nexus-muted">{s.cron_expr}</td>
                    <td className="px-4 py-2 text-xs text-nexus-muted">{s.next_run || "-"}</td>
                    <td className="px-4 py-2 text-right">
                      <button
                        className="nx-btn-ghost px-2 py-1 text-xs hover:text-red-300"
                        onClick={() => remove(s.id)}
                      >
                        <Ic.trash className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

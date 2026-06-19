// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/AttackSimulation.tsx — SDD v2 §5.9. Terstruktur & ter-scope (Scope Guard).
import React, { useEffect, useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { Select } from "../components/Select";
import { buildArgs, runToolJson, isTauri } from "../lib/tauri";

const SIMS = [
  { value: "brute_force", label: "Brute Force Login" },
  { value: "dir_fuzzing", label: "Directory/Param Fuzzing" },
  { value: "dos_lab", label: "Denial of Service (Lab)" },
  { value: "mitm_demo", label: "Man-in-the-Middle Demo" },
  { value: "privesc_check", label: "Privilege Escalation Check" },
];

export const AttackSimulation: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [targets, setTargets] = useState<any[]>([]);
  const [newTarget, setNewTarget] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [sim, setSim] = useState("brute_force");
  const [target, setTarget] = useState("");

  const loadTargets = async () => {
    if (!isTauri()) return;
    const res = await runToolJson<any>("scope", ["--submode", "list"]);
    setTargets(res.targets || []);
  };
  useEffect(() => {
    loadTargets();
  }, []);

  const addTarget = async () => {
    if (!newTarget.trim()) return;
    const res = await runToolJson<any>("scope", [
      "--submode", "add", "--cidr_or_host", newTarget.trim(), "--label", newLabel,
    ]);
    setTargets(res.targets || []);
    setNewTarget("");
    setNewLabel("");
  };
  const removeTarget = async (id: number) => {
    const res = await runToolJson<any>("scope", ["--submode", "remove", "--target_id", String(id)]);
    setTargets(res.targets || []);
  };

  const authorized = targets.some((t) => t.cidr_or_host === target && t.active);

  const run = () =>
    consoleRef.current?.start({
      command: "attack_sim",
      args: buildArgs({ simulation: sim, target, confirmed: "true" }),
      module: "attack",
      target,
    });

  return (
    <ModuleScaffold
      title="Attack Simulation"
      description="Simulasi serangan terstruktur & ter-scope untuk pembelajaran lab"
      icon={Ic.attack}
      consoleRef={consoleRef}
      module="attack"
      renderResult={(r) =>
        r.blocked ? (
          <div className="nx-card border-severity-critical/40">
            <div className="flex items-center gap-2 text-severity-critical">
              <Ic.warning className="h-4 w-4" /> Diblokir oleh Scope Guard
            </div>
            <p className="mt-2 text-sm text-nexus-muted">{r.reason}</p>
          </div>
        ) : (
          <div className="nx-card">
            <div className="flex items-center gap-2 text-nexus-green">
              <Ic.check className="h-4 w-4" /> {r.label} selesai
            </div>
            <p className="mt-2 text-sm text-nexus-muted">Tujuan pembelajaran: {r.goal}</p>
          </div>
        )
      }
      form={
        <div className="space-y-5">
          {/* Scope Guard */}
          <div className="rounded border border-severity-medium/30 bg-severity-medium/5 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-severity-medium">
              <Ic.lock className="h-4 w-4" /> Scope Guard — Authorized Targets
            </div>
            <div className="mb-2 space-y-1">
              {targets.length === 0 && (
                <p className="text-xs text-nexus-muted">Belum ada target yang diizinkan.</p>
              )}
              {targets.map((t) => (
                <div key={t.id} className="flex items-center justify-between text-xs">
                  <span className="font-mono text-nexus-text">
                    {t.cidr_or_host} {t.label ? <span className="text-nexus-subtle">({t.label})</span> : null}
                  </span>
                  <button className="text-nexus-subtle hover:text-red-300" onClick={() => removeTarget(t.id)}>
                    <Ic.trash className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
            <div className="flex gap-1.5">
              <input
                className="nx-input flex-1 text-xs"
                placeholder="IP / CIDR / host"
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
              />
              <input
                className="nx-input w-24 text-xs"
                placeholder="label"
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
              />
              <button className="nx-btn-ghost px-2.5" onClick={addTarget}>
                +
              </button>
            </div>
          </div>

          <div>
            <label className="nx-label">Jenis Simulasi</label>
            <Select value={sim} onChange={setSim} options={SIMS} />
          </div>
          <div>
            <label className="nx-label">Target</label>
            <input className="nx-input font-mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="harus ada di authorized targets" />
            {target && !authorized && (
              <p className="mt-1 text-xs text-severity-critical">Target belum di-authorize.</p>
            )}
          </div>
          <button className="nx-btn-primary w-full" onClick={run} disabled={!target || !authorized}>
            <Ic.play className="h-4 w-4" /> Jalankan Simulasi
          </button>
          <p className="rounded border border-yellow-500/30 bg-severity-medium/10 px-3 py-2 text-xs text-yellow-200">
            Hanya untuk lab/VM milik sendiri. Setiap simulasi divalidasi Scope Guard.
          </p>
        </div>
      }
    />
  );
};

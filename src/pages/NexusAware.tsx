// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusAware.tsx — Nexus Aware: simulasi phishing & kesadaran keamanan.
// Memanggil runner: fleet_aware_* (template Indonesia, kampanye, scoring). Pro-gated.
import React, { useState, useEffect, useCallback } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Template {
  id: string;
  name: string;
  category: string;
  difficulty: string;
  subject: string;
}
interface Campaign {
  id?: string;
  campaign_id?: string;
  name?: string;
  template_id?: string;
  count?: number;
  status?: string;
  created_iso?: string;
}
interface CreatedTarget {
  name: string;
  email: string;
  token: string;
  link_path: string;
}
interface PerUser {
  name: string;
  email: string;
  opened: boolean;
  clicked: boolean;
  reported: boolean;
}
interface ScoreResult {
  ok: boolean;
  sent: number;
  opened: number;
  clicked: number;
  reported: number;
  open_rate: number;
  click_rate: number;
  report_rate: number;
  per_user: PerUser[];
}

const pct = (v: number) => `${Math.round((v || 0) * 100)}%`;

export const NexusAware: React.FC = () => {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  // create form
  const [name, setName] = useState("");
  const [templateId, setTemplateId] = useState("");
  const [targets, setTargets] = useState(
    '[\n  {"name": "Budi", "email": "budi@contoh.id"}\n]'
  );
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8765");
  const [created, setCreated] = useState<CreatedTarget[] | null>(null);

  // score view
  const [score, setScore] = useState<ScoreResult | null>(null);
  const [scoreFor, setScoreFor] = useState<string>("");

  const cid = (c: Campaign) => c.campaign_id || c.id || "";

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const t = await runToolJson<any>("fleet_aware_templates");
      setTemplates(t?.templates || []);
      if (!templateId && t?.templates?.length) setTemplateId(t.templates[0].id);
      const c = await runToolJson<any>("fleet_aware_campaigns");
      setCampaigns(c?.campaigns || []);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const create = useCallback(async () => {
    setMsg("");
    setError("");
    setCreated(null);
    let parsed: any;
    try {
      parsed = JSON.parse(targets);
      if (!Array.isArray(parsed)) throw new Error("targets harus berupa array JSON");
    } catch (e: any) {
      setError(`Targets JSON tidak valid: ${e?.message || e}`);
      return;
    }
    if (!name.trim()) {
      setError("Nama kampanye wajib diisi.");
      return;
    }
    setBusy(true);
    try {
      const d = await runToolJson<any>(
        "fleet_aware_new",
        buildArgs({ name, template_id: templateId, targets: JSON.stringify(parsed) })
      );
      if (d?.ok === false) throw new Error(d.error || "gagal membuat kampanye");
      setCreated(d?.targets || []);
      setMsg(`Kampanye dibuat (id ${d?.campaign_id}) — ${d?.count ?? 0} target.`);
      await load();
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, [name, templateId, targets, load]);

  const send = useCallback(async (c: Campaign) => {
    setMsg("");
    setError("");
    setBusy(true);
    try {
      const d = await runToolJson<any>(
        "fleet_aware_send",
        buildArgs({ campaign_id: cid(c), base_url: baseUrl })
      );
      if (d?.ok === false) throw new Error(d.error || "gagal mengirim");
      if (d?.note) setMsg(`Catatan: ${d.note}`);
      else setMsg(`Terkirim: ${d?.sent ?? 0}/${d?.total ?? 0} (gagal ${d?.failed ?? 0}).`);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, [baseUrl]);

  const doScore = useCallback(async (c: Campaign) => {
    setMsg("");
    setError("");
    setBusy(true);
    try {
      const d = await runToolJson<ScoreResult>(
        "fleet_aware_score",
        buildArgs({ campaign: cid(c) })
      );
      if ((d as any)?.ok === false) throw new Error((d as any).error || "gagal scoring");
      setScore(d);
      setScoreFor(c.name || cid(c));
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, []);

  const del = useCallback(async (c: Campaign) => {
    if (!window.confirm("Hapus kampanye ini?")) return;
    setBusy(true);
    setError("");
    try {
      await runToolJson<any>("fleet_aware_del", buildArgs({ campaign_id: cid(c) }));
      if (scoreFor === (c.name || cid(c))) setScore(null);
      await load();
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  }, [load, scoreFor]);

  const copy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setMsg("Disalin ke clipboard.");
  };

  return (
    <div className="mx-auto max-w-6xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.alert className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">
            Nexus Aware — Simulasi Phishing
          </h1>
          <p className="text-sm text-nexus-muted">
            Kampanye kesadaran keamanan dengan template berbahasa Indonesia: kirim,
            lacak buka/klik/lapor, dan nilai kerentanan tiap pengguna.
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
      {msg && <p className="text-xs text-nexus-accent">{msg}</p>}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Templates */}
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-nexus-text">Template ({templates.length})</h2>
          <div className="border border-nexus-hairline bg-nexus-surface">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                  <th className="px-4 py-2.5">Nama</th>
                  <th className="px-4 py-2.5">Kategori</th>
                  <th className="px-4 py-2.5">Kesulitan</th>
                </tr>
              </thead>
              <tbody>
                {templates.map((t) => (
                  <tr key={t.id} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                    <td className="px-4 py-2.5 text-nexus-text">
                      {t.name}
                      <div className="text-[11px] text-nexus-subtle">{t.subject}</div>
                    </td>
                    <td className="px-4 py-2.5 text-nexus-muted">{t.category}</td>
                    <td className="px-4 py-2.5 uppercase text-[11px] text-nexus-muted">{t.difficulty}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!templates.length && (
              <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
                {busy ? "Memuat…" : "Belum ada template."}
              </p>
            )}
          </div>
        </section>

        {/* Create campaign */}
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-nexus-text">Buat Kampanye</h2>
          <div className="space-y-3 border border-nexus-hairline bg-nexus-surface p-4">
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wider text-nexus-subtle">
                Nama kampanye
              </label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Phishing Q3 — HR"
                className="w-full border border-nexus-border bg-nexus-surface px-3 py-2 text-sm text-nexus-text"
              />
            </div>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wider text-nexus-subtle">
                Template
              </label>
              <select
                value={templateId}
                onChange={(e) => setTemplateId(e.target.value)}
                className="w-full border border-nexus-border bg-nexus-surface px-2 py-2 text-sm text-nexus-text"
              >
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.difficulty})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wider text-nexus-subtle">
                Targets (JSON: [{`{name, email}`}])
              </label>
              <textarea
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                spellCheck={false}
                className="h-28 w-full resize-none border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-[12px] text-nexus-text"
              />
            </div>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wider text-nexus-subtle">
                Base URL (untuk pelacakan)
              </label>
              <input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                className="w-full border border-nexus-border bg-nexus-surface px-3 py-2 font-mono text-sm text-nexus-text"
              />
            </div>
            <button
              onClick={create}
              disabled={busy}
              className="flex items-center gap-1.5 border border-nexus-accent/40 bg-nexus-accent/15 px-3 py-2 text-sm text-nexus-accent transition-colors hover:bg-nexus-accent/25 disabled:opacity-50"
            >
              <Ic.check className="h-4 w-4" /> Buat Kampanye
            </button>
          </div>

          {created && (
            <div className="border border-nexus-hairline bg-nexus-surface">
              <div className="flex items-center justify-between border-b border-nexus-hairline px-4 py-2">
                <span className="text-[11px] uppercase tracking-wider text-nexus-subtle">
                  Link pelacakan per target
                </span>
                <button
                  onClick={() => copy(JSON.stringify(created, null, 2))}
                  className="flex items-center gap-1 text-[11px] text-nexus-muted hover:text-nexus-accent"
                >
                  <Ic.copy className="h-3.5 w-3.5" /> Salin JSON
                </button>
              </div>
              <table className="w-full text-sm">
                <tbody>
                  {created.map((t) => (
                    <tr key={t.token} className="border-b border-nexus-hairline/60">
                      <td className="px-4 py-2 text-nexus-text">
                        {t.name}
                        <div className="text-[11px] text-nexus-subtle">{t.email}</div>
                      </td>
                      <td className="px-4 py-2 font-mono text-[11px] text-nexus-muted">{t.link_path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {/* Campaigns */}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-nexus-text">Kampanye ({campaigns.length})</h2>
        <div className="border border-nexus-hairline bg-nexus-surface">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                <th className="px-4 py-2.5">Nama</th>
                <th className="px-4 py-2.5">Template</th>
                <th className="px-4 py-2.5">Target</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">Aksi</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={cid(c)} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                  <td className="px-4 py-2.5 text-nexus-text">
                    {c.name || "—"}
                    <div className="font-mono text-[10px] text-nexus-subtle">{cid(c)}</div>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-nexus-muted">{c.template_id || "—"}</td>
                  <td className="px-4 py-2.5 text-nexus-muted">{c.count ?? "—"}</td>
                  <td className="px-4 py-2.5 text-[11px] text-nexus-subtle">{c.status || "—"}</td>
                  <td className="whitespace-nowrap px-4 py-2.5">
                    <button onClick={() => send(c)} className="mr-3 text-[12px] text-nexus-accent hover:brightness-110">
                      Kirim
                    </button>
                    <button onClick={() => doScore(c)} className="mr-3 text-[12px] text-emerald-400 hover:brightness-110">
                      Skor
                    </button>
                    <button onClick={() => del(c)} className="text-[12px] text-nexus-danger hover:brightness-110">
                      Hapus
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!campaigns.length && (
            <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
              {busy ? "Memuat…" : "Belum ada kampanye. Buat kampanye di atas untuk memulai."}
            </p>
          )}
        </div>
      </section>

      {/* Score view */}
      {score && (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-nexus-text">Hasil Skor — {scoreFor}</h2>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="Terkirim" value={score.sent} />
            <Stat label="Open rate" value={pct(score.open_rate)} cls="text-nexus-warning" />
            <Stat label="Click rate" value={pct(score.click_rate)} cls="text-nexus-danger" />
            <Stat label="Report rate" value={pct(score.report_rate)} cls="text-emerald-400" />
          </div>
          <div className="border border-nexus-hairline bg-nexus-surface">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
                  <th className="px-4 py-2.5">Nama</th>
                  <th className="px-4 py-2.5">Email</th>
                  <th className="px-4 py-2.5">Buka</th>
                  <th className="px-4 py-2.5">Klik</th>
                  <th className="px-4 py-2.5">Lapor</th>
                </tr>
              </thead>
              <tbody>
                {(score.per_user || []).map((u, k) => (
                  <tr key={k} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                    <td className="px-4 py-2.5 text-nexus-text">{u.name}</td>
                    <td className="px-4 py-2.5 text-[11px] text-nexus-muted">{u.email}</td>
                    <td className="px-4 py-2.5">{u.opened ? "✓" : "—"}</td>
                    <td className={`px-4 py-2.5 ${u.clicked ? "text-nexus-danger" : ""}`}>{u.clicked ? "✓" : "—"}</td>
                    <td className={`px-4 py-2.5 ${u.reported ? "text-emerald-400" : ""}`}>{u.reported ? "✓" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};

const Stat: React.FC<{ label: string; value: React.ReactNode; cls?: string }> = ({ label, value, cls }) => (
  <div className="border border-nexus-hairline bg-nexus-panel/40 px-4 py-3 text-center">
    <div className={`text-xl font-bold ${cls || "text-nexus-text"}`}>{value}</div>
    <div className="text-[10px] uppercase tracking-wide text-nexus-subtle">{label}</div>
  </div>
);

export default NexusAware;

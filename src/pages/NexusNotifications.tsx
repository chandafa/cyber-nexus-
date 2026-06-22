// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src/pages/NexusNotifications.tsx — Notification Hub: kelola channel notifikasi
// (telegram/email/slack/discord/webhook/whatsapp) untuk alert fleet.
import React, { useEffect, useState } from "react";
import { Ic } from "../lib/icons";
import { buildArgs, runToolJson } from "../lib/tauri";

interface Channel {
  id: string;
  type: string;
  name: string;
  enabled: boolean;
  min_level: number | string;
  [k: string]: any;
}

type ChType = "telegram" | "email" | "slack" | "discord" | "webhook" | "whatsapp";

const CH_TYPES: ChType[] = ["telegram", "email", "slack", "discord", "webhook", "whatsapp"];

export const NexusNotifications: React.FC = () => {
  const [channels, setChannels] = useState<Channel[]>([]);
  const [minLevel, setMinLevel] = useState<number | string>(12);
  const [legacyWebhook, setLegacyWebhook] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // --- add-channel form state ---
  const [type, setType] = useState<ChType>("telegram");
  const [name, setName] = useState("");
  const [chMinLevel, setChMinLevel] = useState("12");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [useTls, setUseTls] = useState(true);
  const [adding, setAdding] = useState(false);

  const setF = (k: string, v: string) => setFields((f) => ({ ...f, [k]: v }));

  const load = async () => {
    setBusy(true);
    setError("");
    try {
      const d = await runToolJson<any>("fleet_notify_list");
      if (d?.ok === false) throw new Error(d.error || "gagal memuat channel");
      setChannels(d?.channels || []);
      setMinLevel(d?.min_level ?? 12);
      setLegacyWebhook(d?.legacy_webhook || "");
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const buildChannel = (): Record<string, any> | null => {
    const lvl = parseInt(chMinLevel, 10);
    const base: Record<string, any> = {
      type,
      name: name.trim() || type,
      enabled: true,
      min_level: Number.isNaN(lvl) ? 12 : lvl,
    };
    if (type === "telegram") {
      if (!fields.bot_token || !fields.chat_id) return null;
      return { ...base, bot_token: fields.bot_token, chat_id: fields.chat_id };
    }
    if (type === "email") {
      if (!fields.smtp_host || !fields.from_addr || !fields.to_addrs) return null;
      const port = parseInt(fields.smtp_port || "587", 10);
      return {
        ...base,
        smtp_host: fields.smtp_host,
        smtp_port: Number.isNaN(port) ? 587 : port,
        username: fields.username || "",
        password: fields.password || "",
        use_tls: useTls,
        from_addr: fields.from_addr,
        to_addrs: fields.to_addrs
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };
    }
    if (type === "whatsapp") {
      if (!fields.token || !fields.phone_id || !fields.to) return null;
      return { ...base, token: fields.token, phone_id: fields.phone_id, to: fields.to };
    }
    // slack / discord / webhook
    if (!fields.url) return null;
    return { ...base, url: fields.url };
  };

  const addChannel = async () => {
    const ch = buildChannel();
    if (!ch) {
      setError("Lengkapi semua field wajib untuk tipe channel ini.");
      return;
    }
    setAdding(true);
    setError("");
    setNotice("");
    try {
      const r = await runToolJson<any>("fleet_notify_add", buildArgs({ channel: JSON.stringify(ch) }));
      if (r?.ok === false) throw new Error(r.error || "gagal menambah channel");
      setNotice(`Channel "${ch.name}" (${ch.type}) ditambahkan.`);
      setName("");
      setFields({});
      setChMinLevel("12");
      setUseTls(true);
      load();
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setAdding(false);
    }
  };

  const testChannel = async (id: string) => {
    setError("");
    setNotice("");
    try {
      const r = await runToolJson<any>("fleet_notify_test", buildArgs({ id }));
      if (r?.ok === false) throw new Error(r.error || "test gagal");
      setNotice("Pesan uji terkirim — periksa channel tujuan.");
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  };

  const delChannel = async (id: string) => {
    if (!window.confirm("Hapus channel notifikasi ini?")) return;
    setError("");
    try {
      const r = await runToolJson<any>("fleet_notify_del", buildArgs({ id }));
      if (r?.ok === false) throw new Error(r.error || "gagal menghapus");
      load();
    } catch (e: any) {
      setError(String(e?.message || e));
    }
  };

  return (
    <div className="mx-auto max-w-5xl animate-fade-in space-y-6 p-6">
      <header className="flex items-center gap-3 border-b border-nexus-hairline pb-4">
        <div className="rounded-lg border border-nexus-accent/30 bg-nexus-accent/15 p-2">
          <Ic.alert className="h-6 w-6 text-nexus-accent" />
        </div>
        <div className="flex-1">
          <h1 className="text-lg font-bold tracking-tight text-nexus-text">Notification Hub</h1>
          <p className="text-sm text-nexus-muted">
            Kirim alert fleet ke Telegram, Email, Slack, Discord, Webhook, atau WhatsApp.
          </p>
        </div>
        <button
          onClick={load}
          disabled={busy}
          className="nx-btn-ghost text-xs"
        >
          <Ic.refresh className="h-3.5 w-3.5" /> Muat ulang
        </button>
      </header>

      {error && (
        <div className="border border-severity-critical/40 bg-severity-critical/10 px-4 py-2 text-sm text-severity-critical">
          {error}
        </div>
      )}
      {notice && (
        <div className="border border-nexus-green/40 bg-nexus-green/10 px-4 py-2 text-sm text-nexus-green">
          {notice}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 text-xs text-nexus-subtle">
        <span className="nx-chip">Ambang global min_level: <b className="text-nexus-text">{minLevel}</b></span>
        {legacyWebhook && (
          <span className="nx-chip">Legacy webhook aktif: <b className="text-nexus-text">{legacyWebhook}</b></span>
        )}
      </div>

      {/* Channel list */}
      <section className="border border-nexus-hairline bg-nexus-surface">
        <div className="border-b border-nexus-hairline px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-nexus-subtle">
          Channel terdaftar ({channels.length})
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-nexus-hairline text-left text-[11px] uppercase tracking-wider text-nexus-subtle">
              <th className="px-4 py-2.5">Tipe</th>
              <th className="px-4 py-2.5">Nama</th>
              <th className="px-4 py-2.5">Min Level</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5 text-right">Aksi</th>
            </tr>
          </thead>
          <tbody>
            {channels.map((c) => (
              <tr key={c.id} className="border-b border-nexus-hairline/60 hover:bg-nexus-panel/50">
                <td className="px-4 py-2.5 font-mono text-[11px] uppercase text-nexus-accent">{c.type}</td>
                <td className="px-4 py-2.5 text-nexus-text">{c.name}</td>
                <td className="px-4 py-2.5 font-mono text-[11px] text-nexus-muted">{c.min_level}</td>
                <td className="px-4 py-2.5">
                  <span
                    className={`inline-flex items-center gap-1 text-[11px] ${
                      c.enabled ? "text-emerald-400" : "text-nexus-subtle"
                    }`}
                  >
                    <span className={`h-1.5 w-1.5 rounded-full ${c.enabled ? "bg-emerald-400" : "bg-nexus-subtle"}`} />
                    {c.enabled ? "enabled" : "disabled"}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-right whitespace-nowrap">
                  <button className="text-nexus-accent hover:brightness-110 text-[11px] mr-3" onClick={() => testChannel(c.id)}>
                    Test
                  </button>
                  <button className="text-red-400 hover:brightness-110 text-[11px]" onClick={() => delChannel(c.id)}>
                    Hapus
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!channels.length && (
          <p className="px-4 py-8 text-center text-sm italic text-nexus-subtle">
            {busy ? "Memuat…" : "Belum ada channel. Tambahkan di bawah."}
          </p>
        )}
      </section>

      {/* Add channel form */}
      <section className="border border-nexus-hairline bg-nexus-surface p-4 space-y-4">
        <h2 className="text-[11px] font-semibold uppercase tracking-wider text-nexus-subtle">Tambah channel</h2>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <div>
            <label className="nx-label">Tipe</label>
            <select
              value={type}
              onChange={(e) => {
                setType(e.target.value as ChType);
                setFields({});
              }}
              className="nx-input"
            >
              {CH_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="nx-label">Nama</label>
            <input className="nx-input" value={name} onChange={(e) => setName(e.target.value)} placeholder={type} />
          </div>
          <div>
            <label className="nx-label">Min Level</label>
            <input
              type="number"
              className="nx-input font-mono"
              value={chMinLevel}
              onChange={(e) => setChMinLevel(e.target.value)}
            />
          </div>
        </div>

        {/* type-specific fields */}
        {type === "telegram" && (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Field label="Bot Token" value={fields.bot_token || ""} onChange={(v) => setF("bot_token", v)} mono />
            <Field label="Chat ID" value={fields.chat_id || ""} onChange={(v) => setF("chat_id", v)} mono />
          </div>
        )}

        {type === "email" && (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Field label="SMTP Host" value={fields.smtp_host || ""} onChange={(v) => setF("smtp_host", v)} />
            <Field label="SMTP Port" value={fields.smtp_port || ""} onChange={(v) => setF("smtp_port", v)} mono placeholder="587" />
            <Field label="Username" value={fields.username || ""} onChange={(v) => setF("username", v)} />
            <Field label="Password" value={fields.password || ""} onChange={(v) => setF("password", v)} type="password" />
            <Field label="From" value={fields.from_addr || ""} onChange={(v) => setF("from_addr", v)} placeholder="alerts@example.com" />
            <Field label="To (pisah koma)" value={fields.to_addrs || ""} onChange={(v) => setF("to_addrs", v)} placeholder="a@x.com, b@y.com" />
            <label className="flex items-center gap-2 text-xs text-nexus-muted">
              <input type="checkbox" checked={useTls} onChange={(e) => setUseTls(e.target.checked)} />
              Gunakan TLS
            </label>
          </div>
        )}

        {(type === "slack" || type === "discord" || type === "webhook") && (
          <Field label="Webhook URL" value={fields.url || ""} onChange={(v) => setF("url", v)} mono placeholder="https://…" />
        )}

        {type === "whatsapp" && (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Field label="Token" value={fields.token || ""} onChange={(v) => setF("token", v)} mono />
            <Field label="Phone ID" value={fields.phone_id || ""} onChange={(v) => setF("phone_id", v)} mono />
            <Field label="To" value={fields.to || ""} onChange={(v) => setF("to", v)} mono placeholder="+62…" />
          </div>
        )}

        <button className="nx-btn-primary text-xs" onClick={addChannel} disabled={adding}>
          <Ic.check className="h-3.5 w-3.5" /> {adding ? "Menambah…" : "Tambah channel"}
        </button>
      </section>
    </div>
  );
};

const Field: React.FC<{
  label: string;
  value: string;
  onChange: (v: string) => void;
  mono?: boolean;
  type?: string;
  placeholder?: string;
}> = ({ label, value, onChange, mono, type = "text", placeholder }) => (
  <div>
    <label className="nx-label">{label}</label>
    <input
      type={type}
      className={`nx-input ${mono ? "font-mono" : ""}`}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
    />
  </div>
);

export default NexusNotifications;

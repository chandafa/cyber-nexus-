// src/pages/Listener.tsx — Reverse Shell / Listener.
// Hanya untuk pengujian keamanan yang SAH (authorized pentesting).
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { ResultTable } from "../components/ResultTable";
import { Select } from "../components/Select";
import { buildArgs } from "../lib/tauri";

export const Listener: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [submode, setSubmode] = useState("payload");
  const [lhost, setLhost] = useState("");
  const [lport, setLport] = useState("4444");
  const [port, setPort] = useState("4444");
  const [duration, setDuration] = useState("60");
  const [shell, setShell] = useState("bash");

  const run = () =>
    consoleRef.current?.start({
      command: "listener",
      args:
        submode === "payload"
          ? buildArgs({ submode: "payload", lhost, lport, shell })
          : buildArgs({ submode: "listen", port, duration }),
      module: "listener",
      target: submode === "payload" ? `${lhost || "auto"}:${lport}` : `:${port}`,
    });

  const copy = (text: string) => {
    try {
      navigator.clipboard?.writeText(text);
    } catch {
      /* abaikan — clipboard mungkin tidak tersedia */
    }
  };

  return (
    <ModuleScaffold
      title="Reverse Shell / Listener"
      description="Generate payload reverse-shell atau bind TCP listener"
      icon={Ic.terminal}
      consoleRef={consoleRef}
      module="listener"
      renderResult={(r) =>
        r.submode === "payload" ? (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-4 text-xs text-nexus-muted">
              <span>
                LHOST <span className="font-mono text-nexus-text">{r.lhost}</span>
              </span>
              <span>
                LPORT <span className="font-mono text-nexus-text">{r.lport}</span>
              </span>
              <span>
                Total <span className="font-mono text-nexus-text">{r.total}</span>
              </span>
            </div>
            <ResultTable
              csvName="payloads.csv"
              rows={r.payloads || []}
              columns={[
                { key: "name", header: "Nama" },
                { key: "lang", header: "Lang" },
                {
                  key: "command",
                  header: "Command",
                  sortable: false,
                  render: (row) => (
                    <div className="flex items-start gap-2">
                      <span className="font-mono text-xs break-all">{row.command}</span>
                      <button
                        className="nx-btn-ghost shrink-0 px-1.5 py-1"
                        title="Salin"
                        onClick={() => copy(row.command)}
                      >
                        <Ic.copy className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ),
                },
              ]}
            />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-2">
              <div className="nx-card text-center">
                <div className="text-xs text-nexus-muted">Status</div>
                <div className="text-sm font-semibold">
                  {r.connected ? "Terhubung" : "Tidak ada koneksi"}
                </div>
              </div>
              <div className="nx-card text-center">
                <div className="text-xs text-nexus-muted">Connection</div>
                <div className="font-mono text-sm">{r.connection ?? "-"}</div>
              </div>
              <div className="nx-card text-center">
                <div className="text-xs text-nexus-muted">Bytes</div>
                <div className="font-mono text-sm">{r.bytes ?? 0}</div>
              </div>
            </div>
            <pre className="nx-card font-mono text-xs whitespace-pre-wrap">
              {r.received || (r.error ? `[ERROR] ${r.error}` : "(belum ada data diterima)")}
            </pre>
          </div>
        )
      }
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Mode</label>
            <Select
              value={submode}
              onChange={setSubmode}
              options={[
                { value: "payload", label: "Generate Payload" },
                { value: "listen", label: "Start Listener" },
              ]}
            />
          </div>

          {submode === "payload" ? (
            <>
              <div>
                <label className="nx-label">LHOST (kosong = IP LAN otomatis)</label>
                <input
                  className="nx-input font-mono"
                  placeholder="auto"
                  value={lhost}
                  onChange={(e) => setLhost(e.target.value)}
                />
              </div>
              <div>
                <label className="nx-label">LPORT</label>
                <input
                  className="nx-input font-mono"
                  value={lport}
                  onChange={(e) => setLport(e.target.value)}
                />
              </div>
              <div>
                <label className="nx-label">Shell</label>
                <input
                  className="nx-input font-mono"
                  value={shell}
                  onChange={(e) => setShell(e.target.value)}
                />
              </div>
            </>
          ) : (
            <>
              <div>
                <label className="nx-label">Port</label>
                <input
                  className="nx-input font-mono"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                />
              </div>
              <div>
                <label className="nx-label">Durasi (detik, maks 600)</label>
                <input
                  className="nx-input font-mono"
                  value={duration}
                  onChange={(e) => setDuration(e.target.value)}
                />
              </div>
            </>
          )}

          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" />{" "}
            {submode === "payload" ? "Generate Payload" : "Start Listener"}
          </button>
          <p className="text-xs text-nexus-muted">
            Hanya untuk target yang Anda miliki / berizin.
          </p>
        </div>
      }
    />
  );
};

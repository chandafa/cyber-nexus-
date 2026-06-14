// src/pages/WAF.tsx — lightweight WAF control page (MVP)
import React, { useRef, useState } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { buildArgs } from "../lib/tauri";
import { Select } from "../components/Select";
import { runToolJson } from "../lib/tauri";

export const WAF: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  const [listenPort, setListenPort] = useState("8080");
  const [backendHost, setBackendHost] = useState("127.0.0.1");
  const [backendPort, setBackendPort] = useState("8000");
  const [maxRps, setMaxRps] = useState("10");

  const run = () => {
    consoleRef.current?.start({
      command: "waf",
      args: buildArgs({ listen_port: listenPort, backend: backendHost, backend_port: backendPort, max_rps: maxRps }),
      module: "waf",
    });
  };

  const stop = async () => {
    const res = await runToolJson("waf_stop");
    consoleRef.current?.start({ command: "waf_status", args: [], module: "waf" });
    alert(JSON.stringify(res));
  };

  const showLogs = async () => {
    const res = await runToolJson("waf_logs", []);
    // open in console as JSON
    consoleRef.current?.start({ command: "waf_logs", args: [], module: "waf" });
  };

  return (
    <ModuleScaffold
      title="Portable WAF (MVP)"
      description="Reverse-proxy WAF ringan: rule-based blocking (SQLi/XSS/path-traversal) dan rate limiting. Gunakan untuk proteksi aplikasi lokal."
      icon={Ic.defense}
      consoleRef={consoleRef}
      module="waf"
      renderResult={(r) => (
        <div className="space-y-3">
          <div className="nx-card">
            <div className="text-xs text-nexus-muted">Status</div>
            <div className="font-mono text-sm">{r.status || "-"}</div>
          </div>
          <div className="nx-card">
            <div className="text-xs text-nexus-muted">Listening</div>
            <div className="font-mono text-sm">{r.listen_port ? `0.0.0.0:${r.listen_port}` : "-"}</div>
          </div>
        </div>
      )}
      form={
        <div className="space-y-4">
          <div>
            <label className="nx-label">Listen Port</label>
            <input className="nx-input font-mono" value={listenPort} onChange={(e) => setListenPort(e.target.value)} />
          </div>
          <div>
            <label className="nx-label">Backend Host</label>
            <input className="nx-input font-mono" value={backendHost} onChange={(e) => setBackendHost(e.target.value)} />
          </div>
          <div>
            <label className="nx-label">Backend Port</label>
            <input className="nx-input font-mono" value={backendPort} onChange={(e) => setBackendPort(e.target.value)} />
          </div>
          <div>
            <label className="nx-label">Max requests / sec (per IP)</label>
            <input className="nx-input font-mono" value={maxRps} onChange={(e) => setMaxRps(e.target.value)} />
          </div>
          <button className="nx-btn-primary w-full" onClick={run}>
            <Ic.play className="h-4 w-4" /> Start WAF
          </button>
          <div className="grid grid-cols-2 gap-2">
            <button className="nx-btn-ghost w-full" onClick={stop}>
              <Ic.stop className="h-4 w-4" /> Stop WAF
            </button>
            <button className="nx-btn-ghost w-full" onClick={showLogs}>
              <Ic.log className="h-4 w-4" /> Show Logs
            </button>
          </div>
        </div>
      }
    />
  );
};

export default WAF;

// src/pages/WAF.tsx — lightweight WAF control page (MVP)
import React, { useRef, useState, useEffect } from "react";
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
    // start via runner (background) and then refresh status
    runToolJson("waf", buildArgs({ listen_port: listenPort, backend: backendHost, backend_port: backendPort, max_rps: maxRps })).then(() => {
      fetchStatus();
    });
  };

  const stop = async () => {
    const res = await runToolJson("waf_stop", []);
    await fetchStatus();
    return res;
  };

  const showLogs = async () => {
    const res = await runToolJson("waf_logs", ["--limit", "200"]);
    setLogs(res.logs || []);
    setShowLogs(true);
  };

  const [isRunning, setIsRunning] = useState(false);
  const [statusInfo, setStatusInfo] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [showLogs, setShowLogs] = useState(false);

  const fetchStatus = async () => {
    try {
      const s = await runToolJson("waf_status", []);
      setIsRunning(s.status === "running");
      setStatusInfo(s);
    } catch (e) {
      setIsRunning(false);
      setStatusInfo(null);
    }
  };

  useEffect(() => {
    fetchStatus();
    const t = setInterval(fetchStatus, 3000);
    return () => clearInterval(t);
  }, []);

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
            <div className="font-mono text-sm">{statusInfo?.status || r.status || "-"}</div>
          </div>
          <div className="nx-card">
            <div className="text-xs text-nexus-muted">Listening</div>
            <div className="font-mono text-sm">{statusInfo?.listen || (r.listen_port ? `0.0.0.0:${r.listen_port}` : "-")}</div>
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
          <div className="space-y-2">
            <button
              className="nx-btn-primary w-full flex items-center justify-center"
              onClick={() => (isRunning ? stop() : run())}
            >
              {isRunning ? <Ic.stop className="h-4 w-4 mr-2" /> : <Ic.play className="h-4 w-4 mr-2" />}
              {isRunning ? "Stop WAF" : "Start WAF"}
            </button>

            <div className="grid grid-cols-2 gap-2">
              <button className="nx-btn-ghost w-full" onClick={fetchStatus}>
                <Ic.refresh className="h-4 w-4" /> Refresh
              </button>
              <button className="nx-btn-ghost w-full" onClick={showLogs}>
                <Ic.log className="h-4 w-4" /> Show Logs
              </button>
            </div>
          </div>
        </div>
      }
    />
    {showLogs && (
      <div className="p-4">
        <h3 className="font-semibold">WAF Logs (recent)</h3>
        <div className="overflow-auto mt-2 rounded border">
          <table className="w-full table-fixed text-sm">
            <thead className="bg-nexus-surface text-left text-xs">
              <tr>
                <th className="px-2 py-1">Time</th>
                <th className="px-2 py-1">IP</th>
                <th className="px-2 py-1">Rule</th>
                <th className="px-2 py-1">Path</th>
                <th className="px-2 py-1">Payload</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l, i) => (
                <tr key={i} className="odd:bg-white even:bg-nexus-surface">
                  <td className="px-2 py-1 font-mono text-xs">{l.ts}</td>
                  <td className="px-2 py-1">{l.ip}</td>
                  <td className="px-2 py-1">{l.rule}</td>
                  <td className="px-2 py-1 font-mono">{l.path}</td>
                  <td className="px-2 py-1 truncate">{l.payload}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-2 flex gap-2">
          <button
            className="nx-btn-ghost"
            onClick={async () => {
              const res = await runToolJson("waf_logs", ["--limit", "1000"]);
              setLogs(res.logs || []);
            }}
          >
            Reload
          </button>
          <button
            className="nx-btn-ghost"
            onClick={() => {
              setShowLogs(false);
            }}
          >
            Close
          </button>
        </div>
      </div>
    )}
  );
};

export default WAF;

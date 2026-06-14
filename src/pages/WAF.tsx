// src/pages/WAF.tsx — WAF control page with VHost and Custom Rules (MVP)
import React, { useRef, useState, useEffect } from "react";
import { Ic } from "../lib/icons";
import { ModuleScaffold } from "../components/ModuleScaffold";
import { type ScanConsoleHandle } from "../components/ScanConsole";
import { buildArgs, runToolJson } from "../lib/tauri";
import { useScanRuntimeStore } from "../app/store/scanRuntime.store";

export const WAF: React.FC = () => {
  const consoleRef = useRef<ScanConsoleHandle>(null);
  
  // WAF General state
  const [listenPort, setListenPort] = useState("8080");
  const [backendHost, setBackendHost] = useState("127.0.0.1");
  const [backendPort, setBackendPort] = useState("8000");
  const [maxRps, setMaxRps] = useState("10");
  const [maxLogMb, setMaxLogMb] = useState("10");
  const [learningMode, setLearningMode] = useState(false);
  const [allowlistIps, setAllowlistIps] = useState("");
  const [allowlistPaths, setAllowlistPaths] = useState("");

  // SSL settings
  const [sslEnabled, setSslEnabled] = useState(false);
  const [sslCertType, setSslCertType] = useState("self_signed");
  const [sslCertPath, setSslCertPath] = useState("");
  const [sslKeyPath, setSslKeyPath] = useState("");

  // UI Navigation Tabs
  const [activeTab, setActiveTab] = useState<"general" | "vhosts" | "rules">("general");

  const scan = useScanRuntimeStore((s) => s.scans["waf"]);
  const isRunning = scan?.running ?? false;

  const [logs, setLogs] = useState<any[]>([]);
  const [showLogs, setShowLogs] = useState(true);

  // VHosts state
  const [vhosts, setVhosts] = useState<any[]>([]);
  const [newVhostHost, setNewVhostHost] = useState("");
  const [newVhostBackend, setNewVhostBackend] = useState("127.0.0.1");
  const [newVhostPort, setNewVhostPort] = useState("8000");
  const [newVhostRps, setNewVhostRps] = useState("10");
  const [newVhostLearning, setNewVhostLearning] = useState(false);
  const [newVhostIps, setNewVhostIps] = useState("");
  const [newVhostPaths, setNewVhostPaths] = useState("");
  const [selectedRules, setSelectedRules] = useState<string[]>([
    "sql_injection", "xss", "path_traversal", "cmd_injection", "scanner_detected"
  ]);

  // Custom Rules state
  const [customRules, setCustomRules] = useState<any[]>([]);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRulePattern, setNewRulePattern] = useState("");
  const [newRuleDesc, setNewRuleDesc] = useState("");
  const [newRuleEnabled, setNewRuleEnabled] = useState(true);

  const run = () => {
    consoleRef.current?.start({
      command: "waf",
      args: buildArgs({
        foreground: true,
        listen_port: listenPort,
        backend: backendHost,
        backend_port: backendPort,
        max_rps: maxRps,
        max_log_mb: maxLogMb,
        learning_mode: learningMode,
        allowlist_ips: allowlistIps,
        allowlist_paths: allowlistPaths,
        ssl_enabled: sslEnabled,
        ssl_cert_type: sslCertType,
        ssl_cert_path: sslCertPath,
        ssl_key_path: sslKeyPath,
      }),
      module: "waf",
    });
  };

  const stop = () => {
    useScanRuntimeStore.getState().stop("waf");
  };

  // VHost CRUD Operations
  const fetchVhosts = async () => {
    try {
      const res = await runToolJson("waf_get_vhosts");
      if (res && res.status === "ok") {
        setVhosts(res.vhosts || []);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveVhost = async () => {
    if (!newVhostHost) return;
    try {
      await runToolJson("waf_save_vhost", buildArgs({
        hostname: newVhostHost,
        backend_host: newVhostBackend,
        backend_port: newVhostPort,
        max_rps: newVhostRps,
        learning_mode: newVhostLearning,
        allowlist_ips: newVhostIps,
        allowlist_paths: newVhostPaths,
        rules_json: JSON.stringify(selectedRules)
      }));
      setNewVhostHost("");
      setNewVhostIps("");
      setNewVhostPaths("");
      fetchVhosts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteVhost = async (hostname: string) => {
    try {
      await runToolJson("waf_delete_vhost", ["--hostname", hostname]);
      fetchVhosts();
    } catch (err) {
      console.error(err);
    }
  };

  // Custom Rule CRUD Operations
  const fetchCustomRules = async () => {
    try {
      const res = await runToolJson("waf_get_rules");
      if (res && res.status === "ok") {
        setCustomRules(res.rules || []);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveRule = async () => {
    if (!newRuleName || !newRulePattern) return;
    try {
      await runToolJson("waf_save_rule", buildArgs({
        name: newRuleName,
        pattern: newRulePattern,
        description: newRuleDesc,
        enabled: newRuleEnabled
      }));
      setNewRuleName("");
      setNewRulePattern("");
      setNewRuleDesc("");
      fetchCustomRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteRule = async (name: string) => {
    try {
      await runToolJson("waf_delete_rule", ["--name", name]);
      fetchCustomRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleRuleStatus = async (rule: any) => {
    try {
      await runToolJson("waf_save_rule", buildArgs({
        name: rule.name,
        pattern: rule.pattern,
        description: rule.description,
        enabled: !rule.enabled
      }));
      fetchCustomRules();
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await runToolJson("waf_logs", ["--limit", "200"]);
      setLogs(res.logs || []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchVhosts();
    fetchCustomRules();
    fetchLogs();
  }, []);

  useEffect(() => {
    let t: any;
    if (isRunning) {
      fetchLogs();
      t = setInterval(fetchLogs, 3000);
    }
    return () => {
      if (t) clearInterval(t);
    };
  }, [isRunning]);

  const toggleRuleSelection = (ruleName: string) => {
    if (selectedRules.includes(ruleName)) {
      setSelectedRules(selectedRules.filter(r => r !== ruleName));
    } else {
      setSelectedRules([...selectedRules, ruleName]);
    }
  };

  const renderForm = () => {
    return (
      <div className="space-y-5">
        {/* Navigation sub-tabs inside form panel */}
        <div className="flex border-b border-nexus-hairline">
          <button
            className={`flex-1 pb-2 text-[12px] font-semibold text-center border-b-2 transition-all ${
              activeTab === "general"
                ? "border-nexus-accent text-nexus-text"
                : "border-transparent text-nexus-muted hover:text-nexus-text"
            }`}
            onClick={() => setActiveTab("general")}
          >
            General & SSL
          </button>
          <button
            className={`flex-1 pb-2 text-[12px] font-semibold text-center border-b-2 transition-all ${
              activeTab === "vhosts"
                ? "border-nexus-accent text-nexus-text"
                : "border-transparent text-nexus-muted hover:text-nexus-text"
            }`}
            onClick={() => setActiveTab("vhosts")}
          >
            Virtual Hosts
          </button>
          <button
            className={`flex-1 pb-2 text-[12px] font-semibold text-center border-b-2 transition-all ${
              activeTab === "rules"
                ? "border-nexus-accent text-nexus-text"
                : "border-transparent text-nexus-muted hover:text-nexus-text"
            }`}
            onClick={() => setActiveTab("rules")}
          >
            Custom Rules
          </button>
        </div>

        {activeTab === "general" && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="nx-label">Proxy Listen Port</label>
                <input className="nx-input font-mono" value={listenPort} onChange={(e) => setListenPort(e.target.value)} />
              </div>
              <div>
                <label className="nx-label">Max Log Size (MB)</label>
                <input className="nx-input font-mono" value={maxLogMb} onChange={(e) => setMaxLogMb(e.target.value)} />
              </div>
            </div>

            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <h4 className="text-xs font-semibold text-nexus-text">Default Target Routing (Wildcard)</h4>
              <div>
                <label className="nx-label">Default Backend Host</label>
                <input className="nx-input font-mono" value={backendHost} onChange={(e) => setBackendHost(e.target.value)} />
              </div>
              <div>
                <label className="nx-label">Default Backend Port</label>
                <input className="nx-input font-mono" value={backendPort} onChange={(e) => setBackendPort(e.target.value)} />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="nx-label">Default Max RPS</label>
                  <input className="nx-input font-mono" value={maxRps} onChange={(e) => setMaxRps(e.target.value)} />
                </div>
                <div className="flex items-end pb-1.5">
                  <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                    <input
                      type="checkbox"
                      checked={learningMode}
                      onChange={(e) => setLearningMode(e.target.checked)}
                      className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                    />
                    Learning Mode
                  </label>
                </div>
              </div>
              <div>
                <label className="nx-label">Allowlist IPs</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={allowlistIps}
                  onChange={(e) => setAllowlistIps(e.target.value)}
                  placeholder="e.g. 127.0.0.1, 192.168.1.100"
                />
              </div>
              <div>
                <label className="nx-label">Allowlist Paths</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={allowlistPaths}
                  onChange={(e) => setAllowlistPaths(e.target.value)}
                  placeholder="e.g. /assets, /api/public"
                />
              </div>
            </div>

            {/* SSL/TLS termination configs */}
            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-nexus-text">SSL/TLS Termination</h4>
                <label className="relative inline-flex items-center cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={sslEnabled}
                    onChange={(e) => setSslEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                  />
                  <span className="ml-2 text-xs font-semibold text-nexus-text">Enable HTTPS</span>
                </label>
              </div>

              {sslEnabled && (
                <div className="space-y-3 pt-1 border-t border-nexus-hairline">
                  <div>
                    <label className="nx-label">Certificate Type</label>
                    <select
                      className="nx-input"
                      value={sslCertType}
                      onChange={(e) => setSslCertType(e.target.value)}
                    >
                      <option value="self_signed">Auto Self-Signed (openssl)</option>
                      <option value="custom">Custom Certificate Paths</option>
                    </select>
                  </div>

                  {sslCertType === "custom" && (
                    <div className="space-y-2">
                      <div>
                        <label className="nx-label">Certificate Pem Path</label>
                        <input
                          className="nx-input font-mono text-xs"
                          value={sslCertPath}
                          onChange={(e) => setSslCertPath(e.target.value)}
                          placeholder="C:/certs/fullchain.pem"
                        />
                      </div>
                      <div>
                        <label className="nx-label">Private Key Pem Path</label>
                        <input
                          className="nx-input font-mono text-xs"
                          value={sslKeyPath}
                          onChange={(e) => setSslKeyPath(e.target.value)}
                          placeholder="C:/certs/privkey.pem"
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "vhosts" && (
          <div className="space-y-4">
            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <h4 className="text-xs font-semibold text-nexus-text">Add / Edit Virtual Host</h4>
              <div>
                <label className="nx-label">Hostname (Domain)</label>
                <input
                  className="nx-input font-mono"
                  value={newVhostHost}
                  onChange={(e) => setNewVhostHost(e.target.value)}
                  placeholder="e.g. app.local"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="nx-label">Backend IP/Host</label>
                  <input className="nx-input font-mono" value={newVhostBackend} onChange={(e) => setNewVhostBackend(e.target.value)} />
                </div>
                <div>
                  <label className="nx-label">Backend Port</label>
                  <input className="nx-input font-mono" value={newVhostPort} onChange={(e) => setNewVhostPort(e.target.value)} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="nx-label">Max RPS</label>
                  <input className="nx-input font-mono" value={newVhostRps} onChange={(e) => setNewVhostRps(e.target.value)} />
                </div>
                <div className="flex items-end pb-1.5">
                  <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-nexus-text select-none">
                    <input
                      type="checkbox"
                      checked={newVhostLearning}
                      onChange={(e) => setNewVhostLearning(e.target.checked)}
                      className="h-4 w-4 rounded border-nexus-hairline bg-nexus-surface text-nexus-accent focus:ring-nexus-accent"
                    />
                    Learning Mode
                  </label>
                </div>
              </div>
              <div>
                <label className="nx-label">Allowlist IPs (comma-separated)</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newVhostIps}
                  onChange={(e) => setNewVhostIps(e.target.value)}
                  placeholder="e.g. 192.168.1.50"
                />
              </div>
              <div>
                <label className="nx-label">Allowlist Paths (comma-separated)</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newVhostPaths}
                  onChange={(e) => setNewVhostPaths(e.target.value)}
                  placeholder="e.g. /public"
                />
              </div>

              <div>
                <label className="nx-label">Enabled Rule Packages</label>
                <div className="space-y-1.5 max-h-32 overflow-auto border border-nexus-hairline rounded p-2 bg-nexus-surface">
                  {[
                    { key: "sql_injection", label: "SQL Injection Patterns" },
                    { key: "xss", label: "Cross-Site Scripting (XSS)" },
                    { key: "path_traversal", label: "Path Traversal Patterns" },
                    { key: "cmd_injection", label: "Command Injection Check" },
                    { key: "scanner_detected", label: "Scanner Detection heuristic" }
                  ].map((pkg) => (
                    <label key={pkg.key} className="flex items-center gap-2 text-xs cursor-pointer select-none text-nexus-text">
                      <input
                        type="checkbox"
                        checked={selectedRules.includes(pkg.key)}
                        onChange={() => toggleRuleSelection(pkg.key)}
                        className="h-3.5 w-3.5 rounded border-nexus-hairline text-nexus-accent"
                      />
                      {pkg.label}
                    </label>
                  ))}
                  {customRules.map((cr) => (
                    <label key={cr.name} className="flex items-center gap-2 text-xs cursor-pointer select-none text-nexus-text">
                      <input
                        type="checkbox"
                        checked={selectedRules.includes(cr.name)}
                        onChange={() => toggleRuleSelection(cr.name)}
                        className="h-3.5 w-3.5 rounded border-nexus-hairline text-nexus-accent"
                      />
                      <span className="text-nexus-accent font-semibold">{cr.name}</span> (Custom)
                    </label>
                  ))}
                </div>
              </div>

              <button
                type="button"
                className="nx-btn-primary w-full py-1"
                onClick={handleSaveVhost}
              >
                Save Virtual Host
              </button>
            </div>

            {/* List of existing virtual hosts */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-nexus-muted uppercase tracking-wider">Virtual Hosts List</h4>
              {vhosts.length === 0 ? (
                <p className="text-xs text-nexus-subtle italic">No custom virtual hosts configured yet.</p>
              ) : (
                vhosts.map((vh) => (
                  <div key={vh.id} className="p-2 border border-nexus-hairline rounded bg-nexus-panel flex justify-between items-center text-xs">
                    <div>
                      <div className="font-semibold text-nexus-text font-mono">{vh.hostname}</div>
                      <div className="text-[11px] text-nexus-muted font-mono">
                        Proxy to: {vh.backend_host}:{vh.backend_port}
                      </div>
                      <div className="text-[10px] text-nexus-subtle mt-0.5">
                        Rules: {vh.rules.join(", ")}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="text-red-400 hover:text-red-500 font-bold px-2 py-1"
                      onClick={() => handleDeleteVhost(vh.hostname)}
                    >
                      Delete
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === "rules" && (
          <div className="space-y-4">
            <div className="border border-nexus-hairline p-3 rounded bg-nexus-panel/50 space-y-3">
              <h4 className="text-xs font-semibold text-nexus-text">Add Custom Matching Pattern</h4>
              <div>
                <label className="nx-label">Rule Name</label>
                <input
                  className="nx-input font-mono"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  placeholder="e.g. block_admin_path"
                />
              </div>
              <div>
                <label className="nx-label">Regex Pattern</label>
                <input
                  className="nx-input font-mono text-xs"
                  value={newRulePattern}
                  onChange={(e) => setNewRulePattern(e.target.value)}
                  placeholder="e.g. /wp-admin|/administrator"
                />
              </div>
              <div>
                <label className="nx-label">Description</label>
                <input
                  className="nx-input"
                  value={newRuleDesc}
                  onChange={(e) => setNewRuleDesc(e.target.value)}
                  placeholder="Block attempts to access admin panels"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="ruleEnabled"
                  checked={newRuleEnabled}
                  onChange={(e) => setNewRuleEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-nexus-hairline"
                />
                <label htmlFor="ruleEnabled" className="text-xs font-medium text-nexus-text">
                  Enabled by Default
                </label>
              </div>
              <button
                type="button"
                className="nx-btn-primary w-full py-1"
                onClick={handleSaveRule}
              >
                Add Rule
              </button>
            </div>

            {/* List of custom rules */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-nexus-muted uppercase tracking-wider">Custom Regex Rules</h4>
              {customRules.length === 0 ? (
                <p className="text-xs text-nexus-subtle italic">No custom rules added yet.</p>
              ) : (
                customRules.map((rule) => (
                  <div key={rule.id} className="p-2 border border-nexus-hairline rounded bg-nexus-panel flex justify-between items-center text-xs">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-nexus-text">{rule.name}</span>
                        <span className={`text-[10px] px-1 rounded ${rule.enabled ? 'bg-green-800 text-green-200' : 'bg-gray-700 text-gray-400'}`}>
                          {rule.enabled ? 'active' : 'inactive'}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-nexus-accent2 font-semibold truncate max-w-[200px]">{rule.pattern}</div>
                      <div className="text-[10px] text-nexus-subtle">{rule.description}</div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        className="text-nexus-accent hover:brightness-110"
                        onClick={() => handleToggleRuleStatus(rule)}
                      >
                        Toggle
                      </button>
                      <button
                        type="button"
                        className="text-red-400 hover:text-red-500 font-bold"
                        onClick={() => handleDeleteRule(rule.name)}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        <div className="space-y-2 pt-2 border-t border-nexus-hairline">
          <button
            className="nx-btn-primary w-full flex items-center justify-center font-semibold"
            onClick={() => (isRunning ? stop() : run())}
          >
            {isRunning ? <Ic.stop className="h-4 w-4 mr-2" /> : <Ic.play className="h-4 w-4 mr-2" />}
            {isRunning ? "Stop WAF Proxy" : "Start WAF Proxy"}
          </button>

          <div className="grid grid-cols-2 gap-2">
            <button className="nx-btn-ghost w-full py-1 text-xs" onClick={fetchLogs}>
              <Ic.refresh className="h-3.5 w-3.5" /> Refresh Logs
            </button>
            <button className="nx-btn-ghost w-full py-1 text-xs" onClick={() => setShowLogs(!showLogs)}>
              <Ic.log className="h-3.5 w-3.5" /> {showLogs ? "Hide Logs" : "Show Logs"}
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <>
      <ModuleScaffold
        title="Portable WAF (MVP)"
        description="Reverse-proxy WAF ringan dengan dukungan TLS termination, Virtual Hosts routing, custom regex rule editor, dan rate limiting."
        icon={Ic.defense}
        consoleRef={consoleRef}
        module="waf"
        form={renderForm()}
      />
      {showLogs && (
        <div className="p-4 bg-nexus-surface border-t border-nexus-hairline">
          <div className="flex justify-between items-center mb-2">
            <h3 className="font-semibold text-nexus-text">WAF Logs (recent events)</h3>
            <button
              className="text-xs text-nexus-accent hover:brightness-115 font-semibold"
              onClick={fetchLogs}
            >
              Force Refresh
            </button>
          </div>
          <div className="overflow-auto max-h-48 rounded border border-nexus-hairline">
            <table className="w-full table-fixed text-xs">
              <thead className="bg-nexus-panel text-left text-xs text-nexus-muted">
                <tr>
                  <th className="px-2 py-1.5 w-[140px]">Time</th>
                  <th className="px-2 py-1.5 w-[110px]">Client IP</th>
                  <th className="px-2 py-1.5 w-[120px]">Triggered Rule</th>
                  <th className="px-2 py-1.5">Requested Path</th>
                  <th className="px-2 py-1.5">Payload Data</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-nexus-hairline text-nexus-text font-mono">
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center py-4 text-nexus-subtle italic">
                      No matching log events captured.
                    </td>
                  </tr>
                ) : (
                  logs.map((l, i) => {
                    const isBlocked = !l.rule.startsWith("allow:") && !l.rule.startsWith("detect:");
                    const isDetected = l.rule.startsWith("detect:");
                    return (
                      <tr
                        key={i}
                        className={`hover:bg-nexus-panel/40 ${
                          isBlocked
                            ? "bg-red-950/20 text-red-200"
                            : isDetected
                            ? "bg-yellow-950/20 text-yellow-200"
                            : "odd:bg-white/5 even:bg-transparent"
                        }`}
                      >
                        <td className="px-2 py-1 font-mono text-[11px]">{l.ts}</td>
                        <td className="px-2 py-1 text-[11.5px]">{l.ip}</td>
                        <td className="px-2 py-1 text-[11.5px] font-semibold">{l.rule}</td>
                        <td className="px-2 py-1 truncate text-[11px]">{l.path}</td>
                        <td className="px-2 py-1 truncate text-[11px]">{l.payload || "-"}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
};

export default WAF;

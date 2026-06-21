// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// app.js — SPA dashboard Nexus Fleet (vanilla JS, query REST API manager).
const $ = (id) => document.getElementById(id);
let timer = null;
let connected = false;
let curView = "overview";

function base() { return `http://${$("host").value.trim()}:${$("port").value.trim()}/api/v1`; }
function headers() { return { "X-Admin-Token": $("token").value.trim() }; }

async function api(path) {
  const r = await fetch(base() + path, { headers: headers() });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(base() + path, {
    method: "POST", headers: { ...headers(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function toast(msg, kind = "") {
  const el = $("toast");
  el.textContent = msg; el.className = "toast show " + kind;
  clearTimeout(el._t); el._t = setTimeout(() => (el.className = "toast"), 2600);
}
function setConn(ok) {
  connected = ok;
  const s = $("conn-status");
  s.className = "conn-status " + (ok ? "on" : "off");
  s.querySelector("[data-icon]").innerHTML = icon(ok ? "online" : "offline");
  $("conn-label").textContent = t(ok ? "conn.connected" : "conn.offline");
}

// ============ Routing ============
function showView(name) {
  curView = name;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === name));
  localStorage.setItem("nx_view", name);
  if (name === "help") renderHelp();
  if (name === "policy") loadPolicy();
  if (name === "license") loadLicense();
  if (name === "incidents") loadIncidents();
  if (name === "xdr") loadXDR();
  if (name === "ai") loadAI();
  if (name === "edr") loadEDR();
  if (name === "ueba") loadUEBA();
  if (name === "intel") loadIntel();
  if (name === "cloud") loadCloud();
  if (name === "ndr") loadNDR();
  if (name === "soar") loadSOAR();
}

// ============ SecOps: NDR ============
async function loadNDR() {
  if (!connected) return;
  try {
    const s = await api("/ndr/stats");
    $("nd-stats").innerHTML = `<div class="stat"><div class="stat-num">${s.observations ?? 0}</div><div class="stat-lbl">Flows (24h)</div></div>
      <div class="stat"><div class="stat-num">${s.distinct_dst ?? 0}</div><div class="stat-lbl">Destinations</div></div>`;
  } catch {}
  let data; try { data = await api("/ndr/talkers"); } catch { return; }
  const rows = data.talkers || [];
  const tb = document.querySelector("#nd-talkers tbody"); tb.innerHTML = "";
  $("nd-empty").style.display = rows.length ? "none" : "block";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td style="font-family:ui-monospace,monospace;font-size:12px">${esc(r.dst)}</td>
      <td>${esc(r.connections)}</td><td class="sub">${esc(r.bytes ? (Math.round(r.bytes/1024) + " KB") : "—")}</td>`;
    tb.appendChild(tr);
  }
}

// ============ SecOps: SIEM Search (NQL) ============
async function runSearch() {
  if (!connected) { toast(t("common.connectFirst") || "Connect first", "err"); return; }
  const idx = $("se-index").value, q = $("se-q").value.trim();
  let data;
  try { data = await api(`/search?index=${idx}&q=${encodeURIComponent(q)}&limit=200`); }
  catch (e) { toast(`${t("toast.failed")}: ${e.message}`, "err"); return; }
  const rows = data.results || [];
  $("se-meta").textContent = `${data.count ?? rows.length} ${t("card.events").toLowerCase()} · NQL: ${data.query || "—"}`;
  const tb = document.querySelector("#se-res tbody"); tb.innerHTML = "";
  $("se-empty").style.display = rows.length ? "none" : "block";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td style="white-space:nowrap">${esc(r.ts_iso)}</td>
      <td><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></td>
      <td>${esc(r.event_type || r.rule_id || r.type || "")}</td>
      <td>${esc(r.title)}</td><td class="sub">${esc((r.agent_id || "").slice(0, 14))}</td>`;
    tb.appendChild(tr);
  }
}
async function nlSearch() {
  const text = prompt(t("se.nl"));
  if (!text) return;
  try {
    const j = await api(`/ai/nl?q=${encodeURIComponent(text)}`);
    $("se-index").value = j.index || "events";
    $("se-q").value = j.nql || text;
    runSearch();
  } catch (e) { toast(`${t("toast.failed")}: ${e.message}`, "err"); }
}

// ============ SecOps: XDR incidents ============
async function loadXDR() {
  if (!connected) return;
  let data; try { data = await api("/xdr/incidents?limit=200"); } catch { return; }
  const incs = data.incidents || [];
  const tb = document.querySelector("#xdr-list tbody"); tb.innerHTML = "";
  $("xdr-empty").style.display = incs.length ? "none" : "block";
  for (const i of incs) {
    const tr = document.createElement("tr"); tr.style.cursor = "pointer";
    tr.innerHTML = `<td>${esc(i.name)}<br><span class="sub">${esc(i.rule_id)} · ${esc((i.mitre || []).join(", "))}</span></td>
      <td><span class="sev ${esc(i.severity)}">${esc(i.severity)}</span> <b>${esc(i.level)}</b></td>
      <td class="sub">${esc(i.entity)}</td><td>${esc(i.count)}</td>
      <td>${esc(i.status)}</td><td class="sub" style="white-space:nowrap">${esc(i.last_iso)}</td>`;
    tr.addEventListener("click", () => showIncidentDetail(i.id));
    tb.appendChild(tr);
  }
}
async function showIncidentDetail(id) {
  const box = $("xdr-detail");
  try {
    const j = await api(`/xdr/incident?id=${encodeURIComponent(id)}`);
    const inc = j.incident || {};
    const steps = (inc.timeline || []).map((s) =>
      `<div class="step">[${esc((s.ts_iso || "").slice(11, 16))}] <b>${esc(s.title)}</b> <span class="sub">${esc(s.rule_id)}</span></div>`).join("");
    box.innerHTML = `<h2>${esc(inc.name || "")}</h2>
      <p class="sub">${esc(inc.entity)} · MITRE ${esc((inc.mitre || []).join(", "))}</p>
      ${steps}<p class="sub" style="margin-top:8px">${esc(inc.recommendation || "")}</p>`;
    box.style.display = "block";
  } catch (e) { box.innerHTML = `<p class="sub">${esc(e.message)}</p>`; box.style.display = "block"; }
}

// ============ SecOps: AI Triage ============
async function loadAI() {
  if (!connected) return;
  try { const m = await api("/ai/model");
    $("ai-model").textContent = `${t("nav.ai")}: ${m.trained ? "trained" : "collecting"} · ${m.samples || 0} samples`; } catch {}
  let data; try { data = await api("/ai/triage?limit=100"); } catch { return; }
  const items = data.triage || [];
  const box = $("ai-cards"); box.innerHTML = "";
  $("ai-empty").style.display = items.length ? "none" : "block";
  for (const it of items) {
    const recs = ((it.recommendations || {}).actions || []).map((a) => `<li>${esc(a)}</li>`).join("");
    const d = document.createElement("div"); d.className = "tcard " + esc(it.priority);
    d.innerHTML = `<div class="tcard-head"><span class="pri ${esc(it.priority)}">${esc(it.priority)}</span>
      <b>${esc(it.entity)}</b><span class="tcard-meta">score ${esc(it.score)} · FP ${esc(it.fp_likelihood)}% · conf ${esc(it.confidence)}%</span></div>
      <div class="tcard-sum">${esc(it.summary)}</div>
      ${recs ? `<ul class="tcard-recs">${recs}</ul>` : ""}`;
    box.appendChild(d);
  }
}
async function runAITriage() {
  if (!connected) return;
  try { await post("/ai/triage", { status: "open" }); toast("OK", "ok"); loadAI(); }
  catch (e) { toast(`${t("toast.failed")}: ${e.message}`, "err"); }
}

// ============ SecOps: EDR process tree ============
async function loadEDR() {
  if (!connected) return;
  let data; try { data = await api("/edr/hosts"); } catch { return; }
  const sel = $("edr-host"); const prev = sel.value;
  sel.innerHTML = (data.hosts || []).map((h) => `<option value="${esc(h.agent_id)}">${esc(h.agent_id)} (${esc(h.processes)})</option>`).join("");
  if (prev) sel.value = prev;
  if (sel.value) loadEDRTree(sel.value);
  else { $("edr-tree").innerHTML = ""; $("edr-empty").style.display = "block"; }
}
function procNode(n) {
  const risk = n.risk ? ` <span class="risk-tag">${esc(n.risk)}</span>` : "";
  const kids = (n.children || []).length ? `<ul>${n.children.map(procNode).join("")}</ul>` : "";
  return `<li class="${n.risk ? "risk" : ""}"><span class="pname">${esc(n.name)}</span>
    <span class="ppid">#${esc(n.pid)}</span>${risk}
    ${n.cmdline ? `<div class="pcmd">${esc(String(n.cmdline).slice(0, 120))}</div>` : ""}${kids}</li>`;
}
async function loadEDRTree(agentId) {
  let data; try { data = await api(`/edr/tree?agent_id=${encodeURIComponent(agentId)}`); } catch { return; }
  const tree = data.tree || [];
  $("edr-empty").style.display = tree.length ? "none" : "block";
  $("edr-tree").innerHTML = tree.length ? `<ul>${tree.map(procNode).join("")}</ul>` : "";
}

// ============ SecOps: UEBA ============
async function loadUEBA() {
  if (!connected) return;
  let data; try { data = await api("/ueba/scores?limit=100"); } catch { return; }
  const rows = data.scores || [];
  const tb = document.querySelector("#ueba-list tbody"); tb.innerHTML = "";
  $("ueba-empty").style.display = rows.length ? "none" : "block";
  for (const r of rows) {
    const reasons = (r.reasons || []).map((x) => x.detail || x.signal).join("; ");
    const cls = r.band === "high" ? "critical" : r.band === "medium" ? "high" : "low";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="sub">${esc(r.entity)}</td><td><b class="sev ${cls}">${esc(r.score)}</b></td>
      <td><span class="sev ${cls}">${esc(r.band)}</span></td>
      <td style="font-size:11px">${esc(reasons)}</td>
      <td class="sub" style="white-space:nowrap">${esc(r.ts_iso)}</td>`;
    tb.appendChild(tr);
  }
}

// ============ SecOps: Threat Intel ============
async function loadIntel() {
  if (!connected) return;
  try {
    const s = await api("/ti/stats"); const bt = s.by_type || {};
    $("ti-stats").innerHTML = `<div class="stat"><div class="stat-num">${s.total_iocs ?? 0}</div><div class="stat-lbl">IOCs</div></div>
      <div class="stat"><div class="stat-num crit">${s.total_matches ?? 0}</div><div class="stat-lbl">Matches</div></div>
      <div class="stat"><div class="stat-num">${bt.ip || 0}</div><div class="stat-lbl">IP</div></div>
      <div class="stat"><div class="stat-num">${(bt.domain || 0) + (bt.url || 0)}</div><div class="stat-lbl">Domain/URL</div></div>`;
  } catch {}
  let data; try { data = await api("/ti/iocs?limit=300"); } catch { return; }
  const rows = data.iocs || [];
  const tb = document.querySelector("#ti-list tbody"); tb.innerHTML = "";
  $("ti-empty").style.display = rows.length ? "none" : "block";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="sub">${esc(r.type)}</td><td style="font-family:ui-monospace,monospace;font-size:12px">${esc(r.value)}</td>
      <td>${esc(r.threat)}</td><td><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></td>
      <td class="sub">${esc(r.source)}</td>`;
    tb.appendChild(tr);
  }
}

// ============ SecOps: Cloud ============
async function loadCloud() {
  if (!connected) return;
  try {
    const p = await api("/cloud/posture"); const bp = p.by_provider || {};
    const prov = Object.entries(bp).map(([k, v]) => `<div class="stat"><div class="stat-num">${v}</div><div class="stat-lbl">${esc(k)}</div></div>`).join("");
    $("cl-posture").innerHTML = `<div class="stat"><div class="stat-num ${p.overall < 50 ? "crit" : ""}">${p.overall ?? 100}</div><div class="stat-lbl">Posture</div></div>
      <div class="stat"><div class="stat-num crit">${p.open_findings ?? 0}</div><div class="stat-lbl">Open findings</div></div>${prov}`;
  } catch {}
  let data; try { data = await api("/cloud/findings?limit=300"); } catch { return; }
  const rows = data.findings || [];
  const tb = document.querySelector("#cl-list tbody"); tb.innerHTML = "";
  $("cl-empty").style.display = rows.length ? "none" : "block";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(r.title)}<br><span class="sub">${esc(r.check_id)} · ${esc(r.compliance)}</span></td>
      <td><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></td>
      <td class="sub">${esc(r.resource)}</td><td class="sub">${esc(r.provider)}</td>
      <td style="font-size:11px">${esc(r.remediation)}</td>`;
    tb.appendChild(tr);
  }
}

// ============ SecOps: SOAR ============
async function loadSOAR() {
  if (!connected) return;
  try {
    const pb = (await api("/soar/playbooks")).playbooks || [];
    const tb = document.querySelector("#so-pb tbody"); tb.innerHTML = "";
    for (const p of pb) {
      const trig = (p.trigger || {}); const cond = JSON.stringify(trig.conditions || {});
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${esc(p.name)}<br><span class="sub">${esc(p.id)}</span></td>
        <td class="sub">${esc(trig.on || "")} ${esc(cond)}</td>
        <td><span class="pill ${esc(p.mode)}">${esc(p.mode)}</span></td>
        <td><span class="pill ${p.enabled ? "on" : "off"}">${p.enabled ? "on" : "off"}</span></td>`;
      tb.appendChild(tr);
    }
  } catch { return; }
  try {
    const runs = (await api("/soar/runs?limit=100")).runs || [];
    const tb = document.querySelector("#so-runs tbody"); tb.innerHTML = "";
    $("so-empty").style.display = runs.length ? "none" : "block";
    for (const r of runs) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="sub" style="white-space:nowrap">${esc(r.ts_iso)}</td>
        <td>${esc(r.playbook_name)}</td><td class="sub">${esc(r.entity)}</td>
        <td><span class="pill ${r.status === "executed" ? "on" : r.status === "dry_run" ? "dry_run" : ""}">${esc(r.status)}</span></td>`;
      tb.appendChild(tr);
    }
  } catch {}
}

// ============ Refresh loop ============
async function refresh() {
  try {
    const st = await api("/stats");
    $("s-agents").textContent = st.agents_total ?? 0;
    $("s-online").textContent = st.agents_online ?? 0;
    $("s-events").textContent = st.events_total ?? 0;
    $("s-open").textContent = st.alerts_open ?? 0;
    $("s-risk").textContent = st.risk_score ?? 0;
    const badge = $("nav-alerts-badge");
    badge.textContent = st.alerts_open ?? 0;
    badge.classList.toggle("show", (st.alerts_open ?? 0) > 0);
    setConn(true);
  } catch (e) { setConn(false); return; }

  try { renderAlerts((await api("/alerts?limit=200" + ($("astatus").value ? "&status=" + $("astatus").value : ""))).alerts || []); } catch {}
  try { renderAgents((await api("/agents")).agents || []); } catch {}
  try { renderEvents((await api("/events?limit=200")).events || []); } catch {}
  try { renderSeats(await api("/license")); } catch {}
  if (curView === "license") loadLicense();
  if (curView === "incidents") loadIncidents();
}

// ============ Overview: seats + recent ============
function tierClass(t) { return (t || "free").toLowerCase(); }
function renderSeats(lic) {
  const used = parseInt($("s-agents").textContent || "0", 10);
  const max = lic.max_agents;
  const tier = (lic.tier || "free").toUpperCase();
  $("side-tier").textContent = tier; $("side-tier").className = "lic-pill " + tierClass(lic.tier);
  $("seat-tier").textContent = tier; $("seat-tier").className = "lic-pill " + tierClass(lic.tier);
  const fill = $("seatbar-fill");
  if (max == null) {
    $("seat-text").textContent = `${used} / ∞`;
    fill.style.width = "12%"; fill.className = "seatbar-fill";
  } else {
    const pct = max ? Math.min(100, Math.round((used / max) * 100)) : 0;
    $("seat-text").textContent = `${used} / ${max}`;
    fill.style.width = pct + "%";
    fill.className = "seatbar-fill" + (pct >= 100 ? " full" : pct >= 80 ? " warn" : "");
  }
}

function renderAlerts(alerts) {
  const tb = document.querySelector("#alerts tbody");
  tb.innerHTML = "";
  $("alerts-empty").style.display = alerts.length ? "none" : "block";
  for (const a of alerts) {
    const mitre = (a.mitre || []).join(", ");
    const next = a.status === "open" ? "ack" : a.status === "ack" ? "resolved" : "open";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="white-space:nowrap">${esc(a.ts_iso)}</td>
      <td><b>${esc(a.level)}</b></td>
      <td><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td class="sub">${esc(a.rule_id)}</td>
      <td>${esc(a.title)}<br><span class="sub">${esc(a.recommendation || "")}</span></td>
      <td style="color:var(--low)">${esc(mitre)}</td>
      <td class="sub">${esc((a.agent_id || "").slice(0, 12))}</td>
      <td>
        <button class="act" data-id="${esc(a.id)}" data-next="${next}">${esc(a.status)} → ${next}</button><br>
        <button class="act fix" data-rid="${esc(a.rule_id || "")}" data-agent="${esc(a.agent_id || "")}"
          data-proc="${esc((a.target && a.target.process) || "")}">${esc(t("alerts.secure"))}</button>
      </td>`;
    tb.appendChild(tr);
  }
  tb.querySelectorAll(".act:not(.fix)").forEach((b) =>
    b.addEventListener("click", () => ackAlert(b.dataset.id, b.dataset.next)));
  tb.querySelectorAll(".act.fix").forEach((b) =>
    b.addEventListener("click", () => remediate(b.dataset.rid, b.dataset.agent, b.dataset.proc)));
  // recent (overview): first 6
  const rb = document.querySelector("#recent-alerts tbody");
  rb.innerHTML = "";
  $("recent-empty").style.display = alerts.length ? "none" : "block";
  for (const a of alerts.slice(0, 6)) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td>${esc(a.title)}</td><td class="sub" style="white-space:nowrap">${esc(a.ts_iso)}</td>`;
    rb.appendChild(tr);
  }
}

function suggestedAction(ruleId, proc) {
  if (ruleId === "NEXUS-FW-001") return { action: "enable_firewall" };
  if (ruleId === "NEXUS-PROC-001") return { action: "kill_process", process: proc };
  if (ruleId === "NEXUS-SCA-001") return { action: "disable_guest" };
  if (ruleId.startsWith("NEXUS-AUTH") || ruleId === "NEXUS-LOG-005" || ruleId === "NEXUS-LOG-001")
    return { action: "block_ip" };
  return { action: "harden" };
}
async function remediate(ruleId, agentId, proc) {
  const sug = suggestedAction(ruleId, proc);
  if (sug.action === "block_ip") {
    const ip = prompt("Block which IP? (empty = cancel)");
    if (!ip) return; sug.ip = ip;
  }
  if (!confirm(`Send "${sug.action}" remediation to the agent?\n(Dry-run by default — real execution only if policy.active_response is on.)`)) return;
  try {
    const j = await post("/response/actions", { agent_id: agentId, ...sug });
    toast(j.ok ? `"${sug.action}" → ${t("toast.queued")}` : `${t("toast.failed")}: ${j.error || ""}`, j.ok ? "ok" : "err");
  } catch (e) { toast(`${t("toast.failed")}: ${e.message}`, "err"); }
}
async function ackAlert(id, status) {
  try { await post("/alerts/ack", { id, status }); refresh(); }
  catch (e) { toast(`${t("toast.failed")}: ${e.message}`, "err"); }
}

function renderAgents(agents) {
  const tb = document.querySelector("#agents tbody");
  tb.innerHTML = "";
  $("agents-empty").style.display = agents.length ? "none" : "block";
  for (const a of agents) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(a.name || a.hostname)}<br><span class="sub">${esc(a.agent_id)}</span></td>
      <td>${esc(a.hostname)}<br><span class="sub">${esc(a.os)} ${esc(a.os_release || "")}</span></td>
      <td>${esc(a.ip || "—")}</td>
      <td class="st ${esc(a.status)}">● ${esc(a.status)}</td>
      <td>${esc(a.last_seen_iso)}</td>
      <td>
        <button class="act" data-scan="${esc(a.agent_id)}">${esc(t("agents.scan"))}</button>
        <button class="act danger" data-remove="${esc(a.agent_id)}">${esc(t("agents.remove"))}</button>
      </td>`;
    tb.appendChild(tr);
  }
  tb.querySelectorAll("[data-scan]").forEach((b) => b.addEventListener("click", () => sendCommand(b.dataset.scan)));
  tb.querySelectorAll("[data-remove]").forEach((b) => b.addEventListener("click", () => removeAgent(b.dataset.remove)));
}
async function sendCommand(agentId) {
  try { await post("/command", { agent_id: agentId, command: "collect_now", args: {} });
    toast(`collect_now → ${t("toast.queued")} (${agentId.slice(0, 10)})`, "ok"); }
  catch (e) { toast(`${t("toast.failed")}: ${e.message}`, "err"); }
}
async function removeAgent(agentId) {
  if (!confirm(t("agents.confirmRemove"))) return;
  try { await post("/agents/remove", { agent_id: agentId }); toast("OK", "ok"); refresh(); }
  catch (e) { toast(`${t("toast.failed")}: ${e.message}`, "err"); }
}

function renderEvents(events) {
  const filter = $("sev").value;
  const rows = filter ? events.filter((e) => e.severity === filter) : events;
  const tb = document.querySelector("#events tbody");
  tb.innerHTML = "";
  $("events-empty").style.display = rows.length ? "none" : "block";
  for (const e of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="white-space:nowrap">${esc(e.ts_iso)}</td>
      <td><span class="sev ${esc(e.severity)}">${esc(e.severity)}</span></td>
      <td>${esc(e.type)}</td><td>${esc(e.title)}</td>
      <td class="sub">${esc((e.agent_id || "").slice(0, 12))}</td>`;
    tb.appendChild(tr);
  }
}

// ============ Incidents ============
async function loadIncidents() {
  if (!connected) return;
  let data;
  try { data = await api("/incidents?status=open"); } catch { return; }
  const incs = data.incidents || [];
  const tb = document.querySelector("#incidents tbody");
  tb.innerHTML = "";
  $("incidents-empty").style.display = incs.length ? "none" : "block";
  for (const i of incs) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(i.title || i.key || i.rule_id || "—")}<br><span class="sub">${esc(i.key || "")}</span></td>
      <td>${esc(i.count ?? (i.alerts ? i.alerts.length : ""))}</td>
      <td><span class="sev ${esc(i.severity || i.max_severity || "info")}">${esc(i.severity || i.max_severity || "info")}</span></td>
      <td class="sub">${esc((i.agents || []).join(", ") || (i.agent_id || "").slice(0, 12))}</td>
      <td class="sub" style="white-space:nowrap">${esc(i.last_iso || i.ts_iso || "")}</td>`;
    tb.appendChild(tr);
  }
}

// ============ Policy ============
async function loadPolicy() {
  if (!connected) { $("policy-json").value = t("common.connectFirst"); return; }
  try { const p = await api("/policy"); $("policy-json").value = JSON.stringify(p.policy || p, null, 2); }
  catch (e) { $("policy-json").value = `// ${e.message}`; }
}
async function savePolicy() {
  let pol;
  try { pol = JSON.parse($("policy-json").value); }
  catch (e) { setMsg("policy-msg", t("pol.invalid") + e.message, "err"); return; }
  try { await post("/policy", { policy: pol }); setMsg("policy-msg", t("pol.saved"), "ok"); }
  catch (e) { setMsg("policy-msg", `${t("toast.failed")}: ${e.message}`, "err"); }
}
function setMsg(id, text, kind) { const el = $(id); el.textContent = text; el.className = "msg " + (kind || ""); }

// ============ License ============
async function loadLicense() {
  if (!connected) return;
  let lic;
  try { lic = await api("/license"); } catch { return; }
  renderSeats(lic);
  const tier = (lic.tier || "free").toUpperCase();
  $("lic-tier").textContent = tier; $("lic-tier").className = "lic-pill " + tierClass(lic.tier);
  $("lic-valid").textContent = lic.valid ? t("lic.valid") : t("lic.invalid");
  $("lic-valid").style.color = lic.valid ? "var(--ok)" : "var(--subtle)";
  $("lic-licensee").textContent = lic.licensee || "—";
  $("lic-seats").textContent = lic.max_agents == null ? t("lic.unlimited") : lic.max_agents;
  $("lic-expires").textContent = lic.expires_iso || (lic.expires ? lic.expires : t("common.never"));
  const fb = $("lic-features"); fb.innerHTML = "";
  for (const f of (lic.features || [])) { const s = document.createElement("span"); s.className = "chip"; s.textContent = f; fb.appendChild(s); }
  $("lic-note").textContent = (!lic.valid || lic.tier === "free") ? t("lic.free.note", { n: lic.max_agents ?? 2 }) : "";
}

// ============ Connect / theme / lang ============
function connect() {
  if (timer) clearInterval(timer);
  localStorage.setItem("nx_host", $("host").value);
  localStorage.setItem("nx_port", $("port").value);
  sessionStorage.setItem("nx_token", $("token").value);  // token: sessionStorage (kurangi paparan XSS)
  refresh();
  timer = setInterval(refresh, 4000);
}
function toggleTheme() {
  const root = document.documentElement;
  const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
  root.setAttribute("data-theme", next);
  localStorage.setItem("nx_theme", next);
  $("theme-toggle").querySelector("[data-icon]").innerHTML = icon(next === "dark" ? "moon" : "sun");
}
function toggleLang() {
  setLang(LANG === "id" ? "en" : "id");
  $("lang-label").textContent = LANG.toUpperCase();
}
window.onLangChange = () => { setConn(connected); if (curView === "help") renderHelp(); };

window.addEventListener("DOMContentLoaded", () => {
  // tema & bahasa
  const theme = localStorage.getItem("nx_theme") || "dark";
  document.documentElement.setAttribute("data-theme", theme);
  hydrateIcons();
  applyI18n();
  $("lang-label").textContent = LANG.toUpperCase();
  $("theme-toggle").querySelector("[data-icon]").innerHTML = icon(theme === "dark" ? "moon" : "sun");
  setConn(false);

  // restore koneksi
  $("host").value = localStorage.getItem("nx_host") || $("host").value;
  $("port").value = localStorage.getItem("nx_port") || $("port").value;
  $("token").value = sessionStorage.getItem("nx_token") || "";

  // nav
  document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
  showView(localStorage.getItem("nx_view") || "overview");

  // controls
  $("connect").addEventListener("click", connect);
  $("refresh-all").addEventListener("click", refresh);
  $("theme-toggle").addEventListener("click", toggleTheme);
  $("lang-toggle").addEventListener("click", toggleLang);
  $("sev").addEventListener("change", () => refresh());
  $("astatus").addEventListener("change", () => refresh());
  $("policy-save").addEventListener("click", savePolicy);
  // SecOps controls
  $("se-go").addEventListener("click", runSearch);
  $("se-q").addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });
  $("se-nl").addEventListener("click", nlSearch);
  $("ai-run").addEventListener("click", runAITriage);
  $("edr-host").addEventListener("change", (e) => loadEDRTree(e.target.value));
  $("edr-reload").addEventListener("click", loadEDR);

  if ($("token").value) connect();
});

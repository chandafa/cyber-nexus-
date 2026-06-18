// nexus-dashboard — UI monitoring fleet (vanilla JS, query REST API manager).
const $ = (id) => document.getElementById(id);
let timer = null;

function base() {
  return `http://${$("host").value.trim()}:${$("port").value.trim()}/api/v1`;
}
function headers() {
  return { "X-Admin-Token": $("token").value.trim() };
}

async function api(path) {
  const r = await fetch(base() + path, { headers: headers() });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function setOnline(ok) {
  $("dot").className = "dot " + (ok ? "on" : "off");
}

async function refresh() {
  try {
    const st = await api("/stats");
    $("s-agents").textContent = st.agents_total ?? 0;
    $("s-online").textContent = st.agents_online ?? 0;
    $("s-events").textContent = st.events_total ?? 0;
    $("s-open").textContent = st.alerts_open ?? 0;
    $("s-risk").textContent = st.risk_score ?? 0;
    setOnline(true);
  } catch (e) {
    setOnline(false);
    return;
  }
  try {
    const al = await api("/alerts?limit=200" + ($("astatus").value ? "&status=" + $("astatus").value : ""));
    renderAlerts(al.alerts || []);
  } catch {}
  try {
    const a = await api("/agents");
    renderAgents(a.agents || []);
  } catch {}
  try {
    const ev = await api("/events?limit=200");
    renderEvents(ev.events || []);
  } catch {}
}

function renderAlerts(alerts) {
  const tb = document.querySelector("#alerts tbody");
  tb.innerHTML = "";
  $("alerts-empty").style.display = alerts.length ? "none" : "block";
  for (const a of alerts) {
    const tr = document.createElement("tr");
    const mitre = (a.mitre || []).join(", ");
    const next = a.status === "open" ? "ack" : a.status === "ack" ? "resolved" : "open";
    tr.innerHTML = `
      <td style="white-space:nowrap">${esc(a.ts_iso)}</td>
      <td><b>${a.level}</b></td>
      <td><span class="sev ${a.severity}">${a.severity}</span></td>
      <td style="color:var(--subtle)">${esc(a.rule_id)}</td>
      <td>${esc(a.title)}<br><span style="color:var(--subtle);font-size:10px">${esc(a.recommendation || "")}</span></td>
      <td style="color:var(--low)">${esc(mitre)}</td>
      <td style="color:var(--subtle)">${esc((a.agent_id || "").slice(0, 12))}</td>
      <td>
        <button class="act" data-id="${esc(a.id)}" data-next="${next}">${esc(a.status)} → ${next}</button>
        <button class="act fix" data-rid="${esc(a.rule_id || "")}" data-agent="${esc(a.agent_id || "")}"
          data-proc="${esc((a.target && a.target.process) || "")}" title="Auto-remediation (dry-run default)">🛡 Amankan</button>
      </td>`;
    tb.appendChild(tr);
  }
  tb.querySelectorAll(".act:not(.fix)").forEach((b) =>
    b.addEventListener("click", () => ackAlert(b.dataset.id, b.dataset.next)));
  tb.querySelectorAll(".act.fix").forEach((b) =>
    b.addEventListener("click", () => remediate(b.dataset.rid, b.dataset.agent, b.dataset.proc)));
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
    const ip = prompt("Blokir IP mana? (kosongkan untuk batal)");
    if (!ip) return;
    sug.ip = ip;
  }
  if (!confirm(`Kirim remediasi "${sug.action}" ke agent?\n` +
      `(Default DRY-RUN — eksekusi nyata hanya jika policy.active_response aktif.)`)) return;
  try {
    const r = await fetch(base() + "/response/actions", {
      method: "POST",
      headers: { ...headers(), "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: agentId, ...sug }),
    });
    const j = await r.json();
    alert(j.ok ? `Remediasi "${sug.action}" diantri ke agent.` : `Gagal: ${j.error || r.status}`);
  } catch (e) {
    alert("Gagal: " + e.message);
  }
}

async function ackAlert(id, status) {
  try {
    const r = await fetch(base() + "/alerts/ack", {
      method: "POST",
      headers: { ...headers(), "Content-Type": "application/json" },
      body: JSON.stringify({ id, status }),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    refresh();
  } catch (e) {
    alert("Gagal: " + e.message);
  }
}

function renderAgents(agents) {
  const tb = document.querySelector("#agents tbody");
  tb.innerHTML = "";
  $("agents-empty").style.display = agents.length ? "none" : "block";
  for (const a of agents) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(a.name || a.hostname)}<br><span style="color:var(--subtle);font-size:10px">${esc(a.agent_id)}</span></td>
      <td>${esc(a.hostname)}<br><span style="color:var(--subtle);font-size:10px">${esc(a.os)} ${esc(a.os_release || "")}</span></td>
      <td>${esc(a.ip || "—")}</td>
      <td class="status ${a.status}">● ${a.status}</td>
      <td>${esc(a.last_seen_iso)}</td>
      <td><button class="act" data-id="${esc(a.agent_id)}">scan now</button></td>`;
    tb.appendChild(tr);
  }
  tb.querySelectorAll(".act").forEach((b) =>
    b.addEventListener("click", () => sendCommand(b.dataset.id)));
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
      <td><span class="sev ${e.severity}">${e.severity}</span></td>
      <td>${esc(e.type)}</td>
      <td>${esc(e.title)}</td>
      <td style="color:var(--subtle)">${esc((e.agent_id || "").slice(0, 12))}</td>`;
    tb.appendChild(tr);
  }
}

async function sendCommand(agentId) {
  try {
    const r = await fetch(base() + "/command", {
      method: "POST",
      headers: { ...headers(), "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: agentId, command: "collect_now", args: {} }),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    alert("Perintah collect_now diantri untuk " + agentId);
  } catch (e) {
    alert("Gagal: " + e.message);
  }
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function connect() {
  if (timer) clearInterval(timer);
  // persist
  localStorage.setItem("nx_host", $("host").value);
  localStorage.setItem("nx_port", $("port").value);
  // Admin token disimpan di sessionStorage (terhapus saat tab ditutup) — kurangi
  // paparan bila ada XSS, dan tak persist seperti localStorage.
  sessionStorage.setItem("nx_token", $("token").value);
  refresh();
  timer = setInterval(refresh, 4000);
}

window.addEventListener("DOMContentLoaded", () => {
  $("host").value = localStorage.getItem("nx_host") || $("host").value;
  $("port").value = localStorage.getItem("nx_port") || $("port").value;
  $("token").value = sessionStorage.getItem("nx_token") || "";
  $("connect").addEventListener("click", connect);
  $("refresh").addEventListener("click", refresh);
  $("sev").addEventListener("change", refresh);
  $("arefresh").addEventListener("click", refresh);
  $("astatus").addEventListener("change", refresh);
  if ($("token").value) connect();
});

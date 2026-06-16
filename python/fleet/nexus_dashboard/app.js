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
      <td><button class="act" data-id="${esc(a.id)}" data-next="${next}">${esc(a.status)} → ${next}</button></td>`;
    tb.appendChild(tr);
  }
  tb.querySelectorAll(".act").forEach((b) =>
    b.addEventListener("click", () => ackAlert(b.dataset.id, b.dataset.next)));
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
  localStorage.setItem("nx_token", $("token").value);
  refresh();
  timer = setInterval(refresh, 4000);
}

window.addEventListener("DOMContentLoaded", () => {
  $("host").value = localStorage.getItem("nx_host") || $("host").value;
  $("port").value = localStorage.getItem("nx_port") || $("port").value;
  $("token").value = localStorage.getItem("nx_token") || "";
  $("connect").addEventListener("click", connect);
  $("refresh").addEventListener("click", refresh);
  $("sev").addEventListener("change", refresh);
  $("arefresh").addEventListener("click", refresh);
  $("astatus").addEventListener("change", refresh);
  if ($("token").value) connect();
});

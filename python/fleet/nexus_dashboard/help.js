// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// help.js — isi panduan in-app (dwibahasa). Dirender ke tab Bantuan.
const HELP = {
  id: `
<h2>Apa itu Nexus Fleet?</h2>
<p>Fleet adalah sistem pemantauan endpoint ala-Wazuh: <b>Agent</b> ringan berjalan di
tiap komputer dan mengirim telemetri ke <b>Manager</b> pusat. Dashboard ini membaca
Manager (REST API) untuk menampilkan agent, kejadian, dan peringatan secara real-time.</p>

<h2>Langkah cepat</h2>
<ol>
  <li><b>Jalankan Manager</b> di server pusat:
    <pre>nexus manager run --host 0.0.0.0 --port 8765</pre></li>
  <li><b>Lihat kunci enrollment &amp; admin token</b>:
    <pre>nexus manager info</pre></li>
  <li><b>Hubungkan dashboard ini</b>: isi host, port, dan admin token di bilah atas, lalu
    klik <b>Hubungkan</b>. Titik status berubah hijau bila tersambung.</li>
  <li><b>Daftarkan endpoint</b> di tiap komputer:
    <pre>nexus agent enroll --host MANAGER_IP --port 8765 --key ENROLLMENT_KEY
nexus agent start</pre></li>
</ol>

<h2>Tiap tab</h2>
<ul>
  <li><b>Ringkasan</b> — kartu metrik + pemakaian seat lisensi + peringatan terbaru.</li>
  <li><b>Agent</b> — daftar endpoint; "Scan" memerintahkan pengumpulan telemetri, "Hapus" membebaskan seat.</li>
  <li><b>Peringatan</b> — temuan rule engine (MITRE ATT&amp;CK). Klik status untuk ack/resolve; "Amankan" mengirim remediasi (default uji-coba/dry-run).</li>
  <li><b>Kejadian</b> — telemetri mentah (port mendengarkan, login gagal, perubahan berkas, dll).</li>
  <li><b>Insiden</b> — peringatan terkait yang dikelompokkan.</li>
  <li><b>Kebijakan</b> — JSON yang dikirim ke semua agent (interval, kolektor, active-response).</li>
  <li><b>Lisensi</b> — tier &amp; pemakaian seat. FREE dibatasi 2 agent; <b>PRO berbasis seat</b> (mis. 50); ENTERPRISE tak terbatas.</li>
</ul>

<h2>Tier &amp; seat</h2>
<p>Satu lisensi membuka GUI desktop, CLI, dan Fleet di perangkat yang sama. Jumlah agent
yang boleh mendaftar mengikuti <b>seat</b> pada tier Anda. Bila menyentuh batas,
enrollment ditolak — bebaskan seat (Hapus agent) atau tingkatkan lisensi.</p>

<h2>Privasi</h2>
<p>Semua data tetap di LAN Anda. Dashboard hanya berbicara ke Manager yang Anda tentukan.
Admin token disimpan di sessionStorage (terhapus saat tab ditutup).</p>
`,
  en: `
<h2>What is Nexus Fleet?</h2>
<p>Fleet is a Wazuh-style endpoint monitoring system: a lightweight <b>Agent</b> runs on
each computer and ships telemetry to a central <b>Manager</b>. This dashboard reads the
Manager (REST API) to show agents, events, and alerts in real time.</p>

<h2>Quick start</h2>
<ol>
  <li><b>Run the Manager</b> on a central host:
    <pre>nexus manager run --host 0.0.0.0 --port 8765</pre></li>
  <li><b>Show the enrollment key &amp; admin token</b>:
    <pre>nexus manager info</pre></li>
  <li><b>Connect this dashboard</b>: fill host, port, and admin token in the top bar, then
    click <b>Connect</b>. The status dot turns green when linked.</li>
  <li><b>Enroll an endpoint</b> on each machine:
    <pre>nexus agent enroll --host MANAGER_IP --port 8765 --key ENROLLMENT_KEY
nexus agent start</pre></li>
</ol>

<h2>Each tab</h2>
<ul>
  <li><b>Overview</b> — metric cards + license seat usage + recent alerts.</li>
  <li><b>Agents</b> — endpoint list; "Scan" triggers collection, "Remove" frees a seat.</li>
  <li><b>Alerts</b> — rule-engine findings (MITRE ATT&amp;CK). Click the status to ack/resolve; "Secure" sends remediation (dry-run by default).</li>
  <li><b>Events</b> — raw telemetry (listening ports, failed logins, file changes, etc).</li>
  <li><b>Incidents</b> — related alerts grouped together.</li>
  <li><b>Policy</b> — the JSON pushed to every agent (intervals, collectors, active-response).</li>
  <li><b>License</b> — tier &amp; seat usage. FREE is limited to 2 agents; <b>PRO is seat-based</b> (e.g. 50); ENTERPRISE is unlimited.</li>
</ul>

<h2>Tiers &amp; seats</h2>
<p>One license unlocks the desktop GUI, the CLI, and Fleet on the same device. The number of
agents that may enroll follows the <b>seats</b> on your tier. When you hit the limit,
enrollment is refused — free a seat (Remove an agent) or upgrade your license.</p>

<h2>Privacy</h2>
<p>All data stays on your LAN. The dashboard only talks to the Manager you point it at.
The admin token is kept in sessionStorage (cleared when the tab closes).</p>
`,
};

function renderHelp() {
  const el = document.getElementById("help-body");
  if (el) el.innerHTML = HELP[LANG] || HELP.en;
}

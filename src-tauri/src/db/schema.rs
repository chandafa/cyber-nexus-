// src-tauri/src/db/schema.rs
//! Skema SQLite lengkap — SDD bagian 7.
pub const SCHEMA_SQL: &str = r#"
-- Tabel sessions scan
CREATE TABLE IF NOT EXISTS scan_sessions (
    id          TEXT PRIMARY KEY,
    module      TEXT NOT NULL,
    target      TEXT,
    mode        TEXT,
    status      TEXT DEFAULT 'running',
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    raw_output  TEXT,
    notes       TEXT
);

-- Hasil port scan
CREATE TABLE IF NOT EXISTS port_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT REFERENCES scan_sessions(id),
    target_ip   TEXT NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    port        INTEGER NOT NULL,
    protocol    TEXT,
    state       TEXT,
    service     TEXT,
    version     TEXT,
    extra_info  TEXT
);

-- Hasil vulnerability scan
CREATE TABLE IF NOT EXISTS vuln_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT REFERENCES scan_sessions(id),
    tool        TEXT NOT NULL,
    severity    TEXT,
    vuln_id     TEXT,
    title       TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    remediation TEXT
);

-- Log anomali yang terdeteksi
CREATE TABLE IF NOT EXISTS anomaly_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT REFERENCES scan_sessions(id),
    timestamp   TEXT,
    source_ip   TEXT,
    attack_type TEXT,
    severity    TEXT,
    detail      TEXT,
    raw_line    TEXT
);

-- Pengaturan aplikasi
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings VALUES
    ('theme', 'dark'),
    ('terminal_font_size', '13'),
    ('default_wordlist', 'wordlists/rockyou.txt'),
    ('nmap_default_mode', 'standard'),
    ('max_hydra_threads', '16'),
    ('auto_save_pcap', 'false'),
    ('onboarding_complete', 'false'),
    ('essential_ports', '22,80,443'),
    ('attack_simulation_enabled', 'false'),
    ('ids_auto_start', 'false'),
    ('report_output_dir', './reports');

-- ===================== Tabel SDD v2 =====================

-- Target authorized untuk Attack Simulation (Scope Guard)
CREATE TABLE IF NOT EXISTS authorized_targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr_or_host TEXT NOT NULL UNIQUE,
    label        TEXT,
    active       INTEGER DEFAULT 1,
    added_at     TEXT NOT NULL
);

-- Asset Inventory
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL,
    mac_address TEXT,
    hostname    TEXT,
    os_guess    TEXT,
    open_ports  TEXT,
    device_type TEXT,
    custom_label TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(ip_address, mac_address)
);

-- TLS/SSL audit findings
CREATE TABLE IF NOT EXISTS tls_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT REFERENCES scan_sessions(id),
    category    TEXT,
    name        TEXT NOT NULL,
    status      TEXT,
    detail      TEXT
);

-- Exploit lookup referensi
CREATE TABLE IF NOT EXISTS exploit_refs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT REFERENCES scan_sessions(id),
    matched_service TEXT,
    title           TEXT,
    exploit_type    TEXT,
    edb_id          TEXT,
    path            TEXT
);

-- Security Score history
CREATE TABLE IF NOT EXISTS security_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT REFERENCES scan_sessions(id),
    target          TEXT,
    overall_score   REAL,
    grade           TEXT,
    network_exposure_score REAL,
    vulnerability_score    REAL,
    ssl_tls_score          REAL,
    password_policy_score  REAL,
    hardening_score        REAL,
    calculated_at   TEXT NOT NULL
);

-- Firewall rule suggestions
CREATE TABLE IF NOT EXISTS firewall_suggestions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT REFERENCES scan_sessions(id),
    port        INTEGER,
    protocol    TEXT,
    service     TEXT,
    action      TEXT,
    command     TEXT,
    reasoning   TEXT,
    status      TEXT DEFAULT 'pending'
);

-- Patch advisory list
CREATE TABLE IF NOT EXISTS patch_advisories (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT REFERENCES scan_sessions(id),
    component       TEXT,
    current_version TEXT,
    recommended_version TEXT,
    max_severity    TEXT,
    issues          TEXT,
    status          TEXT DEFAULT 'open'
);

-- IDS alerts (Suricata)
CREATE TABLE IF NOT EXISTS ids_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    signature   TEXT,
    severity    INTEGER,
    src_ip      TEXT,
    dest_ip     TEXT,
    detected_at TEXT NOT NULL
);

-- Scheduled scans
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    module      TEXT NOT NULL,
    mode        TEXT,
    cron_expr   TEXT NOT NULL,
    enabled     INTEGER DEFAULT 1,
    last_run    TEXT,
    next_run    TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_module ON scan_sessions(module);
CREATE INDEX IF NOT EXISTS idx_port_results_session ON port_results(session_id);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vuln_results(severity);
CREATE INDEX IF NOT EXISTS idx_anomaly_session ON anomaly_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_tls_findings_session ON tls_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_security_scores_target ON security_scores(target);
CREATE INDEX IF NOT EXISTS idx_firewall_status ON firewall_suggestions(status);
CREATE INDEX IF NOT EXISTS idx_patch_status ON patch_advisories(status);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_time ON ids_alerts(detected_at);
"#;

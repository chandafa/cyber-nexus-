// src-tauri/src/models/scan_result.rs
//! Struktur data hasil scan yang dipertukarkan antara Rust, frontend, dan DB.
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanOutput {
    pub line: String,
    pub scan_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanComplete {
    pub scan_id: String,
    pub exit_code: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanSession {
    pub id: String,
    pub module: String,
    pub target: Option<String>,
    pub mode: Option<String>,
    pub status: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub raw_output: Option<String>,
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PortResultRow {
    pub session_id: String,
    pub target_ip: String,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub port: i64,
    pub protocol: Option<String>,
    pub state: Option<String>,
    pub service: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VulnResultRow {
    pub session_id: String,
    pub tool: String,
    pub severity: Option<String>,
    pub vuln_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnomalyRow {
    pub session_id: String,
    pub timestamp: Option<String>,
    pub source_ip: Option<String>,
    pub attack_type: Option<String>,
    pub severity: Option<String>,
    pub detail: Option<String>,
    pub raw_line: Option<String>,
}

// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

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

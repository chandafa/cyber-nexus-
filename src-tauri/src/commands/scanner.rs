// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src-tauri/src/commands/scanner.rs
//! Tauri commands untuk database (sessions, results, settings) — SDD bagian 7.
use serde_json::Value;
use tauri::State;

use crate::db::Db;
use crate::models::scan_result::ScanSession;

#[tauri::command]
pub fn list_sessions(db: State<'_, Db>, limit: Option<i64>) -> Result<Vec<ScanSession>, String> {
    db.list_sessions(limit.unwrap_or(100))
}

#[tauri::command]
pub fn get_session(db: State<'_, Db>, session_id: String) -> Result<Value, String> {
    db.get_session_full(&session_id)
}

#[tauri::command]
pub fn delete_session(db: State<'_, Db>, session_id: String) -> Result<(), String> {
    db.delete_session(&session_id)
}

#[tauri::command]
pub fn get_settings(db: State<'_, Db>) -> Result<Value, String> {
    db.get_settings()
}

#[tauri::command]
pub fn set_setting(db: State<'_, Db>, key: String, value: String) -> Result<(), String> {
    db.set_setting(&key, &value)
}

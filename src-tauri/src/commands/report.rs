// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src-tauri/src/commands/report.rs
//! Tauri command untuk generate laporan PDF/HTML — SDD bagian 10.
use serde_json::Value;
use tauri::{AppHandle, State};

use super::executor::run_python_blocking;
use crate::db::Db;

/// Tulis konten teks ke file (untuk export CSV/JSON ke folder pilihan user).
#[tauri::command]
pub fn write_text_file(path: String, content: String) -> Result<(), String> {
    use std::path::Path;
    if let Some(parent) = Path::new(&path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, content).map_err(|e| e.to_string())
}

/// Buka file/folder dengan aplikasi default OS (lintas-platform).
#[tauri::command]
pub fn open_path(path: String) -> Result<(), String> {
    use std::process::Command;
    use super::executor::hide_window;
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", &path]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(&path);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(&path);
        c
    };
    hide_window(&mut cmd);
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

/// Buka folder yang memuat sebuah file.
#[tauri::command]
pub fn reveal_path(path: String) -> Result<(), String> {
    use std::path::Path;
    let p = Path::new(&path);
    let dir = if p.is_file() {
        p.parent().map(|d| d.to_string_lossy().to_string()).unwrap_or(path.clone())
    } else {
        path.clone()
    };
    open_path(dir)
}

/// Generate laporan dari sebuah session_id tersimpan.
#[tauri::command]
pub async fn generate_report(
    app: AppHandle,
    db: State<'_, Db>,
    session_id: String,
    report_type: String,
    output_path: Option<String>,
) -> Result<Value, String> {
    // Ambil data session lengkap dari DB.
    let session = db.get_session_full(&session_id)?;
    let session_json = serde_json::to_string(&session).map_err(|e| e.to_string())?;

    let mut args = vec![
        "--session".to_string(),
        session_json,
        "--report_type".to_string(),
        report_type,
    ];
    if let Some(p) = output_path {
        args.push("--output_path".to_string());
        args.push(p);
    }
    run_python_blocking(&app, "generate_report", &args)
}

/// Generate laporan dari data hasil yang dikirim langsung dari frontend
/// (mis. hasil scan yang belum disimpan).
#[tauri::command]
pub async fn generate_report_from_data(
    app: AppHandle,
    session_data: Value,
    report_type: String,
) -> Result<Value, String> {
    let session_json = serde_json::to_string(&session_data).map_err(|e| e.to_string())?;
    let args = vec![
        "--session".to_string(),
        session_json,
        "--report_type".to_string(),
        report_type,
    ];
    run_python_blocking(&app, "generate_report", &args)
}

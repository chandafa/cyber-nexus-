// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src-tauri/src/commands/dependency.rs
//! Tauri commands untuk dependency checking & info sistem — SDD bagian 3.
use serde_json::Value;
use tauri::AppHandle;

use super::executor::run_python_blocking;

/// Jalankan pengecekan semua tools (required + optional).
#[tauri::command]
pub async fn check_dependencies(app: AppHandle) -> Result<Value, String> {
    run_python_blocking(&app, "check_deps", &[])
}

/// Dapatkan perintah instalasi untuk tools yang kurang.
#[tauri::command]
pub async fn get_install_info(app: AppHandle, missing: Vec<String>) -> Result<Value, String> {
    let args = vec!["--missing".to_string(), missing.join(",")];
    run_python_blocking(&app, "install_info", &args)
}

/// Pasang satu/lebih tools (otomatis minta elevasi), lalu kembalikan status terbaru.
#[tauri::command]
pub async fn install_tools(app: AppHandle, tools: Vec<String>) -> Result<Value, String> {
    let args = vec!["--tools".to_string(), tools.join(",")];
    run_python_blocking(&app, "install_tools", &args)
}

/// Cek privilege admin/root.
#[tauri::command]
pub async fn check_privileges(app: AppHandle) -> Result<Value, String> {
    run_python_blocking(&app, "privileges", &[])
}

/// Daftar interface jaringan (untuk Network Scanner).
#[tauri::command]
pub async fn list_interfaces(app: AppHandle) -> Result<Value, String> {
    run_python_blocking(&app, "list_interfaces", &[])
}

/// Generic: jalankan command python (blocking) & kembalikan JSON hasil.
/// Dipakai modul manajemen v2 (scheduler, asset, wordlist, scope, dll.).
#[tauri::command]
pub async fn run_tool_json(
    app: AppHandle,
    command: String,
    args: Vec<String>,
) -> Result<Value, String> {
    run_python_blocking(&app, &command, &args)
}

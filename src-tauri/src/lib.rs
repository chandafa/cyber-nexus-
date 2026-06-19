// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src-tauri/src/lib.rs
//! Nexus Tauri application entry — SDD bagian 6.
mod commands;
mod db;
mod models;

use tauri::Manager;

use commands::dependency::{
    check_dependencies, check_privileges, get_install_info, install_tools, list_interfaces,
    run_tool_json,
};
use commands::executor::{run_port_scan, run_scan, stop_scan, ScanRegistry};
use commands::pty::{pty_close, pty_open, pty_resize, pty_write, PtyRegistry};
use commands::report::{
    generate_report, generate_report_from_data, open_path, reveal_path, write_text_file,
};
use commands::scanner::{delete_session, get_session, get_settings, list_sessions, set_setting};
use db::Db;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init());

    // Updater hanya untuk desktop (bukan Android/iOS) — auto-update dari GitHub Release.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }

    builder
        .manage(ScanRegistry::default())
        .manage(PtyRegistry::default())
        .setup(|app| {
            // Inisialisasi database di folder data aplikasi.
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("tidak bisa menentukan app_data_dir");
            std::fs::create_dir_all(&data_dir).ok();
            let db_path = data_dir.join("nexus.db");
            let db = Db::new(&db_path).expect("gagal inisialisasi database");
            app.manage(db);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // executor / scanning
            run_scan,
            run_port_scan,
            stop_scan,
            // terminal interaktif (PTY)
            pty_open,
            pty_write,
            pty_resize,
            pty_close,
            // dependency & sistem
            check_dependencies,
            get_install_info,
            install_tools,
            check_privileges,
            list_interfaces,
            run_tool_json,
            // database
            list_sessions,
            get_session,
            delete_session,
            get_settings,
            set_setting,
            // report
            generate_report,
            generate_report_from_data,
            open_path,
            reveal_path,
            write_text_file,
        ])
        .run(tauri::generate_context!())
        .expect("error saat menjalankan aplikasi Nexus");
}

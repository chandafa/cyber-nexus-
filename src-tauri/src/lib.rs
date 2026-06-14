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
use commands::report::{
    generate_report, generate_report_from_data, open_path, reveal_path, write_text_file,
};
use commands::scanner::{delete_session, get_session, get_settings, list_sessions, set_setting};
use db::Db;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanRegistry::default())
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

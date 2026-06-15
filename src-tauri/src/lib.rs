// src-tauri/src/lib.rs
//! Nexus Tauri application entry — SDD bagian 6.
mod commands;
mod db;
mod models;

use std::sync::Mutex;
use sysinfo::System;
use tauri::{Emitter, Manager};

use commands::dependency::{
    check_dependencies, check_privileges, get_install_info, install_tools, list_interfaces,
    run_tool_json,
};
use commands::executor::{run_port_scan, run_scan, stop_scan, ScanRegistry};
use commands::report::{
    generate_report, generate_report_from_data, open_path, reveal_path, write_text_file,
};
use commands::scanner::{delete_session, get_session, get_settings, list_sessions, set_setting};
use commands::monitor::{
    get_system_status, get_supervisor_status, set_supervisor_enabled, clear_supervisor_logs,
    SystemMonitorState, WafSupervisorState,
};
use db::Db;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ScanRegistry::default())
        .manage(SystemMonitorState {
            sys: Mutex::new(System::new_all()),
        })
        .manage(WafSupervisorState::default())
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

            // Thread Watchdog Supervisor untuk memantau kesehatan modul WAF
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    if let Some(sup) = app_handle.try_state::<WafSupervisorState>() {
                        let is_enabled = {
                            let val = sup.is_enabled.lock().unwrap();
                            *val
                        };
                        if is_enabled {
                            let scan_id_opt = {
                                let val = sup.active_scan_id.lock().unwrap();
                                val.clone()
                            };
                            if let Some(scan_id) = scan_id_opt {
                                let mut is_running = false;
                                if let Some(reg) = app_handle.try_state::<ScanRegistry>() {
                                    if let Ok(map) = reg.0.lock() {
                                        if let Some(child_arc) = map.get(&scan_id) {
                                            if let Ok(mut child) = child_arc.lock() {
                                                match child.try_wait() {
                                                    Ok(None) => {
                                                        is_running = true;
                                                    }
                                                    _ => {
                                                        is_running = false;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if !is_running {
                                    // WAF terhenti secara tidak wajar. Lakukan auto-restart!
                                    let mut logs = sup.logs.lock().unwrap();
                                    let restarts = {
                                        let mut r = sup.auto_restarts.lock().unwrap();
                                        *r += 1;
                                        *r
                                    };
                                    logs.push(format!(
                                        "[{}] [CRITICAL] WAF process terminated unexpectedly (scan_id: {}). Restarting (Attempt #{})...",
                                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                                        scan_id,
                                        restarts
                                    ));

                                    // Ambil parameter konfigurasi sebelumnya
                                    let command = sup.command.lock().unwrap().clone();
                                    let args = sup.args.lock().unwrap().clone();
                                    let target = sup.target.lock().unwrap().clone();
                                    let mode = sup.mode.lock().unwrap().clone();

                                    if let (Some(cmd), Some(args)) = (command, args) {
                                        let new_scan_id = uuid::Uuid::new_v4().to_string();
                                        // Update active scan ID baru
                                        *sup.active_scan_id.lock().unwrap() = Some(new_scan_id.clone());

                                        let app_thread = app_handle.clone();
                                        tauri::async_runtime::spawn(async move {
                                            let db = app_thread.state::<Db>();
                                            let reg = app_thread.state::<ScanRegistry>();
                                            
                                            // Kirim notifikasi event kustom ke frontend
                                            app_thread.emit("waf-watchdog-restart", serde_json::json!({
                                                "old_scan_id": scan_id,
                                                "new_scan_id": new_scan_id.clone()
                                            })).ok();

                                            // Jalankan kembali WAF dengan kloning handle
                                            let _ = commands::executor::run_scan(
                                                app_thread.clone(),
                                                db,
                                                reg,
                                                new_scan_id,
                                                cmd,
                                                args,
                                                "waf".to_string(),
                                                target,
                                                mode
                                            ).await;
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            });

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
            // monitor & supervisor
            get_system_status,
            get_supervisor_status,
            set_supervisor_enabled,
            clear_supervisor_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error saat menjalankan aplikasi Nexus");
}

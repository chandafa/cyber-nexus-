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

use std::sync::Mutex;
use sysinfo::System;
use tauri::{Emitter, Manager};

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
use commands::monitor::{
    get_system_status, get_supervisor_status, set_supervisor_enabled, clear_supervisor_logs,
    SystemMonitorState, WafSupervisorState,
};
use commands::ebpf::{
    get_ebpf_status, get_blocked_ips, block_ip, unblock_ip, get_ids_alerts,
    clear_ids_alerts, set_ebpf_active, set_ebpf_interface, EbpfState,
};
use commands::nexus_listener::{
    get_nexus_listener_status, start_nexus_listener, stop_nexus_listener, send_nexus_agent_command, NexusAgentListenerState,
};
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

    let app = builder
        .manage(ScanRegistry::default())
        .manage(SystemMonitorState {
            sys: Mutex::new(System::new_all()),
            docker_services: Mutex::new(Vec::new()),
            network_interfaces: Mutex::new(Vec::new()),
        })
        .manage(WafSupervisorState::default())
        .manage(EbpfState::default())
        .manage(PtyRegistry::default())
        .manage(NexusAgentListenerState::default())
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

            // Jalankan Simulator eBPF untuk local development/mocking
            commands::ebpf::start_ebpf_simulator(app.handle().clone());

            // Thread untuk memperbarui status Network Interfaces dan Docker secara berkala (Non-blocking)
            let app_handle_for_discovery = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    let interfaces = {
                        let networks = sysinfo::Networks::new_with_refreshed_list();
                        networks.iter().map(|(name, _)| name.clone()).collect::<Vec<String>>()
                    };
                    let docker_svcs = get_docker_services();

                    if let Some(monitor) = app_handle_for_discovery.try_state::<SystemMonitorState>() {
                        if let Ok(mut lock) = monitor.network_interfaces.lock() {
                            *lock = interfaces;
                        }
                        if let Ok(mut lock) = monitor.docker_services.lock() {
                            *lock = docker_svcs;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(10));
                }
            });

            // Thread Watchdog Supervisor untuk memantau kesehatan modul WAF
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    
                    let mut is_enabled = false;
                    let mut scan_id_opt = None;
                    
                    // 1. Get system and supervisor telemetry and emit to frontend
                    if let (Some(monitor), Some(sup)) = (
                        app_handle.try_state::<SystemMonitorState>(),
                        app_handle.try_state::<WafSupervisorState>()
                    ) {
                        let system_status = {
                            let mut monitor_state = monitor.sys.lock().unwrap();
                            monitor_state.refresh_cpu();
                            monitor_state.refresh_memory();
                            
                            let cpu_usage = monitor_state.global_cpu_info().cpu_usage();
                            let total_memory = monitor_state.total_memory();
                            let used_memory = monitor_state.used_memory();
                            let memory_usage = if total_memory > 0 {
                                (used_memory as f64 / total_memory as f64) * 100.0
                            } else {
                                0.0
                            };
                            let uptime = System::uptime();
                            let os_name = System::name().unwrap_or_else(|| "Unknown".to_string());
                            let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
                            let kernel_version = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());
                            
                            let disks = sysinfo::Disks::new_with_refreshed_list();
                            let mut total_disk = 0;
                            let mut available_disk = 0;
                            for disk in &disks {
                                total_disk += disk.total_space();
                                available_disk += disk.available_space();
                            }
                            let disk_usage = if total_disk > 0 {
                                ((total_disk - available_disk) as f64 / total_disk as f64) * 100.0
                            } else {
                                0.0
                            };

                            let (docker_svcs, interfaces) = {
                                let docker = monitor.docker_services.lock().unwrap().clone();
                                let net = monitor.network_interfaces.lock().unwrap().clone();
                                (docker, net)
                            };

                            serde_json::json!({
                                "cpu_usage": cpu_usage,
                                "memory_usage": memory_usage,
                                "total_memory": total_memory,
                                "used_memory": used_memory,
                                "uptime": uptime,
                                "disk_usage": disk_usage,
                                "total_disk": total_disk,
                                "available_disk": available_disk,
                                "os_name": os_name,
                                "os_version": os_version,
                                "kernel_version": kernel_version,
                                "network_interfaces": interfaces,
                                "discovered_services": docker_svcs,
                            })
                        };

                        let supervisor_status = {
                            scan_id_opt = sup.active_scan_id.lock().unwrap().clone();
                            is_enabled = *sup.is_enabled.lock().unwrap();
                            let restarts = *sup.auto_restarts.lock().unwrap();
                            let logs = sup.logs.lock().unwrap().clone();
                            serde_json::json!({
                                "active_scan_id": scan_id_opt,
                                "is_enabled": is_enabled,
                                "auto_restarts": restarts,
                                "logs": logs,
                            })
                        };

                        app_handle.emit("system-telemetry", serde_json::json!({
                            "system": system_status,
                            "supervisor": supervisor_status
                        })).ok();
                    }

                    // 2. Perform watchdog check if enabled
                    if is_enabled {
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
                                if let Some(sup) = app_handle.try_state::<WafSupervisorState>() {
                                    let mut logs = sup.logs.lock().unwrap();
                                    
                                    // Watchdog Crash-Loop Breaker
                                    let mut quick_crash = false;
                                    let now = chrono::Local::now();
                                    if let Some(last_time) = *sup.last_restart_time.lock().unwrap() {
                                        let elapsed = now.signed_duration_since(last_time).num_seconds();
                                        if elapsed < 5 {
                                            quick_crash = true;
                                        }
                                    }

                                    let consecutive = {
                                        let mut count = sup.consecutive_quick_crashes.lock().unwrap();
                                        if quick_crash {
                                            *count += 1;
                                        } else {
                                            *count = 0;
                                        }
                                        *count
                                    };

                                    if consecutive >= 3 {
                                        *sup.is_enabled.lock().unwrap() = false;
                                        *sup.consecutive_quick_crashes.lock().unwrap() = 0; // reset
                                        logs.push(format!(
                                            "[{}] [CRITICAL] Watchdog disabled: WAF crashed repeatedly during startup. Check port bindings.",
                                            now.format("%Y-%m-%d %H:%M:%S")
                                        ));
                                        continue;
                                    }

                                    // WAF terhenti secara tidak wajar. Lakukan auto-restart!
                                    let restarts = {
                                        let mut r = sup.auto_restarts.lock().unwrap();
                                        *r += 1;
                                        *r
                                    };
                                    logs.push(format!(
                                        "[{}] [CRITICAL] WAF process terminated unexpectedly (scan_id: {}). Restarting (Attempt #{})...",
                                        now.format("%Y-%m-%d %H:%M:%S"),
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
            // monitor & supervisor
            get_system_status,
            get_supervisor_status,
            set_supervisor_enabled,
            clear_supervisor_logs,
            // ebpf security
            get_ebpf_status,
            get_blocked_ips,
            block_ip,
            unblock_ip,
            get_ids_alerts,
            clear_ids_alerts,
            set_ebpf_active,
            set_ebpf_interface,
            // nexus agent listener
            get_nexus_listener_status,
            start_nexus_listener,
            stop_nexus_listener,
            send_nexus_agent_command,
        ])
        .build(tauri::generate_context!())
        .expect("error saat menjalankan aplikasi Nexus");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            // 1. Kill WAF and scanners in ScanRegistry
            if let Some(registry) = app_handle.try_state::<ScanRegistry>() {
                if let Ok(mut reg) = registry.0.lock() {
                    for (scan_id, child_arc) in reg.iter() {
                        if let Ok(mut child) = child_arc.lock() {
                            println!("[Cleanup] Menghentikan subproses scan_id: {}", scan_id);
                            let _ = child.kill();
                        }
                    }
                    reg.clear();
                }
            }
            // 2. Stop Nexus Listener
            if let Some(state) = app_handle.try_state::<NexusAgentListenerState>() {
                let _ = stop_nexus_listener(state, app_handle.clone());
            }
        }
    });
}

fn get_docker_services() -> Vec<serde_json::Value> {
    use std::process::Command;
    let mut cmd = Command::new("docker");
    cmd.args(&["ps", "--format", "{{json .}}"]);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut services = Vec::new();
    if let Ok(output) = cmd.output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                        services.push(val);
                    }
                }
            }
        }
    }
    services
}

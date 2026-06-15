// src-tauri/src/commands/monitor.rs
use std::sync::Mutex;
use sysinfo::{System, Disks};
use tauri::State;
use serde_json::Value;

pub struct SystemMonitorState {
    pub sys: Mutex<System>,
}

pub struct WafSupervisorState {
    pub active_scan_id: Mutex<Option<String>>,
    pub is_enabled: Mutex<bool>,
    pub auto_restarts: Mutex<u32>,
    pub logs: Mutex<Vec<String>>,
    
    // Parameters for WAF restart
    pub command: Mutex<Option<String>>,
    pub args: Mutex<Option<Vec<String>>>,
    pub target: Mutex<Option<String>>,
    pub mode: Mutex<Option<String>>,
}

impl Default for WafSupervisorState {
    fn default() -> Self {
        Self {
            active_scan_id: Mutex::new(None),
            is_enabled: Mutex::new(false),
            auto_restarts: Mutex::new(0),
            logs: Mutex::new(vec!["[SYSTEM] Supervisor initialized.".to_string()]),
            command: Mutex::new(None),
            args: Mutex::new(None),
            target: Mutex::new(None),
            mode: Mutex::new(None),
        }
    }
}

#[tauri::command]
pub fn get_system_status(
    monitor: State<'_, SystemMonitorState>,
) -> Result<Value, String> {
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
    
    // Uptime, Name, OS Version, Kernel Version are static associated functions in sysinfo v0.30+
    let uptime = System::uptime();
    let os_name = System::name().unwrap_or_else(|| "Unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());
    
    // Disk info via Disks API in sysinfo v0.30+
    let disks = Disks::new_with_refreshed_list();
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

    Ok(serde_json::json!({
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
    }))
}

#[tauri::command]
pub fn get_supervisor_status(
    supervisor: State<'_, WafSupervisorState>,
) -> Result<Value, String> {
    let active_id = supervisor.active_scan_id.lock().unwrap().clone();
    let is_enabled = *supervisor.is_enabled.lock().unwrap();
    let restarts = *supervisor.auto_restarts.lock().unwrap();
    let logs = supervisor.logs.lock().unwrap().clone();
    
    Ok(serde_json::json!({
        "active_scan_id": active_id,
        "is_enabled": is_enabled,
        "auto_restarts": restarts,
        "logs": logs,
    }))
}

#[tauri::command]
pub fn set_supervisor_enabled(
    supervisor: State<'_, WafSupervisorState>,
    enabled: bool,
) -> Result<(), String> {
    let mut is_enabled = supervisor.is_enabled.lock().unwrap();
    *is_enabled = enabled;
    
    let mut logs = supervisor.logs.lock().unwrap();
    let status_str = if enabled { "ENABLED" } else { "DISABLED" };
    logs.push(format!(
        "[{}] Watchdog manually {}.",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        status_str
    ));
    Ok(())
}

#[tauri::command]
pub fn clear_supervisor_logs(
    supervisor: State<'_, WafSupervisorState>,
) -> Result<(), String> {
    let mut logs = supervisor.logs.lock().unwrap();
    logs.clear();
    logs.push("[SYSTEM] Supervisor logs cleared.".to_string());
    Ok(())
}

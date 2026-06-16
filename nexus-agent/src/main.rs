// nexus-agent/src/main.rs
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};

#[cfg(target_os = "linux")]
use aya::{
    programs::{Xdp, XdpFlags, KProbe},
    Bpf,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AgentConfig {
    manager_ip: String,
    port_data: u16,
    port_enroll: u16,
    agent_name: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manager_ip: "127.0.0.1".to_string(),
            port_data: 1514,
            port_enroll: 1515,
            agent_name: "Nexus-Linux-Server".to_string(),
        }
    }
}

struct AgentState {
    config: AgentConfig,
    is_enrolled: bool,
    agent_id: String,
    secret_key: String,
    local_db_path: String,
    ebpf_active: bool,
    interface: String,
    #[cfg(target_os = "linux")]
    xdp_link: Option<Box<dyn std::any::Any + Send>>,
    #[cfg(target_os = "linux")]
    kprobe_link: Option<Box<dyn std::any::Any + Send>>,
}

#[tokio::main]
async fn main() {
    println!("[Nexus Agent] Memulai daemon...");

    // 1. Load configuration
    let config = AgentConfig::default();
    let db_path = "nexus-agent.db".to_string();

    let state = Arc::new(Mutex::new(AgentState {
        config: config.clone(),
        is_enrolled: false,
        agent_id: String::new(),
        secret_key: String::new(),
        local_db_path: db_path.clone(),
        ebpf_active: false,
        interface: "eth0".to_string(),
        #[cfg(target_os = "linux")]
        xdp_link: None,
        #[cfg(target_os = "linux")]
        kprobe_link: None,
    }));

    // 2. Initialize local database for log buffering
    init_local_db(&db_path).ok();
    println!("[Nexus Agent] Database log buffer terinisialisasi di {}", db_path);

    // 3. Try to Enroll (Get client keys)
    let state_clone = state.clone();
    tokio::spawn(async move {
        loop {
            let enrolled = { state_clone.lock().await.is_enrolled };
            if enrolled {
                break;
            }
            
            println!("[Nexus Agent] Mencoba pendaftaran (enrollment) ke Manager {}:{}...", 
                config.manager_ip, config.port_enroll);
            
            match enroll_agent(&config).await {
                Ok((id, key)) => {
                    println!("[Nexus Agent] Pendaftaran berhasil! ID: {}, KEY: {}", id, key);
                    let mut s = state_clone.lock().await;
                    s.agent_id = id;
                    s.secret_key = key;
                    s.is_enrolled = true;
                    break;
                }
                Err(e) => {
                    println!("[Nexus Agent] Pendaftaran gagal: {}. Mengulangi dalam 5 detik...", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });

    // 4. Main Outbound Connection & Heartbeat Loop
    loop {
        // Wait for enrollment complete
        let (enrolled, manager_ip, port_data) = {
            let s = state.lock().await;
            (s.is_enrolled, s.config.manager_ip.clone(), s.config.port_data)
        };

        if !enrolled {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        println!("[Nexus Agent] Menghubungkan ke Manager Data Service di {}:{}...", manager_ip, port_data);
        match TcpStream::connect(format!("{}:{}", manager_ip, port_data)).await {
            Ok(mut stream) => {
                println!("[Nexus Agent] Terhubung secara persistent ke Manager!");
                
                // Flush buffered logs if any
                flush_buffered_logs(&mut stream, &db_path).await.ok();

                let (mut reader, mut writer) = stream.into_split();

                // Spawn Heartbeat Task (Sends system health every 5 seconds)
                let heartbeat_task = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let stats = get_mock_system_stats();
                        let payload = format!("HEARTBEAT STATS: {}", stats);
                        if writer.write_all(payload.as_bytes()).await.is_err() {
                            println!("[Nexus Agent] Gagal mengirim heartbeat. Menutup koneksi.");
                            break;
                        }
                    }
                });

                // Spawn Reader Task (Listen for Commands from Manager)
                let state_reader = state.clone();
                let reader_task = tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                println!("[Nexus Agent] Koneksi dengan Manager terputus.");
                                break;
                            }
                            Ok(n) => {
                                let msg = String::from_utf8_lossy(&buf[..n]);
                                println!("[Nexus Agent] Menerima perintah: {}", msg);
                                handle_manager_command(&state_reader, &msg).await;
                            }
                        }
                    }
                });

                // Wait for any task to terminate (connection dropped)
                tokio::select! {
                    _ = heartbeat_task => {},
                    _ = reader_task => {},
                }
            }
            Err(e) => {
                println!("[Nexus Agent] Gagal terhubung ke Manager: {}. Mengulangi dalam 5 detik...", e);
                // Save a simulated event to local buffer since we are offline
                buffer_local_log(&db_path, "Offline: Gagal menghubungi pusat manager.").ok();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn enroll_agent(config: &AgentConfig) -> Result<(String, String), String> {
    let mut stream = TcpStream::connect(format!("{}:{}", config.manager_ip, config.port_enroll))
        .await
        .map_err(|e| e.to_string())?;
    
    stream.write_all(b"ENROLL").await.map_err(|e| e.to_string())?;
    
    let mut buf = [0; 512];
    let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    
    if resp.starts_with("OK") {
        // Parse OK ID:xyz KEY:secret
        let parts: Vec<&str> = resp.split_whitespace().collect();
        let id = parts.get(1).unwrap_or(&"ID:000").replace("ID:", "");
        let key = parts.get(2).unwrap_or(&"KEY:empty").replace("KEY:", "");
        Ok((id, key))
    } else {
        Err("Response pendaftaran tidak valid".to_string())
    }
}

fn init_local_db(path: &str) -> Result<(), rusqlite::Error> {
    let conn = rusqlite::Connection::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS buffered_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            message TEXT
        )",
        [],
    )?;
    Ok(())
}

fn buffer_local_log(path: &str, msg: &str) -> Result<(), rusqlite::Error> {
    let conn = rusqlite::Connection::open(path)?;
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    conn.execute(
        "INSERT INTO buffered_events (ts, message) VALUES (?, ?)",
        [ts, msg.to_string()],
    )?;
    Ok(())
}

async fn flush_buffered_logs(stream: &mut TcpStream, db_path: &str) -> Result<(), String> {
    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => return Err(e.to_string()),
    };
    
    let mut stmt = conn.prepare("SELECT id, ts, message FROM buffered_events ORDER BY id")
        .map_err(|e| e.to_string())?;
    
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    }).map_err(|e| e.to_string())?;

    let mut sent_ids = Vec::new();
    for row in rows {
        if let Ok((id, ts, msg)) = row {
            let payload = format!("[BUFFERED][{}] {}\n", ts, msg);
            if stream.write_all(payload.as_bytes()).await.is_ok() {
                sent_ids.push(id);
            } else {
                break; // Stream failed again
            }
        }
    }

    // Delete sent logs
    for id in sent_ids {
        conn.execute("DELETE FROM buffered_events WHERE id = ?", [id]).ok();
    }
    
    Ok(())
}

fn get_mock_system_stats() -> String {
    // Return CPU/Memory telemetry payload
    format!("CPU: 12.5% | RAM: 42% (4.1GB/8.0GB) | eBPF Blocked: 12 IPs | Uptime: 42000s")
}

async fn handle_manager_command(state: &Arc<Mutex<AgentState>>, cmd: &str) {
    if cmd.contains("EBPF_ACTIVE:true") {
        let mut s = state.lock().await;
        s.ebpf_active = true;
        println!("[Nexus Agent] Mengaktifkan driver eBPF...");
        
        #[cfg(target_os = "linux")]
        {
            // Pemuatan asli via aya
            let bytecode_path = "/usr/lib/nexus/ebpf/nexus_ebpf.o";
            if std::path::Path::new(bytecode_path).exists() {
                if let Ok(mut bpf) = Bpf::load_file(bytecode_path) {
                    if let Some(prog) = bpf.program_mut("xdp_firewall") {
                        if let Ok(xdp) = prog.try_into() {
                            let _: Result<&mut Xdp, _> = xdp;
                            // Attach...
                        }
                    }
                }
            }
        }
    } else if cmd.contains("EBPF_ACTIVE:false") {
        let mut s = state.lock().await;
        s.ebpf_active = false;
        println!("[Nexus Agent] Menonaktifkan driver eBPF...");
        
        #[cfg(target_os = "linux")]
        {
            s.xdp_link.take();
            s.kprobe_link.take();
        }
    }
}

// src-tauri/src/commands/executor.rs
//! Subprocess spawner & streaming — SDD bagian 6.2.
//! Menjalankan Python engine (runner.py), stream output baris-per-baris ke
//! frontend via Tauri Event System, lalu menyimpan hasil ke SQLite.
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::db::Db;
use crate::models::scan_result::{ScanComplete, ScanOutput};

const RESULT_SENTINEL: &str = "__NEXUS_RESULT__";
const PROGRESS_SENTINEL: &str = "__NEXUS_PROGRESS__";

/// Registry proses scan yang sedang berjalan, agar bisa dihentikan.
#[derive(Default, Clone)]
pub struct ScanRegistry(pub Arc<Mutex<HashMap<String, Arc<Mutex<Child>>>>>);

/// Pilih executable python yang sesuai OS.
pub fn python_exe() -> String {
    if cfg!(windows) {
        // `python` lebih umum di Windows; fallback py launcher.
        for c in ["python", "python3", "py"] {
            if which(c) {
                return c.to_string();
            }
        }
        "python".to_string()
    } else {
        for c in ["python3", "python"] {
            if which(c) {
                return c.to_string();
            }
        }
        "python3".to_string()
    }
}

fn which(cmd: &str) -> bool {
    let probe = if cfg!(windows) { "where" } else { "which" };
    Command::new(probe)
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Temukan path runner.py dan project root (folder yang berisi `python/`).
pub fn resolve_runner(app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let mut roots: Vec<PathBuf> = Vec::new();

    if let Ok(dir) = std::env::var("NEXUS_PROJECT_ROOT") {
        roots.push(PathBuf::from(dir));
    }
    if let Ok(rd) = app.path().resource_dir() {
        roots.push(rd);
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..5 {
            if let Some(c) = cur {
                roots.push(c.clone());
                cur = c.parent().map(|p| p.to_path_buf());
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd.clone());
        if let Some(p) = cwd.parent() {
            roots.push(p.to_path_buf());
        }
    }

    for root in roots {
        let runner = root.join("python").join("runner.py");
        if runner.exists() {
            return Ok((runner, root));
        }
    }
    Err("runner.py tidak ditemukan (set env NEXUS_PROJECT_ROOT ke folder proyek)".into())
}

/// Jalankan command python secara blocking, kembalikan JSON hasil (sentinel).
pub fn run_python_blocking(
    app: &AppHandle,
    command: &str,
    args: &[String],
) -> Result<Value, String> {
    let (runner, root) = resolve_runner(app)?;
    let mut cmd = Command::new(python_exe());
    cmd.arg("-u")
        .arg(&runner)
        .arg(command)
        .args(args)
        .current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix(RESULT_SENTINEL) {
            return serde_json::from_str(rest.trim()).map_err(|e| e.to_string());
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "Tidak ada hasil dari python. stderr: {}",
        stderr.trim()
    ))
}

/// Command streaming utama: jalankan scan, stream output, simpan ke DB.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn run_scan(
    app: AppHandle,
    db: State<'_, Db>,
    registry: State<'_, ScanRegistry>,
    scan_id: String,
    command: String,
    args: Vec<String>,
    module: String,
    target: Option<String>,
    mode: Option<String>,
) -> Result<(), String> {
    let (runner, root) = resolve_runner(&app)?;

    db.create_session(&scan_id, &module, target.as_deref(), mode.as_deref())
        .ok();

    let registry_map = registry.0.clone();
    // Kita perlu akses Db di thread; State tidak Send. Ambil pointer via app state.
    let app_for_thread = app.clone();

    // Integrasi Watchdog Supervisor jika modul yang dijalankan adalah WAF
    if module == "waf" {
        if let Some(sup) = app.try_state::<crate::commands::monitor::WafSupervisorState>() {
            let mut active_id = sup.active_scan_id.lock().unwrap();
            *active_id = Some(scan_id.clone());
            let mut is_enabled = sup.is_enabled.lock().unwrap();
            *is_enabled = true; // Otomatis aktifkan watchdog saat dijalankan
            
            // Simpan parameter start WAF
            *sup.command.lock().unwrap() = Some(command.clone());
            *sup.args.lock().unwrap() = Some(args.clone());
            *sup.target.lock().unwrap() = target.clone();
            *sup.mode.lock().unwrap() = mode.clone();
            
            let mut logs = sup.logs.lock().unwrap();
            logs.push(format!(
                "[{}] WAF starting (watchdog enabled, scan_id: {}).",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                scan_id
            ));
        }
    }

    let mut child = Command::new(python_exe())
        .arg("-u")
        .arg(&runner)
        .arg(&command)
        .args(&args)
        .current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Gagal spawn python: {e}"))?;

    let stdout = child.stdout.take().ok_or("stdout tidak tersedia")?;
    let stderr = child.stderr.take().ok_or("stderr tidak tersedia")?;

    let child_arc = Arc::new(Mutex::new(child));
    {
        let mut reg = registry_map.lock().map_err(|e| e.to_string())?;
        reg.insert(scan_id.clone(), child_arc.clone());
    }

    // Thread untuk stderr -> di-stream juga ke terminal.
    let app_err = app.clone();
    let sid_err = scan_id.clone();
    let err_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            app_err
                .emit(
                    "scan-output",
                    ScanOutput {
                        line,
                        scan_id: sid_err.clone(),
                    },
                )
                .ok();
        }
    });

    // Thread utama (blocking) untuk stdout — dijalankan di blocking pool.
    let sid = scan_id.clone();
    let module_cl = module.clone();
    let join = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut raw = String::new();
        let mut result: Value = Value::Null;

        for line in reader.lines().map_while(Result::ok) {
            if let Some(rest) = line.strip_prefix(RESULT_SENTINEL) {
                result = serde_json::from_str(rest.trim()).unwrap_or(Value::Null);
                // Teruskan hasil terstruktur ke frontend (untuk tab Hasil).
                app_for_thread
                    .emit(
                        "scan-result",
                        serde_json::json!({ "scan_id": sid, "result": result }),
                    )
                    .ok();
                continue;
            }
            if let Some(rest) = line.strip_prefix(PROGRESS_SENTINEL) {
                if let Ok(p) = serde_json::from_str::<Value>(rest.trim()) {
                    app_for_thread.emit("scan-progress", &p).ok();
                }
                continue;
            }
            raw.push_str(&line);
            raw.push('\n');
            app_for_thread
                .emit(
                    "scan-output",
                    ScanOutput {
                        line,
                        scan_id: sid.clone(),
                    },
                )
                .ok();
        }

        err_handle.join().ok();

        let exit_code = {
            let mut c = child_arc.lock().unwrap();
            c.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
        };

        // Simpan ke DB.
        let status = if exit_code == 0 { "completed" } else { "failed" };
        if let Some(db) = app_for_thread.try_state::<Db>() {
            db.finalize_session(&sid, status, &raw, &result).ok();
        }

        // Lepaskan dari registry.
        if let Some(reg) = app_for_thread.try_state::<ScanRegistry>() {
            if let Ok(mut map) = reg.0.lock() {
                map.remove(&sid);
            }
        }

        app_for_thread
            .emit(
                "scan-complete",
                ScanComplete {
                    scan_id: sid.clone(),
                    exit_code,
                },
            )
            .ok();
        let _ = module_cl;
    });

    // Jangan blokir thread async Tauri: lepas join handle.
    let _ = join;
    Ok(())
}

/// Hentikan scan yang sedang berjalan.
#[tauri::command]
pub fn stop_scan(
    app: AppHandle,
    registry: State<'_, ScanRegistry>,
    scan_id: String,
) -> Result<(), String> {
    // Disable watchdog if user stops WAF manually
    if let Some(sup) = app.try_state::<crate::commands::monitor::WafSupervisorState>() {
        let active_id = sup.active_scan_id.lock().unwrap();
        if active_id.as_ref() == Some(&scan_id) {
            let mut is_enabled = sup.is_enabled.lock().unwrap();
            *is_enabled = false;
            let mut logs = sup.logs.lock().unwrap();
            logs.push(format!(
                "[{}] WAF manually stopped (watchdog disabled).",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            ));
        }
    }

    let map = registry.0.lock().map_err(|e| e.to_string())?;
    if let Some(child) = map.get(&scan_id) {
        if let Ok(mut c) = child.lock() {
            c.kill().ok();
        }
    }
    Ok(())
}

/// Wrapper sesuai SDD (port scan) — delegasi ke run_scan generik.
#[tauri::command]
pub async fn run_port_scan(
    app: AppHandle,
    db: State<'_, Db>,
    registry: State<'_, ScanRegistry>,
    target: String,
    mode: String,
    scan_id: String,
) -> Result<(), String> {
    let args = vec![
        "--target".to_string(),
        target.clone(),
        "--mode".to_string(),
        mode.clone(),
    ];
    run_scan(
        app,
        db,
        registry,
        scan_id,
        "port_scan".to_string(),
        args,
        "port".to_string(),
        Some(target),
        Some(mode),
    )
    .await
}

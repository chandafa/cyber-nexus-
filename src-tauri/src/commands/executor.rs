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

/// Pilih executable python untuk menjalankan engine.
///
/// PRIORITAS (kritis untuk portabilitas — agar .exe jalan di komputer lain
/// tanpa perlu menginstal Python):
///   1. Runtime Python yang DI-BUNDLE bersama aplikasi (`<root>/python-runtime/`),
///      disiapkan oleh CI/CD (`scripts/prepare-python-runtime.ps1`).
///   2. Fallback: interpreter Python dari PATH host (mode dev / build manual).
pub fn python_exe(root: &std::path::Path) -> String {
    // 1. Runtime bundel — dicari relatif terhadap folder yang berisi `python/`.
    //    Saat di-bundle Tauri, resource `../python-runtime` ditaruh di `_up_/`,
    //    sehingga `root` (= base hasil resolve_runner) sudah menunjuk ke sana.
    let bundled = if cfg!(windows) {
        root.join("python-runtime").join("python.exe")
    } else {
        root.join("python-runtime").join("bin").join("python3")
    };
    if bundled.exists() {
        return bundled.to_string_lossy().into_owned();
    }

    // 2. Fallback ke interpreter host.
    if cfg!(windows) {
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

/// Sembunyikan jendela console subprocess (CREATE_NO_WINDOW) di Windows agar
/// tidak ada kedipan PowerShell/terminal saat memanggil python/where/dll.
/// No-op di OS lain.
#[cfg(windows)]
pub(crate) fn hide_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}
#[cfg(not(windows))]
pub(crate) fn hide_window(_cmd: &mut Command) {}

fn which(cmd: &str) -> bool {
    let probe = if cfg!(windows) { "where" } else { "which" };
    let mut c = Command::new(probe);
    c.arg(cmd).stdout(Stdio::null()).stderr(Stdio::null());
    hide_window(&mut c);
    c.status().map(|s| s.success()).unwrap_or(false)
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
        // Saat di-bundle Tauri, resource yang direferensikan dengan `../python`
        // ditaruh di bawah folder `_up_` (Tauri mengganti `..` -> `_up_`).
        // Jadi cek kedua layout: source tree (`python/`) dan bundle (`_up_/python/`).
        for prefix in ["", "_up_"] {
            let base = if prefix.is_empty() {
                root.clone()
            } else {
                root.join(prefix)
            };
            let runner = base.join("python").join("runner.py");
            if runner.exists() {
                return Ok((runner, base));
            }
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
    let mut cmd = Command::new(python_exe(&root));
    cmd.arg("-u")
        .arg(&runner)
        .arg(command)
        .args(args)
        .current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut cmd);

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

    let mut spawn_cmd = Command::new(python_exe(&root));
    spawn_cmd
        .arg("-u")
        .arg(&runner)
        .arg(&command)
        .args(&args)
        .current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut spawn_cmd);
    let mut child = spawn_cmd
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
pub fn stop_scan(registry: State<'_, ScanRegistry>, scan_id: String) -> Result<(), String> {
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

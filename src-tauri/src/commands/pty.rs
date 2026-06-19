// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src-tauri/src/commands/pty.rs
//! Terminal interaktif sungguhan (PTY) — bukan sekadar tampilan output scan.
//! Menggunakan ConPTY (Windows) / openpty (Unix) via crate `portable-pty`,
//! sehingga pengguna bisa mengetik & menjalankan perintah apa pun di shell host
//! langsung dari dalam aplikasi (PowerShell di Windows, $SHELL/bash di Unix).
//!
//! Alur:
//!   frontend  --invoke pty_open-->  spawn shell + thread pembaca
//!   shell stdout --event "pty-output" {id,data}--> xterm.js
//!   xterm onData --invoke pty_write--> shell stdin
//!   resize --invoke pty_resize--> ConPTY/openpty resize
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

/// Satu sesi terminal aktif.
/// `master` dibungkus Mutex agar `PtySession` menjadi `Sync` (trait object
/// `MasterPty` hanya `Send`), syarat untuk dipakai sebagai managed state Tauri.
pub(crate) struct PtySession {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
}

/// Registry seluruh terminal yang sedang hidup (key = id dari frontend).
#[derive(Default, Clone)]
pub struct PtyRegistry(pub Arc<Mutex<HashMap<String, Arc<PtySession>>>>);

#[derive(Clone, Serialize)]
struct PtyOutput {
    id: String,
    data: String,
}

#[derive(Clone, Serialize)]
struct PtyExit {
    id: String,
}

/// Shell default per-OS. Pengguna bisa override lewat argumen `shell`.
fn default_shell() -> String {
    if cfg!(windows) {
        // PowerShell tersedia di semua Windows 10/11; fallback ke cmd.
        "powershell.exe".to_string()
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string())
    }
}

/// Buka sesi terminal interaktif baru.
#[tauri::command]
pub fn pty_open(
    app: AppHandle,
    registry: State<'_, PtyRegistry>,
    id: String,
    shell: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
) -> Result<(), String> {
    let size = PtySize {
        rows: rows.unwrap_or(24),
        cols: cols.unwrap_or(80),
        pixel_width: 0,
        pixel_height: 0,
    };

    let pty_system = native_pty_system();
    let pair = pty_system.openpty(size).map_err(|e| e.to_string())?;

    let shell = shell.filter(|s| !s.trim().is_empty()).unwrap_or_else(default_shell);
    let mut cmd = CommandBuilder::new(&shell);
    // Mulai di home directory pengguna agar terasa seperti terminal biasa.
    if let Some(home) = dirs_home() {
        cmd.cwd(home);
    }
    cmd.env("TERM", "xterm-256color");

    let child = pair.slave.spawn_command(cmd).map_err(|e| {
        format!("Gagal menjalankan shell '{shell}': {e}")
    })?;
    // slave tidak diperlukan lagi di sisi induk setelah spawn.
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;

    let session = Arc::new(PtySession {
        master: Mutex::new(pair.master),
        writer: Mutex::new(writer),
        child: Mutex::new(child),
    });

    registry
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .insert(id.clone(), session);

    // Thread pembaca: stream output shell ke frontend baris-demi-byte.
    let app_cl = app.clone();
    let reg_cl = registry.0.clone();
    let id_cl = id.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF — shell selesai
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                    app_cl
                        .emit("pty-output", PtyOutput { id: id_cl.clone(), data })
                        .ok();
                }
                Err(_) => break,
            }
        }
        // Bersihkan sesi & beri tahu frontend.
        if let Ok(mut map) = reg_cl.lock() {
            map.remove(&id_cl);
        }
        app_cl.emit("pty-exit", PtyExit { id: id_cl.clone() }).ok();
    });

    Ok(())
}

/// Kirim input (ketikan/perintah) ke shell.
#[tauri::command]
pub fn pty_write(registry: State<'_, PtyRegistry>, id: String, data: String) -> Result<(), String> {
    let session = {
        let map = registry.0.lock().map_err(|e| e.to_string())?;
        map.get(&id).cloned()
    };
    if let Some(session) = session {
        let mut w = session.writer.lock().map_err(|e| e.to_string())?;
        w.write_all(data.as_bytes()).map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Ubah ukuran terminal (mengikuti ukuran kontainer xterm).
#[tauri::command]
pub fn pty_resize(
    registry: State<'_, PtyRegistry>,
    id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let session = {
        let map = registry.0.lock().map_err(|e| e.to_string())?;
        map.get(&id).cloned()
    };
    if let Some(session) = session {
        let master = session.master.lock().map_err(|e| e.to_string())?;
        master
            .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Tutup & matikan sesi terminal.
#[tauri::command]
pub fn pty_close(registry: State<'_, PtyRegistry>, id: String) -> Result<(), String> {
    let session = registry.0.lock().map_err(|e| e.to_string())?.remove(&id);
    if let Some(session) = session {
        if let Ok(mut c) = session.child.lock() {
            c.kill().ok();
        }
    }
    Ok(())
}

/// Folder home pengguna (lintas-OS) untuk cwd awal shell.
fn dirs_home() -> Option<std::path::PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
}

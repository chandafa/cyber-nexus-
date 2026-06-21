// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

// src-tauri/src/db/mod.rs
//! Lapisan akses database SQLite (via rusqlite). Menyimpan sessions, hasil,
//! anomali, dan settings. Sesuai SDD bagian 7.
pub mod schema;

use rusqlite::Connection;
use serde_json::Value;
use std::sync::Mutex;

use crate::models::scan_result::ScanSession;

pub struct Db(pub Mutex<Connection>);

impl Db {
    pub fn new(path: &std::path::Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        let _ = conn.execute("PRAGMA journal_mode=WAL;", []);
        conn.execute_batch(schema::SCHEMA_SQL)
            .map_err(|e| e.to_string())?;
        Ok(Db(Mutex::new(conn)))
    }

    /// Buat sesi scan baru, kembalikan id.
    pub fn create_session(
        &self,
        id: &str,
        module: &str,
        target: Option<&str>,
        mode: Option<&str>,
    ) -> Result<(), String> {
        let conn = self.0.lock().map_err(|e| e.to_string())?;
        let now = chrono::Local::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO scan_sessions (id, module, target, mode, status, started_at)
             VALUES (?1, ?2, ?3, ?4, 'running', ?5)",
            rusqlite::params![id, module, target, mode, now],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Tandai sesi selesai dan simpan raw output + hasil terstruktur.
    pub fn finalize_session(
        &self,
        id: &str,
        status: &str,
        raw_output: &str,
        result: &Value,
    ) -> Result<(), String> {
        let conn = self.0.lock().map_err(|e| e.to_string())?;
        let now = chrono::Local::now().to_rfc3339();
        conn.execute(
            "UPDATE scan_sessions SET status=?1, ended_at=?2, raw_output=?3 WHERE id=?4",
            rusqlite::params![status, now, raw_output, id],
        )
        .map_err(|e| e.to_string())?;

        // Simpan detail sesuai modul.
        if let Some(ports) = result.get("ports").and_then(|v| v.as_array()) {
            let target_ip = result.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let hostname = result.get("hostname").and_then(|v| v.as_str());
            let os_guess = result.get("os_guess").and_then(|v| v.as_str());
            for p in ports {
                conn.execute(
                    "INSERT INTO port_results
                     (session_id,target_ip,hostname,os_guess,port,protocol,state,service,version,extra_info)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    rusqlite::params![
                        id, target_ip, hostname, os_guess,
                        p.get("port").and_then(|v| v.as_i64()).unwrap_or(0),
                        p.get("protocol").and_then(|v| v.as_str()),
                        p.get("state").and_then(|v| v.as_str()),
                        p.get("service").and_then(|v| v.as_str()),
                        p.get("version").and_then(|v| v.as_str()),
                        p.get("extra_info").and_then(|v| v.as_str()),
                    ],
                )
                .ok();
            }
        }

        if let Some(vulns) = result.get("vulnerabilities").and_then(|v| v.as_array()) {
            for v in vulns {
                conn.execute(
                    "INSERT INTO vuln_results
                     (session_id,tool,severity,vuln_id,title,description,url,remediation)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    rusqlite::params![
                        id,
                        v.get("tool").and_then(|x| x.as_str()).unwrap_or("unknown"),
                        v.get("severity").and_then(|x| x.as_str()),
                        v.get("vuln_id").and_then(|x| x.as_str()),
                        v.get("title").and_then(|x| x.as_str()).unwrap_or(""),
                        v.get("description").and_then(|x| x.as_str()),
                        v.get("url").and_then(|x| x.as_str()),
                        v.get("remediation").and_then(|x| x.as_str()),
                    ],
                )
                .ok();
            }
        }

        if let Some(anomalies) = result.get("anomalies").and_then(|v| v.as_array()) {
            for a in anomalies {
                conn.execute(
                    "INSERT INTO anomaly_logs
                     (session_id,timestamp,source_ip,attack_type,severity,detail,raw_line)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    rusqlite::params![
                        id,
                        a.get("timestamp").and_then(|x| x.as_str()),
                        a.get("source_ip").and_then(|x| x.as_str()),
                        a.get("attack_type").and_then(|x| x.as_str()),
                        a.get("severity").and_then(|x| x.as_str()),
                        a.get("detail").and_then(|x| x.as_str()),
                        a.get("raw_line").and_then(|x| x.as_str()),
                    ],
                )
                .ok();
            }
        }
        Ok(())
    }

    pub fn list_sessions(&self, limit: i64) -> Result<Vec<ScanSession>, String> {
        let conn = self.0.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id,module,target,mode,status,started_at,ended_at,raw_output,notes
                 FROM scan_sessions ORDER BY started_at DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok(ScanSession {
                    id: r.get(0)?,
                    module: r.get(1)?,
                    target: r.get(2)?,
                    mode: r.get(3)?,
                    status: r.get(4)?,
                    started_at: r.get(5)?,
                    ended_at: r.get(6)?,
                    raw_output: r.get(7)?,
                    notes: r.get(8)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for s in rows {
            out.push(s.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// Ambil sesi lengkap + hasil terkait sebagai JSON (untuk laporan/detail).
    pub fn get_session_full(&self, session_id: &str) -> Result<Value, String> {
        let conn = self.0.lock().map_err(|e| e.to_string())?;
        let mut session: Value = conn
            .query_row(
                "SELECT id,module,target,mode,status,started_at,ended_at,raw_output,notes
                 FROM scan_sessions WHERE id=?1",
                [session_id],
                |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, String>(0)?,
                        "module": r.get::<_, String>(1)?,
                        "target": r.get::<_, Option<String>>(2)?,
                        "mode": r.get::<_, Option<String>>(3)?,
                        "status": r.get::<_, String>(4)?,
                        "started_at": r.get::<_, String>(5)?,
                        "ended_at": r.get::<_, Option<String>>(6)?,
                        "raw_output": r.get::<_, Option<String>>(7)?,
                        "notes": r.get::<_, Option<String>>(8)?,
                    }))
                },
            )
            .map_err(|e| e.to_string())?;

        // ports
        let mut ports = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT port,protocol,state,service,version,extra_info FROM port_results WHERE session_id=?1")
                .map_err(|e| e.to_string())?;
            let it = stmt
                .query_map([session_id], |r| {
                    Ok(serde_json::json!({
                        "port": r.get::<_, i64>(0)?,
                        "protocol": r.get::<_, Option<String>>(1)?,
                        "state": r.get::<_, Option<String>>(2)?,
                        "service": r.get::<_, Option<String>>(3)?,
                        "version": r.get::<_, Option<String>>(4)?,
                        "extra_info": r.get::<_, Option<String>>(5)?,
                    }))
                })
                .map_err(|e| e.to_string())?;
            for p in it {
                ports.push(p.map_err(|e| e.to_string())?);
            }
        }

        // vulns
        let mut vulns = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT tool,severity,vuln_id,title,description,url,remediation FROM vuln_results WHERE session_id=?1")
                .map_err(|e| e.to_string())?;
            let it = stmt
                .query_map([session_id], |r| {
                    Ok(serde_json::json!({
                        "tool": r.get::<_, String>(0)?,
                        "severity": r.get::<_, Option<String>>(1)?,
                        "vuln_id": r.get::<_, Option<String>>(2)?,
                        "title": r.get::<_, String>(3)?,
                        "description": r.get::<_, Option<String>>(4)?,
                        "url": r.get::<_, Option<String>>(5)?,
                        "remediation": r.get::<_, Option<String>>(6)?,
                    }))
                })
                .map_err(|e| e.to_string())?;
            for v in it {
                vulns.push(v.map_err(|e| e.to_string())?);
            }
        }

        // anomalies
        let mut anomalies = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT timestamp,source_ip,attack_type,severity,detail,raw_line FROM anomaly_logs WHERE session_id=?1")
                .map_err(|e| e.to_string())?;
            let it = stmt
                .query_map([session_id], |r| {
                    Ok(serde_json::json!({
                        "timestamp": r.get::<_, Option<String>>(0)?,
                        "source_ip": r.get::<_, Option<String>>(1)?,
                        "attack_type": r.get::<_, Option<String>>(2)?,
                        "severity": r.get::<_, Option<String>>(3)?,
                        "detail": r.get::<_, Option<String>>(4)?,
                        "raw_line": r.get::<_, Option<String>>(5)?,
                    }))
                })
                .map_err(|e| e.to_string())?;
            for a in it {
                anomalies.push(a.map_err(|e| e.to_string())?);
            }
        }

        if let Some(obj) = session.as_object_mut() {
            obj.insert("ports".into(), Value::Array(ports));
            obj.insert("vulnerabilities".into(), Value::Array(vulns));
            obj.insert("anomalies".into(), Value::Array(anomalies));
        }
        Ok(session)
    }

    pub fn delete_session(&self, session_id: &str) -> Result<(), String> {
        let conn = self.0.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM port_results WHERE session_id=?1", [session_id]).ok();
        conn.execute("DELETE FROM vuln_results WHERE session_id=?1", [session_id]).ok();
        conn.execute("DELETE FROM anomaly_logs WHERE session_id=?1", [session_id]).ok();
        conn.execute("DELETE FROM scan_sessions WHERE id=?1", [session_id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_settings(&self) -> Result<Value, String> {
        let conn = self.0.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT key,value FROM settings")
            .map_err(|e| e.to_string())?;
        let it = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?;
        let mut map = serde_json::Map::new();
        for kv in it {
            let (k, v) = kv.map_err(|e| e.to_string())?;
            map.insert(k, Value::String(v));
        }
        Ok(Value::Object(map))
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.0.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            rusqlite::params![key, value],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

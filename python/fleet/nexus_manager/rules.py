# nexus_manager/rules.py
"""
Rule engine Nexus (item #3) — cocokkan event -> alert berlevel (0-15, ala-Wazuh).

Format rule (native, ramah-konversi Sigma):
  {
    "id": "NEXUS-FIM-001",
    "name": "Sensitive .env file modified",
    "category": "file_integrity",
    "level": 14,                       # atau "severity": "critical"
    "mitre": ["T1005", "T1552.001"],   # MITRE ATT&CK technique IDs
    "conditions": {                    # SEMUA harus cocok (AND)
        "event_type": "file_modified", # sama-dengan
        "target.path": {"ends_with": ".env"},
        "severity_gte": "high",
        "data.port": {"in": [3389, 445]}
    },
    "recommendation": "Rotasi secret, audit proses pengubah file.",
    "response": ["notify", "create_incident"]
  }

`evaluate(event, ruleset)` mengembalikan list alert (schema.make_alert).
"""
from nexus_common import schema


def _get_path(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_op(value, spec):
    """spec bisa nilai literal (sama-dengan) atau dict operator."""
    if isinstance(spec, dict):
        for op, want in spec.items():
            v = value
            if op == "equals" and v != want:
                return False
            if op == "ends_with" and not (isinstance(v, str) and v.lower().endswith(str(want).lower())):
                return False
            if op == "starts_with" and not (isinstance(v, str) and v.lower().startswith(str(want).lower())):
                return False
            if op == "contains" and not (isinstance(v, str) and str(want).lower() in v.lower()):
                return False
            if op == "in" and v not in want:
                return False
            if op == "gte" and not (v is not None and v >= want):
                return False
            if op == "regex":
                import re
                if not (isinstance(v, str) and re.search(want, v, re.I)):
                    return False
        return True
    return value == spec


def _matches(event, conditions):
    for key, spec in (conditions or {}).items():
        if key == "severity_gte":
            if schema.severity_to_level(event.get("severity")) < schema.severity_to_level(spec):
                return False
            continue
        if key == "title_contains":
            if str(spec).lower() not in str(event.get("title", "")).lower():
                return False
            continue
        value = _get_path(event, key)
        if not _match_op(value, spec):
            return False
    return True


def evaluate(event, ruleset, agent_id="", tenant_id="default"):
    """Cocokkan event ke seluruh ruleset; hasilkan alert utk tiap rule yang cocok."""
    alerts = []
    for rule in ruleset or []:
        try:
            if _matches(event, rule.get("conditions", {})):
                alerts.append(schema.make_alert(agent_id or event.get("agent_id", ""),
                                                rule, event, tenant_id))
        except Exception:
            continue
    return alerts


# --------------------------------------------------------------------------- default ruleset
DEFAULT_RULES = [
    {
        "id": "NEXUS-FIM-001", "name": "File sensitif (.env) diubah di endpoint",
        "category": "file_integrity", "level": 14, "mitre": ["T1005", "T1552.001"],
        "conditions": {"category": "file_integrity", "target.path": {"ends_with": ".env"}},
        "recommendation": "Bandingkan hash lama/baru, audit user/proses pengubah, "
                          "rotasi APP_KEY/DB_PASSWORD/JWT_SECRET, restart service.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-FIM-002", "name": "Perubahan integritas file terdeteksi",
        "category": "file_integrity", "level": 10, "mitre": ["T1565.001"],
        "conditions": {"category": "file_integrity"},
        "recommendation": "Verifikasi apakah perubahan sah (deploy) atau mencurigakan.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-FW-001", "tier": "free", "name": "Firewall host NONAKTIF",
        "category": "config_assessment", "level": 10, "mitre": ["T1562.004"],
        "conditions": {"type": "firewall", "data.enabled": False},
        "recommendation": "Aktifkan firewall host & batasi inbound ke port esensial.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-NET-001", "tier": "free", "name": "Port berisiko terekspos",
        "category": "network_activity", "level": 7, "mitre": ["T1046"],
        "conditions": {"type": "exposure"},
        "recommendation": "Tutup/filter layanan (RDP/SMB/DB) atau batasi ke VPN/allowlist.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-AUTH-001", "name": "Indikasi brute-force login",
        "category": "authentication", "level": 12, "mitre": ["T1110"],
        "conditions": {"type": "failed_logins", "severity_gte": "high"},
        "recommendation": "Blokir IP sumber, terapkan rate-limit/fail2ban, audit akun.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-AUTH-002", "tier": "free", "name": "Lonjakan login gagal",
        "category": "authentication", "level": 8, "mitre": ["T1110"],
        "conditions": {"type": "failed_logins", "severity_gte": "medium"},
        "recommendation": "Pantau sumber percobaan login; pertimbangkan MFA.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-SCA-001", "name": "Gagal Security Configuration Assessment",
        "category": "config_assessment", "level": 9, "mitre": ["T1078"],
        "conditions": {"type": "sca", "severity_gte": "high"},
        "recommendation": "Perbaiki konfigurasi sesuai baseline hardening.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-VULN-001", "name": "Kerentanan software berisiko tinggi",
        "category": "vulnerability_finding", "level": 12, "mitre": ["T1190"],
        "conditions": {"type": "vulnerability", "severity_gte": "high"},
        "recommendation": "Patch/upgrade paket terdampak; lihat CVE pada evidence.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-DISK-001", "tier": "free", "name": "Kapasitas disk kritis",
        "category": "device_inventory", "level": 6, "mitre": [],
        "conditions": {"type": "disk", "severity_gte": "high"},
        "recommendation": "Bebaskan ruang/perluas volume; cek log yang membengkak.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-WEB-001", "name": "Laravel APP_DEBUG aktif di produksi",
        "category": "config_assessment", "level": 11, "mitre": ["T1592"],
        "conditions": {"event_type": "app_debug_enabled"},
        "recommendation": "Set APP_DEBUG=false & APP_ENV=production; jangan ekspos stack trace.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-WEB-002", "name": "APP_KEY Laravel kosong",
        "category": "config_assessment", "level": 10, "mitre": ["T1552"],
        "conditions": {"event_type": "app_key_missing"},
        "recommendation": "Jalankan `php artisan key:generate` — enkripsi & session rentan.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-WEB-003", "name": "Password database lemah/kosong",
        "category": "config_assessment", "level": 11, "mitre": ["T1078"],
        "conditions": {"event_type": "weak_db_password"},
        "recommendation": "Gunakan password DB kuat & unik; batasi akses jaringan DB.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-WEB-004", "name": "Secret terekspos ke client (NEXT_PUBLIC_*)",
        "category": "config_assessment", "level": 12, "mitre": ["T1552.001"],
        "conditions": {"event_type": "public_secret_exposed"},
        "recommendation": "Pindahkan rahasia ke server-side env; NEXT_PUBLIC_* terbundel ke browser.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-WEB-005", "name": "Direktori .git terekspos di webroot",
        "category": "config_assessment", "level": 12, "mitre": ["T1083"],
        "conditions": {"event_type": "git_exposed"},
        "recommendation": "Pindahkan .git keluar dari webroot; blokir akses /.git.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-WEB-006", "name": "Source map terekspos di produksi",
        "category": "config_assessment", "level": 6, "mitre": ["T1592"],
        "conditions": {"event_type": "sourcemap_exposed"},
        "recommendation": "Nonaktifkan source map produksi (devtool:false / sourcemap:false).",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-WEB-007", "name": "Aplikasi web berjalan mode non-produksi",
        "category": "config_assessment", "level": 7, "mitre": ["T1592"],
        "conditions": {"event_type": "app_env_nonprod"},
        "recommendation": "Set APP_ENV/NODE_ENV=production untuk deployment live.",
        "response": ["notify"],
    },
    # ---- Log Monitoring (ala-Wazuh) ----
    {
        "id": "NEXUS-LOG-001", "name": "Pola serangan web pada request (SQLi/XSS/traversal)",
        "category": "web_activity", "level": 13, "mitre": ["T1190", "T1059"],
        "conditions": {"event_type": "web_attack"},
        "recommendation": "Blokir IP sumber, periksa WAF, validasi/escape input, audit endpoint.",
        "response": ["notify", "create_incident"],
    },
    {
        "id": "NEXUS-LOG-002", "name": "Scanner/recon terdeteksi di log akses web",
        "category": "web_activity", "level": 8, "mitre": ["T1595"],
        "conditions": {"event_type": "scanner_detected"},
        "recommendation": "Rate-limit/blokir pemindai; pastikan tak ada endpoint sensitif terekspos.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-LOG-003", "name": "Exception Laravel di log produksi",
        "category": "application", "level": 9, "mitre": ["T1190"],
        "conditions": {"event_type": "app_exception"},
        "recommendation": "Selidiki error; jangan tampilkan trace ke publik; perbaiki bug.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-LOG-004", "name": "Lonjakan error server (5xx) dari log web",
        "category": "web_activity", "level": 5, "mitre": [],
        "conditions": {"event_type": "server_error"},
        "recommendation": "Cek kesehatan backend/DB; pantau ketersediaan layanan.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-LOG-005", "name": "Login gagal terdeteksi di log (brute-force)",
        "category": "authentication", "level": 7, "mitre": ["T1110"],
        "conditions": {"event_type": "log_failed_login"},
        "recommendation": "Terapkan fail2ban/rate-limit; audit akun & sumber IP.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-LOG-006", "name": "Lonjakan CSRF 419 (kemungkinan tampering)",
        "category": "web_activity", "level": 5, "mitre": ["T1592"],
        "conditions": {"event_type": "csrf"},
        "recommendation": "Periksa sesi/cookie & kemungkinan manipulasi form/callback.",
        "response": ["notify"],
    },
    {
        "id": "NEXUS-PROC-001", "name": "Proses mencurigakan berjalan di endpoint",
        "category": "process_activity", "level": 12, "mitre": ["T1059", "T1571"],
        "conditions": {"event_type": "suspicious_process"},
        "recommendation": "Isolasi host, hentikan proses, audit persistensi & jalur masuk.",
        "response": ["notify", "create_incident"],
    },
]

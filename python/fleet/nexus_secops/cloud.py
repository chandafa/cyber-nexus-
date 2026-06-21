# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/cloud.py
"""
Cloud Security (CSPM) untuk Nexus — Cloud Security Posture Management.

Mengevaluasi konfigurasi sumber daya cloud NYATA terhadap aturan keamanan gaya
CIS Benchmark (S3 publik, security group 0.0.0.0/0, root tanpa MFA, RDS publik,
volume tak terenkripsi, kebijakan IAM wildcard). Temuan dialirkan ke pipeline
SecOps (event cloud_finding → rule NEXUS-CLOUD-001 → alert → XDR/SOAR/AI) sehingga
risiko cloud berdampingan dgn telemetri endpoint — inilah inti "Cloud Security"
pada Cortex XDR / Defender for Cloud.

NYATA, bukan demo:
  • evaluate() menilai konfigurasi sumber daya yang BENAR-BENAR Anda berikan
    (dari inventori cloud / collector), bukan data karangan;
  • import_prowler() mem-parse keluaran Prowler ASLI (modul desktop cloud_checker
    sudah membungkus Prowler untuk AWS/GCP/Azure);
  • tanpa konfigurasi cloud → kosong (deployment nyata menyambungkan akun cloud).

Tabel: cloud_findings (temuan postur cloud).
"""
import json
import sqlite3
import uuid

from nexus_common import protocol as fc

SEVERITIES = ("info", "low", "medium", "high", "critical")
_ADMIN_PORTS = {22, 3389, 23, 5985, 5986}


def _conn():
    c = sqlite3.connect(fc.manager_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    return c


def ensure_tables(c):
    """Buat tabel CSPM pada koneksi `c` (tanpa commit)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS cloud_findings (
            id TEXT PRIMARY KEY, ts INTEGER, provider TEXT, account TEXT,
            check_id TEXT, title TEXT, severity TEXT, resource TEXT, resource_type TEXT,
            remediation TEXT, compliance TEXT, status TEXT DEFAULT 'open',
            tenant_id TEXT DEFAULT 'default'
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_key
            ON cloud_findings(provider, account, check_id, resource, tenant_id);
        CREATE INDEX IF NOT EXISTS idx_cloud_ts ON cloud_findings(ts DESC);
        """
    )


def init_db():
    c = _conn()
    ensure_tables(c)
    c.commit(); c.close()


# --------------------------------------------------------------------------- checks (CIS-style)
def _f(check_id, title, severity, res, rtype, remediation, compliance):
    return {"check_id": check_id, "title": title, "severity": severity,
            "resource": res, "resource_type": rtype, "remediation": remediation,
            "compliance": compliance}


def _check_resource(r):
    """Jalankan check CIS-style pada satu sumber daya cloud. Mengembalikan temuan."""
    out = []
    t = (r.get("type") or "").lower()
    rid = r.get("id") or r.get("name") or "?"

    if t in ("s3_bucket", "bucket", "storage"):
        if r.get("public") or r.get("public_access"):
            out.append(_f("CLOUD-S3-PUBLIC", "Bucket penyimpanan dapat diakses publik",
                          "critical", rid, "storage",
                          "Blokir akses publik bucket; gunakan kebijakan least-privilege.",
                          "CIS 2.1.5"))
        if r.get("encryption") is False:
            out.append(_f("CLOUD-S3-ENCRYPT", "Bucket tanpa enkripsi at-rest", "medium",
                          rid, "storage", "Aktifkan enkripsi default (SSE-KMS/SSE-S3).",
                          "CIS 2.1.1"))
        if r.get("logging") is False:
            out.append(_f("CLOUD-S3-LOG", "Bucket tanpa access logging", "low", rid,
                          "storage", "Aktifkan server access logging.", "CIS 2.6"))

    elif t in ("security_group", "firewall", "nsg"):
        for ing in (r.get("ingress") or []):
            cidr = str(ing.get("cidr", ""))
            port = ing.get("port")
            if cidr in ("0.0.0.0/0", "::/0"):
                if port in (-1, "all", "*", None) or str(port).lower() == "all":
                    out.append(_f("CLOUD-SG-ALL", "Security group terbuka ke dunia (semua port)",
                                  "critical", rid, "network",
                                  "Batasi sumber ke IP/VPN tepercaya; hapus 0.0.0.0/0.",
                                  "CIS 5.2"))
                elif _to_int(port) in _ADMIN_PORTS:
                    out.append(_f("CLOUD-SG-ADMIN", f"Port admin {port} terekspos ke 0.0.0.0/0",
                                  "high", rid, "network",
                                  "Batasi SSH/RDP ke bastion/VPN; gunakan allowlist.",
                                  "CIS 5.2"))

    elif t in ("iam_user", "iam", "user"):
        is_root = str(rid).lower() == "root" or r.get("root")
        if r.get("mfa") is False:
            out.append(_f("CLOUD-IAM-MFA",
                          ("Akun ROOT tanpa MFA" if is_root else "Pengguna IAM tanpa MFA"),
                          ("critical" if is_root else "high"), rid, "identity",
                          "Aktifkan MFA; untuk root gunakan MFA hardware.",
                          "CIS 1.5" if is_root else "CIS 1.10"))
        if r.get("admin") and (r.get("policy") == "*:*" or r.get("wildcard")):
            out.append(_f("CLOUD-IAM-ADMIN", "Kebijakan IAM dgn hak wildcard (*:*)", "high",
                          rid, "identity", "Terapkan least-privilege; hindari Action/Resource '*'.",
                          "CIS 1.16"))
        if is_root and (r.get("access_keys") or r.get("has_access_key")):
            out.append(_f("CLOUD-IAM-ROOTKEY", "Akun root memiliki access key aktif", "critical",
                          rid, "identity", "Hapus access key root; gunakan IAM user/role.",
                          "CIS 1.4"))

    elif t in ("rds", "database", "db"):
        if r.get("public") or r.get("publicly_accessible"):
            out.append(_f("CLOUD-DB-PUBLIC", "Basis data dapat diakses publik", "critical",
                          rid, "database", "Tempatkan DB di subnet privat; matikan akses publik.",
                          "CIS 2.3.3"))
        if r.get("encryption") is False:
            out.append(_f("CLOUD-DB-ENCRYPT", "Basis data tanpa enkripsi at-rest", "high",
                          rid, "database", "Aktifkan enkripsi storage (KMS).", "CIS 2.3.1"))

    elif t in ("ebs_volume", "disk", "volume"):
        if r.get("encryption") is False:
            out.append(_f("CLOUD-VOL-ENCRYPT", "Volume disk tanpa enkripsi", "medium", rid,
                          "compute", "Aktifkan enkripsi volume (default EBS encryption).",
                          "CIS 2.2.1"))

    elif t in ("account", "logging", "cloudtrail"):
        if r.get("cloudtrail") is False or r.get("audit_log") is False:
            out.append(_f("CLOUD-LOG-OFF", "Audit logging (CloudTrail) nonaktif", "high", rid,
                          "account", "Aktifkan CloudTrail multi-region + validasi log.",
                          "CIS 3.1"))
    return out


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return -999


def evaluate(resources, provider="aws", account="default"):
    """Nilai daftar konfigurasi sumber daya cloud → temuan CSPM (murni, NYATA)."""
    findings = []
    for r in resources or []:
        for f in _check_resource(r or {}):
            f["provider"] = provider
            f["account"] = account
            findings.append(f)
    return {"ok": True, "module": "nexus_secops", "evaluated": len(resources or []),
            "findings": findings}


# --------------------------------------------------------------------------- Prowler import
_PROWLER_KEYS = {
    "status": ("Status", "status", "status_code", "result"),
    "severity": ("Severity", "severity", "severity_label"),
    "check_id": ("CheckID", "check_id", "Check_ID", "control_id"),
    "title": ("CheckTitle", "check_title", "Check_Title", "title", "finding_info"),
    "resource": ("ResourceId", "resource_id", "Resource_Id", "resource_uid", "resource"),
    "remediation": ("Remediation", "remediation", "remediation_recommendation_text"),
    "provider": ("Provider", "provider", "cloud_provider"),
    "account": ("AccountId", "account_id", "Account_Id", "account_uid"),
    "region": ("Region", "region"),
}


def _pick(d, key):
    for k in _PROWLER_KEYS[key]:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return ""


def import_prowler(data, default_provider="aws", default_account="default"):
    """Parse keluaran Prowler NYATA (list dict, format native/ASFF) → temuan FAIL."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception as e:
            return {"ok": False, "error": f"JSON Prowler tak valid: {e}"}
    items = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
    findings = []
    for d in items:
        if not isinstance(d, dict):
            continue
        status = str(_pick(d, "status")).upper()
        if status and status not in ("FAIL", "FAILED", "ALARM"):
            continue                          # hanya temuan gagal (risiko)
        sev = str(_pick(d, "severity") or "medium").lower()
        sev = sev if sev in SEVERITIES else "medium"
        findings.append({
            "check_id": str(_pick(d, "check_id") or "PROWLER"),
            "title": str(_pick(d, "title") or "Temuan Prowler"),
            "severity": sev, "resource": str(_pick(d, "resource") or "?"),
            "resource_type": "cloud",
            "remediation": str(_pick(d, "remediation") or "Lihat panduan Prowler/CIS."),
            "compliance": "Prowler",
            "provider": str(_pick(d, "provider") or default_provider),
            "account": str(_pick(d, "account") or default_account),
            "region": str(_pick(d, "region") or ""),
        })
    return {"ok": True, "module": "nexus_secops", "findings": findings, "imported": len(findings)}


# --------------------------------------------------------------------------- store / query
def store_findings(findings, tenant="default", conn=None):
    """Simpan temuan CSPM (dedup per provider+account+check+resource)."""
    own = conn is None
    c = conn or _conn()
    if own:
        ensure_tables(c)
    now = fc.now()
    n = 0
    for f in findings or []:
        c.execute(
            "INSERT INTO cloud_findings(id,ts,provider,account,check_id,title,severity,"
            "resource,resource_type,remediation,compliance,status,tenant_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,'open',?) "
            "ON CONFLICT(provider,account,check_id,resource,tenant_id) DO UPDATE SET "
            "ts=excluded.ts, severity=excluded.severity, title=excluded.title, status='open'",
            ("cf_" + uuid.uuid4().hex[:12], now, f.get("provider", "aws"),
             f.get("account", "default"), f["check_id"], f["title"], f["severity"],
             f["resource"], f.get("resource_type", "cloud"), f.get("remediation", ""),
             f.get("compliance", ""), tenant))
        n += 1
    if own:
        c.commit(); c.close()
    return n


def list_findings(provider="", severity="", status="", limit=500, tenant="default"):
    init_db()
    c = _conn()
    q = "SELECT * FROM cloud_findings WHERE COALESCE(tenant_id,'default')=?"
    params = [tenant]
    if provider:
        q += " AND provider=?"; params.append(provider)
    if severity:
        q += " AND severity=?"; params.append(severity)
    if status:
        q += " AND status=?"; params.append(status)
    q += " ORDER BY ts DESC LIMIT ?"; params.append(int(limit))
    rows = c.execute(q, params).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "findings": [{
        "id": r["id"], "ts_iso": fc.iso(r["ts"]), "provider": r["provider"],
        "account": r["account"], "check_id": r["check_id"], "title": r["title"],
        "severity": r["severity"], "resource": r["resource"],
        "resource_type": r["resource_type"], "remediation": r["remediation"],
        "compliance": r["compliance"], "status": r["status"],
    } for r in rows]}


def posture(tenant="default"):
    """Skor postur cloud 0-100 (per provider + keseluruhan) dari temuan terbuka."""
    init_db()
    c = _conn()
    rows = c.execute("SELECT provider, severity FROM cloud_findings WHERE status!='resolved' "
                     "AND COALESCE(tenant_id,'default')=?", (tenant,)).fetchall()
    c.close()
    pen = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}
    providers, overall = {}, 100.0
    for r in rows:
        p = pen.get(r["severity"], 2)
        providers[r["provider"]] = max(0.0, providers.get(r["provider"], 100.0) - p)
        overall = max(0.0, overall - p * 0.7)
    label = lambda s: ("baik" if s >= 80 else "perlu perhatian" if s >= 50 else "kritis")
    return {"ok": True, "module": "nexus_secops", "overall": round(overall),
            "label": label(overall), "by_provider": {k: round(v) for k, v in providers.items()},
            "open_findings": len(rows)}


def stats(tenant="default"):
    init_db()
    c = _conn()
    by_sev = {s: 0 for s in SEVERITIES}
    for r in c.execute("SELECT severity, COUNT(*) n FROM cloud_findings WHERE "
                       "COALESCE(tenant_id,'default')=? GROUP BY severity", (tenant,)).fetchall():
        if r["severity"] in by_sev:
            by_sev[r["severity"]] = r["n"]
    total = sum(by_sev.values())
    c.close()
    return {"ok": True, "module": "nexus_secops", "total": total, "by_severity": by_sev}

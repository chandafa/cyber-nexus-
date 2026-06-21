#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji nexus_secops.cloud — CSPM (Cloud Security Posture Management).

Memverifikasi: evaluasi konfigurasi cloud NYATA thd aturan CIS, import keluaran
Prowler asli, penyimpanan+dedup+postur, dan jalur end-to-end manager
(cloud_scan → event cloud_finding → alert NEXUS-CLOUD-001 → XDR/SOAR/AI).
"""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)
sys.path.insert(0, os.path.join(PYDIR, "fleet"))

_tmp = tempfile.mkdtemp(prefix="nexus_cloud_test_")
os.environ["NEXUS_FLEET_DB"] = os.path.join(_tmp, "mgr.db")

from nexus_manager import server as mgr        # noqa: E402
from nexus_secops import cloud                 # noqa: E402

FAILED = []

RESOURCES = [
    {"type": "s3_bucket", "id": "public-bucket", "public": True, "encryption": False},
    {"type": "security_group", "id": "sg-open", "ingress": [{"cidr": "0.0.0.0/0", "port": "all"}]},
    {"type": "security_group", "id": "sg-ssh", "ingress": [{"cidr": "0.0.0.0/0", "port": 22}]},
    {"type": "iam_user", "id": "root", "mfa": False, "access_keys": True},
    {"type": "rds", "id": "db-prod", "public": True, "encryption": False},
    {"type": "ebs_volume", "id": "vol-1", "encryption": False},
    {"type": "s3_bucket", "id": "good-bucket", "public": False, "encryption": True},  # bersih
]


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def main():
    mgr.init_db()

    print("== Evaluasi konfigurasi cloud (CIS) ==")
    res = cloud.evaluate(RESOURCES, provider="aws", account="123456789012")
    fids = {f["check_id"] for f in res["findings"]}
    check("S3 publik → CLOUD-S3-PUBLIC (kritis)", "CLOUD-S3-PUBLIC" in fids)
    check("SG terbuka semua port → CLOUD-SG-ALL", "CLOUD-SG-ALL" in fids)
    check("SG SSH 0.0.0.0/0 → CLOUD-SG-ADMIN", "CLOUD-SG-ADMIN" in fids)
    check("root tanpa MFA → CLOUD-IAM-MFA", "CLOUD-IAM-MFA" in fids)
    check("root access key → CLOUD-IAM-ROOTKEY (kritis)", "CLOUD-IAM-ROOTKEY" in fids)
    check("RDS publik → CLOUD-DB-PUBLIC (kritis)", "CLOUD-DB-PUBLIC" in fids)
    check("volume tak terenkripsi → CLOUD-VOL-ENCRYPT", "CLOUD-VOL-ENCRYPT" in fids)
    root_mfa = [f for f in res["findings"] if f["check_id"] == "CLOUD-IAM-MFA"][0]
    check("root tanpa MFA dinilai kritis", root_mfa["severity"] == "critical")
    check("bucket bersih tak menghasilkan temuan",
          not any(f["resource"] == "good-bucket" for f in res["findings"]))
    check("temuan menyertakan remediasi & compliance",
          all(f.get("remediation") and f.get("compliance") for f in res["findings"]))

    print("== Import keluaran Prowler NYATA (format native) ==")
    prowler = [
        {"Status": "FAIL", "Severity": "critical", "CheckID": "iam_root_mfa",
         "CheckTitle": "Ensure MFA on root", "ResourceId": "root", "Provider": "aws",
         "AccountId": "123456789012", "Remediation": "Enable MFA"},
        {"Status": "PASS", "Severity": "high", "CheckID": "s3_encryption",
         "CheckTitle": "S3 encrypted", "ResourceId": "bucket-x"},   # PASS → diabaikan
        {"Status": "FAIL", "Severity": "high", "CheckID": "ec2_public_ip",
         "CheckTitle": "EC2 has public IP", "ResourceId": "i-0abc"},
    ]
    imp = cloud.import_prowler(prowler)
    check("hanya temuan FAIL diimpor (2 dari 3)", imp["imported"] == 2)
    check("PASS tidak diimpor",
          all(f["check_id"] != "s3_encryption" for f in imp["findings"]))

    print("== Simpan + dedup + list + postur ==")
    cloud.store_findings(res["findings"])
    cloud.store_findings(res["findings"])           # ulang → dedup, tak menggandakan
    lst = cloud.list_findings()["findings"]
    check("temuan tersimpan", len(lst) >= 7)
    n_s3 = len([f for f in lst if f["check_id"] == "CLOUD-S3-PUBLIC"])
    check("dedup: S3-PUBLIC hanya 1 baris", n_s3 == 1)
    pos = cloud.posture()
    check("postur < 100 (ada temuan)", pos["overall"] < 100)
    check("postur punya skor per-provider", "aws" in pos["by_provider"])

    print("== End-to-end manager: cloud_scan → alert NEXUS-CLOUD-001 ==")
    out = mgr.cloud_scan(resources=RESOURCES, provider="aws", account="123456789012")
    check("cloud_scan sukses dgn temuan", out["ok"] and out["findings"] >= 7)
    alerts = mgr.list_alerts(500)["alerts"]
    ca = [a for a in alerts if a["rule_id"] == "NEXUS-CLOUD-001"]
    check("alert NEXUS-CLOUD-001 terbuat (high/critical)", len(ca) >= 1)
    # severity_gte high → temuan medium (ebs/s3-encrypt) TIDAK memicu alert
    check("alert hanya utk high/critical",
          all(a["severity"] in ("high", "critical") for a in ca))
    check("postur dikembalikan oleh scan", out["posture"]["overall"] < 100)

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES CLOUD LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

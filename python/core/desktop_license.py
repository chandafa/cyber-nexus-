# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/desktop_license.py
"""
Gerbang lisensi sisi-DESKTOP (GUI).

Manager fleet sudah menegakkan lisensi di sisi server (nexus_manager/server.py).
Namun beberapa fitur Pro berjalan sebagai modul desktop murni lewat runner.py
(mis. Report Generator) dan TIDAK melewati gerbang manager. Modul ini menutup
celah itu:

  - Menyimpan/membaca token lisensi desktop di ~/.nexus/desktop_license.txt
  - Menyediakan entitlements()/status()/apply()/clear()
  - guard(command): menolak command Pro sebelum dieksekusi bila tak berhak.

Sumber kebenaran verifikasi = paket kanonik nexus_common.license (Ed25519).
Satu file lisensi ini juga dipakai oleh manager tertanam (lihat bootstrap_env()).
"""
import hashlib
import json as _json
import os
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Tambahkan folder fleet/ ke sys.path agar nexus_common bisa di-import.
_FLEET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fleet")
if _FLEET not in sys.path:
    sys.path.insert(0, _FLEET)

from nexus_common import license as licensing  # noqa: E402

# Lokasi penyimpanan key desktop.
LICENSE_DIR = os.path.join(os.path.expanduser("~"), ".nexus")
LICENSE_FILE = os.path.join(LICENSE_DIR, "desktop_license.txt")
# High-water mark waktu (anti putar-mundur jam sistem).
_HWM_FILE = os.path.join(LICENSE_DIR, ".license_hwm")

# Command runner.py (modul GUI) -> fitur yang dibutuhkan.
#   "*"        = butuh lisensi VALID apa pun (Pro/Enterprise) — model "beli Pro,
#                semua modul Pro terbuka".
#   "<nama>"   = butuh fitur spesifik (mis. "report").
# Modul Free TIDAK didaftarkan di sini (port_scan, network_scan, dns_recon,
# log_analyze, hash_tool, wordlist, security_score, dst.).
PRO_COMMANDS = {
    # Web & API
    "vuln_scan": "*",
    "ssl_audit": "*",
    "api_test": "*",
    "dir_fuzz": "*",
    # Recon lanjutan
    "network_map": "*",
    "asset_inventory": "*",
    # Offensive
    "password_audit": "*",
    "exploit_lookup": "*",
    "attack_sim": "*",
    "listener": "*",
    "wireless_scan": "*",
    # Cloud & Container
    "container_scan": "*",
    "cloud_check": "*",
    # Analisis
    "scan_diff": "*",
    # Defense
    "defense_check": "*",
    "ids_monitor": "*",
    "firewall_advisor": "*",
    "patch_advisor": "*",
    # WAF (aksi; pembacaan status/log dibiarkan agar UI tak rusak)
    "waf": "*",
    "waf_save_vhost": "*",
    "waf_delete_vhost": "*",
    "waf_save_rule": "*",
    "waf_delete_rule": "*",
    # Reporting (fitur spesifik)
    "generate_report": "report",
    # Fleet / SOC (start server + aksi tulis; pembacaan status dibiarkan)
    "manager_start": "*",
    "fleet_policy_set": "*",
    "fleet_command": "*",
    "fleet_sigma_import": "*",
    "fleet_respond": "*",
    "fleet_vulndb_set": "*",
    "fleet_notify": "*",
    "fleet_add_user": "*",
    "fleet_remove_agent": "*",
    "agent_enroll": "*",
    "agent_start": "*",
    # Scheduler
    "scheduler": "*",
}

# Label fitur (untuk pesan & UI).
FEATURE_LABELS = {
    "report": "Report Generator",
    "webaudit": "Web & App Audit",
    "sigma": "Sigma Import",
    "active_response": "Active Response",
    "advanced_rules": "Advanced Rules",
    "unlimited_agents": "Unlimited Agents",
}


# --------------------------------------------------------------------- device id
# Sumber TUNGGAL fingerprint device di nexus_common.device → GUI & fleet identik,
# sehingga 1 token device-bound berlaku untuk GUI + CLI di mesin yang sama.
from nexus_common import device as _device  # noqa: E402


def device_id() -> str:
    return _device.device_id()


# --------------------------------------------------------------------- server API
def api_base() -> str:
    """URL dasar Cloud Function: env > config bundel > kosong."""
    env = os.environ.get("NEXUS_LICENSE_API", "").strip()
    if env:
        return env.rstrip("/")
    try:
        from core import license_config
        return (getattr(license_config, "LICENSE_API_BASE", "") or "").strip().rstrip("/")
    except Exception:
        return ""


def _post(path: str, payload: dict, timeout: int = 20) -> dict:
    base = api_base()
    if not base:
        return {"ok": False, "error": "Server lisensi belum dikonfigurasi.",
                "reason": "no_api"}
    req = urllib.request.Request(
        base + path,
        data=_json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            # UA wajar — hindari Cloudflare Bot Fight memblokir 'Python-urllib'.
            "User-Agent": "Mozilla/5.0 (compatible; NexusLicense/1.1)",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return _json.loads(e.read().decode())
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}", "reason": "http_error"}
    except Exception as e:
        return {"ok": False, "error": f"Tidak bisa menghubungi server lisensi: {e}",
                "reason": "network"}


# --------------------------------------------------------------- anti clock-rollback
def _hwm() -> int:
    try:
        with open(_HWM_FILE, encoding="utf-8") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0


def _bump_hwm() -> None:
    try:
        now = int(time.time())
        if now > _hwm():
            os.makedirs(LICENSE_DIR, exist_ok=True)
            with open(_HWM_FILE, "w", encoding="utf-8") as f:
                f.write(str(now))
    except Exception:
        pass


def _effective_now() -> int:
    """Waktu efektif = max(jam sistem, HWM) — mencegah putar-mundur jam."""
    return max(int(time.time()), _hwm())


def _raw_token() -> str:
    """Token tersimpan: file lisensi, selainnya env NEXUS_LICENSE (path/string)."""
    if os.path.isfile(LICENSE_FILE):
        try:
            return open(LICENSE_FILE, encoding="utf-8").read().strip()
        except Exception:
            return ""
    env = os.environ.get("NEXUS_LICENSE", "").strip()
    if env and os.path.isfile(env):
        try:
            return open(env, encoding="utf-8").read().strip()
        except Exception:
            return ""
    return env


def bootstrap_env() -> None:
    """
    Saat runner start: bila ada file lisensi desktop & NEXUS_LICENSE belum diset,
    arahkan env ke file itu. Dengan begitu manager tertanam (yang fallback ke
    env NEXUS_LICENSE) ikut terbuka oleh key yang sama — satu key untuk semua.
    """
    try:
        if not os.environ.get("NEXUS_LICENSE") and os.path.isfile(LICENSE_FILE):
            os.environ["NEXUS_LICENSE"] = LICENSE_FILE
    except Exception:
        pass


def entitlements() -> dict:
    """
    Resolusi hak pakai dari token tersimpan, DENGAN pengikatan device & anti
    putar-mundur jam. Token tanpa field `device` (lisensi manual/enterprise)
    tetap dianggap transferable (device tidak dicek).
    """
    token = _raw_token()
    if not token:
        return licensing.free_entitlements("no_license")
    res = licensing.verify(token)
    if not res.get("valid"):
        return licensing.free_entitlements(res.get("reason", "invalid"))
    p = res.get("payload") or {}

    # Pengikatan device: bila token mencantumkan device, harus cocok.
    bound = p.get("device")
    if bound and bound != device_id():
        return licensing.free_entitlements("device_mismatch")

    # Kedaluwarsa berbasis waktu efektif (kebal putar-mundur jam).
    exp = int(p.get("expires", 0) or 0)
    if exp and _effective_now() > exp:
        return licensing.free_entitlements("expired")
    _bump_hwm()

    feats = set(p.get("features", []))
    return {
        "valid": True,
        "tier": p.get("tier", "pro"),
        "licensee": p.get("licensee", ""),
        "max_agents": None if "unlimited_agents" in feats
        else int(p.get("max_agents", licensing.FREE_MAX_AGENTS)),
        "features": feats,
        "expires": exp,
        "device": bound or "",
        "code": p.get("code", ""),
        "reason": "ok",
    }


def status() -> dict:
    e = entitlements()
    feats = sorted(e.get("features", set()))
    exp = int(e.get("expires", 0) or 0)
    days_left = max(0, (exp - int(time.time())) // 86400) if exp else None
    return {
        "module": "license",
        "tier": e.get("tier", "free"),
        "valid": bool(e.get("valid")),
        "licensee": e.get("licensee", ""),
        "features": feats,
        "feature_labels": {f: FEATURE_LABELS.get(f, f) for f in feats},
        "max_agents": e.get("max_agents"),
        "expires": exp,
        "days_left": days_left,
        "reason": e.get("reason", ""),
        "activated": bool(e.get("valid")),
        "has_file": os.path.isfile(LICENSE_FILE),
        "device_id": device_id(),
        "api_configured": bool(api_base()),
        "pro_commands": PRO_COMMANDS,
    }


def redeem(code: str) -> dict:
    """Tukar kode aktivasi di server (sekali pakai, kunci device), simpan token."""
    code = (code or "").strip().upper()
    if not code:
        return {"module": "license", "ok": False, "error": "Kode aktivasi kosong."}
    res = _post("/redeem_license", {"code": code, "deviceId": device_id()})
    if not res.get("ok"):
        return {"module": "license", "ok": False,
                "error": res.get("error", "Aktivasi gagal."),
                "reason": res.get("reason", "")}
    token = (res.get("token") or "").strip()
    v = licensing.verify(token)
    if not v.get("valid"):
        return {"module": "license", "ok": False,
                "error": "Server mengirim entitlement tidak valid."}
    # Pastikan device pada token = device ini (pertahanan ganda).
    if (v.get("payload") or {}).get("device") not in ("", None, device_id()):
        return {"module": "license", "ok": False, "error": "Entitlement bukan untuk perangkat ini."}
    try:
        os.makedirs(LICENSE_DIR, exist_ok=True)
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            f.write(token + "\n")
        _bump_hwm()
    except Exception as ex:
        return {"module": "license", "ok": False, "error": f"Gagal menyimpan lisensi: {ex}"}
    out = status()
    out["ok"] = True
    return out


def validate() -> dict:
    """Cek status terkini ke server (deteksi revoke/expired). Best-effort."""
    token = _raw_token()
    if not token:
        return status()
    v = licensing.verify(token)
    p = v.get("payload") or {}
    code = p.get("code")
    if not code:
        return status()  # token manual tanpa kode online
    res = _post("/validate_license", {"code": code, "deviceId": device_id()})
    st = res.get("status")
    if st in ("revoked", "expired", "used_other_device", "invalid"):
        clear()
        out = status()
        out["revoked_reason"] = st
        return out
    return status()


def apply(token_or_path: str) -> dict:
    """Verifikasi token (string atau path file) lalu simpan. Tolak bila invalid."""
    token = (token_or_path or "").strip()
    if not token:
        return {"module": "license", "ok": False, "error": "Token lisensi kosong."}
    # Boleh berupa path ke file .license
    if os.path.isfile(token):
        try:
            token = open(token, encoding="utf-8").read().strip()
        except Exception as ex:
            return {"module": "license", "ok": False, "error": f"Gagal membaca file lisensi: {ex}"}
    res = licensing.verify(token)
    if not res.get("valid"):
        reason = res.get("reason", "invalid")
        msg = {
            "no_vendor_pubkey": "Public key vendor tidak ter-bundle — tidak bisa memverifikasi.",
            "malformed": "Format token salah.",
            "bad_signature": "Tanda tangan tidak valid (token bukan dari vendor).",
            "bad_payload": "Isi token rusak.",
            "expired": "Lisensi sudah kedaluwarsa.",
        }.get(reason, f"Lisensi tidak valid: {reason}")
        return {"module": "license", "ok": False, "error": msg, "reason": reason}
    try:
        os.makedirs(LICENSE_DIR, exist_ok=True)
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            f.write(token + "\n")
    except Exception as ex:
        return {"module": "license", "ok": False, "error": f"Gagal menyimpan lisensi: {ex}"}
    out = status()
    out["ok"] = True
    return out


def clear() -> dict:
    try:
        if os.path.isfile(LICENSE_FILE):
            os.remove(LICENSE_FILE)
    except Exception as ex:
        return {"module": "license", "ok": False, "error": f"Gagal menghapus lisensi: {ex}"}
    out = status()
    out["ok"] = True
    return out


def guard(command: str):
    """
    Kembalikan dict 'locked' bila command butuh fitur Pro tapi edisi sekarang
    tidak berhak; kembalikan None bila boleh lanjut.
    """
    feature = PRO_COMMANDS.get(command)
    if not feature:
        return None
    e = entitlements()
    # "*" = cukup punya lisensi valid apa pun; selain itu cek fitur spesifik.
    entitled = bool(e.get("valid")) if feature == "*" else licensing.has(e, feature)
    if entitled:
        return None
    label = "Pro" if feature == "*" else FEATURE_LABELS.get(feature, feature)
    tier = str(e.get("tier", "free")).upper()
    head = "Modul ini hanya untuk edisi Pro/Enterprise" if feature == "*" \
        else f"Fitur '{label}' terkunci"
    return {
        "module": "license",
        "ok": False,
        "locked": True,
        "feature": feature,
        "feature_label": label,
        "tier": e.get("tier", "free"),
        "valid": bool(e.get("valid")),
        "reason": e.get("reason", "no_license"),
        "error": (f"{head}. Edisi saat ini: {tier}. "
                  f"Unggah lisensi di Settings → Lisensi untuk membukanya."),
    }

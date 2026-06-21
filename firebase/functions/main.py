# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# firebase/functions/main.py
"""
Cloud Functions (Python, 2nd gen) untuk aktivasi lisensi Nexus.

  redeem_license   POST {code, deviceId}  -> entitlement bertanda tangan (sekali pakai, kunci device)
  validate_license POST {code, deviceId}  -> status terkini (active/expired/revoked/...)

Keamanan:
  - Semua tulis/baca koleksi `licenses` HANYA lewat function ini (Firestore rules
    menolak akses klien langsung).
  - Redemption ATOMIK (transaksi) -> tak bisa dipakai dua kali / dua device.
  - Private seed Ed25519 dari Secret Manager (VENDOR_SEED) -> tak pernah di app.
"""
import json
import time

from firebase_admin import initialize_app, firestore
from firebase_functions import https_fn, options
from firebase_functions.params import SecretParam
from google.cloud import firestore as gcf

import entitlement

initialize_app()

REGION = "asia-southeast2"  # Jakarta — ganti bila perlu
VENDOR_SEED = SecretParam("VENDOR_SEED")  # set: firebase functions:secrets:set VENDOR_SEED

_COLL = "licenses"


def _json(payload: dict, status: int = 200) -> https_fn.Response:
    return https_fn.Response(
        json.dumps(payload), status=status, mimetype="application/json"
    )


def _read(req: https_fn.Request):
    if req.method != "POST":
        return None, _json({"ok": False, "error": "method_not_allowed"}, 405)
    data = req.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip().upper()
    device = str(data.get("deviceId", "")).strip()
    if not code or not device:
        return None, _json({"ok": False, "error": "missing_code_or_device",
                            "reason": "missing"}, 400)
    return (code, device), None


@https_fn.on_request(
    region=REGION,
    secrets=[VENDOR_SEED],
    cors=options.CorsOptions(cors_origins="*", cors_methods=["POST"]),
)
def redeem_license(req: https_fn.Request) -> https_fn.Response:
    parsed, err = _read(req)
    if err:
        return err
    code, device = parsed

    db = firestore.client()
    ref = db.collection(_COLL).document(code)
    transaction = db.transaction()

    @gcf.transactional
    def _redeem(txn) -> dict:
        snap = ref.get(transaction=txn)
        if not snap.exists:
            return {"ok": False, "reason": "invalid_code"}
        d = snap.to_dict() or {}
        if d.get("status") == "revoked":
            return {"ok": False, "reason": "revoked"}
        now = int(time.time())
        if d.get("status") == "redeemed":
            # Re-aktivasi di DEVICE YANG SAMA boleh (mis. install ulang).
            if d.get("deviceId") != device:
                return {"ok": False, "reason": "used_other_device"}
            expires = int(d.get("expiresAt") or 0)
            if expires and now > expires:
                return {"ok": False, "reason": "expired"}
            return {"ok": True, "tier": d.get("tier", "pro"), "expires": expires,
                    "licensee": d.get("licensee", "")}
        # Pertama kali: kunci ke device ini + set masa berlaku.
        days = int(d.get("durationDays", 30))
        expires = now + days * 86400
        txn.update(ref, {
            "status": "redeemed",
            "deviceId": device,
            "redeemedAt": now,
            "expiresAt": expires,
        })
        return {"ok": True, "tier": d.get("tier", "pro"), "expires": expires,
                "licensee": d.get("licensee", "")}

    result = _redeem(transaction)
    if not result.get("ok"):
        msg = {
            "invalid_code": "Kode aktivasi tidak ditemukan.",
            "revoked": "Kode ini telah dicabut.",
            "used_other_device": "Kode sudah dipakai di perangkat lain.",
            "expired": "Kode sudah kedaluwarsa.",
        }.get(result["reason"], "Aktivasi gagal.")
        return _json({"ok": False, "reason": result["reason"], "error": msg}, 409)

    token = entitlement.issue(
        VENDOR_SEED.value,
        tier=result["tier"],
        device=device,
        code=code,
        expires=result["expires"],
        licensee=result.get("licensee", ""),
    )
    return _json({
        "ok": True,
        "token": token,
        "tier": result["tier"],
        "expiresAt": result["expires"],
    })


@https_fn.on_request(
    region=REGION,
    cors=options.CorsOptions(cors_origins="*", cors_methods=["POST"]),
)
def validate_license(req: https_fn.Request) -> https_fn.Response:
    parsed, err = _read(req)
    if err:
        return err
    code, device = parsed

    db = firestore.client()
    snap = db.collection(_COLL).document(code).get()
    if not snap.exists:
        return _json({"ok": True, "status": "invalid"})
    d = snap.to_dict() or {}
    status = d.get("status", "unused")
    if status == "revoked":
        return _json({"ok": True, "status": "revoked"})
    if status != "redeemed":
        return _json({"ok": True, "status": "unused"})
    if d.get("deviceId") != device:
        return _json({"ok": True, "status": "used_other_device"})
    now = int(time.time())
    expires = int(d.get("expiresAt") or 0)
    if expires and now > expires:
        return _json({"ok": True, "status": "expired", "expiresAt": expires})
    return _json({"ok": True, "status": "active", "tier": d.get("tier", "pro"),
                  "expiresAt": expires})

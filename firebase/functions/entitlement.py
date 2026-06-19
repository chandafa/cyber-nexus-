# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# firebase/functions/entitlement.py
"""
Penerbitan entitlement bertanda-tangan Ed25519 — SAMA persis dengan format yang
diverifikasi app desktop (nexus_common.license). Berjalan di Cloud Function;
private seed diambil dari Secret Manager, TIDAK pernah ada di app/generator.

token = base64url(payload_json) + "." + base64url(signature)
payload kanonik: json.dumps(sort_keys=True, separators=(",", ":"))
"""
import base64
import json
import os
import time

import _ed25519 as ed

# Selaras dengan nexus_common.license.TIER_FEATURES.
_PRO = ["sigma", "active_response", "advanced_rules", "webaudit", "report"]
TIER_FEATURES = {
    "free": [],
    "pro": _PRO,
    "enterprise": ["unlimited_agents"] + _PRO,
}
DEFAULT_MAX_AGENTS = {"free": 2, "pro": 50, "enterprise": 0}


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def issue(seed_hex: str, *, tier: str, device: str, code: str,
          expires: int, licensee: str = "", jti: str = "") -> str:
    """Terbitkan entitlement device-bound bertanda tangan."""
    seed = bytes.fromhex(seed_hex.strip())
    pk = ed.publickey(seed)
    feats = TIER_FEATURES.get(tier, [])
    payload = {
        "id": jti or _b64(os.urandom(8)),
        "tier": tier,
        "device": device,           # terkunci ke 1 device
        "code": code,               # kode yang ditukar (audit/validate)
        "licensee": licensee,
        "features": feats,
        "max_agents": DEFAULT_MAX_AGENTS.get(tier, 2),
        "issued": int(time.time()),
        "expires": int(expires),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = ed.signature(raw, seed, pk)
    return _b64(raw) + "." + _b64(sig)


def pubkey_hex(seed_hex: str) -> str:
    return ed.publickey(bytes.fromhex(seed_hex.strip())).hex()

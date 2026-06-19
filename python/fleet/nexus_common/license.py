# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_common/license.py
"""
Lisensi Nexus (model freemium / open-core).

- Vendor (Anda) memegang **private key**; menerbitkan token lisensi per pelanggan.
- Manager memegang **public key** (ter-bundle) untuk memverifikasi.
- Tanpa lisensi valid -> tier **FREE** (terbatas). Dengan lisensi -> fitur dibuka.

Token = base64url(payload_json) + "." + base64url(signature_ed25519).
payload = {id, licensee, tier, features[], max_agents, issued, expires}

Catatan kejujuran (open-core): karena sebagian kode publik, gerbang ini menahan
penyalahgunaan kasual, BUKAN reverse-engineer ahli. Perlindungan kuat = simpan
modul premium secara privat / jalankan sisi-server. Lihat README.
"""
import base64
import json
import os
import time

from nexus_common import _ed25519 as ed

# ----- definisi tier & fitur -----
FEATURES_ALL = ["unlimited_agents", "sigma", "active_response",
                "advanced_rules", "webaudit", "report"]
_PRO = ["sigma", "active_response", "advanced_rules", "webaudit", "report"]
TIER_FEATURES = {
    "free": [],
    "pro": _PRO,                          # seat-terbatas (max_agents dihormati)
    "enterprise": ["unlimited_agents"] + _PRO,
}
FREE_MAX_AGENTS = 2

_VENDOR_PUBKEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "vendor_public.key")


# --------------------------------------------------------------------------- keys
def generate_keypair():
    """Kembalikan (seed_hex, pubkey_hex). Vendor menyimpan seed (RAHASIA)."""
    seed = os.urandom(32)
    pk = ed.publickey(seed)
    return seed.hex(), pk.hex()


def vendor_pubkey() -> str:
    """Public key vendor (hex): env NEXUS_VENDOR_PUBKEY > file bundle > kosong."""
    env = os.environ.get("NEXUS_VENDOR_PUBKEY", "").strip()
    if env:
        return env
    try:
        with open(_VENDOR_PUBKEY_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def save_vendor_pubkey(pk_hex: str):
    with open(_VENDOR_PUBKEY_FILE, "w", encoding="utf-8") as f:
        f.write(pk_hex.strip() + "\n")


# --------------------------------------------------------------------------- token
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(seed_hex: str, licensee: str, tier: str = "pro", days: int = 365,
          max_agents: int = 50, features=None, issued_ts: int = None) -> str:
    """Terbitkan token lisensi (vendor; butuh seed/private key)."""
    seed = bytes.fromhex(seed_hex)
    pk = ed.publickey(seed)
    now = int(issued_ts or time.time())
    payload = {
        "id": _b64(os.urandom(6)),
        "licensee": licensee,
        "tier": tier,
        "features": features if features is not None else TIER_FEATURES.get(tier, []),
        "max_agents": max_agents,
        "issued": now,
        "expires": now + days * 86400 if days else 0,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = ed.signature(raw, seed, pk)
    return _b64(raw) + "." + _b64(sig)


def verify(token: str, pubkey_hex: str = "") -> dict:
    """Verifikasi token. Kembalikan {valid, payload, reason}."""
    pubkey_hex = pubkey_hex or vendor_pubkey()
    if not pubkey_hex:
        return {"valid": False, "reason": "no_vendor_pubkey", "payload": None}
    try:
        raw_b64, sig_b64 = token.strip().split(".", 1)
        raw = _unb64(raw_b64)
        sig = _unb64(sig_b64)
    except Exception:
        return {"valid": False, "reason": "malformed", "payload": None}
    if not ed.checkvalid(sig, raw, bytes.fromhex(pubkey_hex)):
        return {"valid": False, "reason": "bad_signature", "payload": None}
    try:
        payload = json.loads(raw)
    except Exception:
        return {"valid": False, "reason": "bad_payload", "payload": None}
    exp = int(payload.get("expires", 0) or 0)
    if exp and time.time() > exp:
        return {"valid": False, "reason": "expired", "payload": payload}
    return {"valid": True, "reason": "ok", "payload": payload}


# --------------------------------------------------------------------------- entitlements
def free_entitlements(reason="no_license") -> dict:
    return {"valid": False, "tier": "free", "licensee": "", "max_agents": FREE_MAX_AGENTS,
            "features": set(), "expires": 0, "reason": reason}


def entitlements(token: str = "", pubkey_hex: str = "") -> dict:
    """Resolusi hak pakai dari token (atau FREE bila tak ada/invalid)."""
    token = (token or os.environ.get("NEXUS_LICENSE", "")).strip()
    if not token:
        return free_entitlements("no_license")
    # token bisa berupa path file
    if os.path.isfile(token):
        try:
            token = open(token, encoding="utf-8").read().strip()
        except Exception:
            return free_entitlements("license_unreadable")
    res = verify(token, pubkey_hex)
    if not res["valid"]:
        return free_entitlements(res["reason"])
    p = res["payload"]
    feats = set(p.get("features", []))
    return {
        "valid": True, "tier": p.get("tier", "pro"), "licensee": p.get("licensee", ""),
        "max_agents": None if "unlimited_agents" in feats else int(p.get("max_agents", FREE_MAX_AGENTS)),
        "features": feats, "expires": int(p.get("expires", 0) or 0), "reason": "ok",
    }


def has(ent: dict, feature: str) -> bool:
    return feature in (ent or {}).get("features", set())

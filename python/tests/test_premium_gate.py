# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# tests/test_premium_gate.py
"""Validasi gerbang lisensi Pro di Manager API berlaku SERAGAM (CLI/mobile/dashboard)
untuk SecOps (9 pilar) + fitur ekosistem premium (W1-W4): Pro->200, Free->403,
endpoint publik (/c/, /aw/) & /audit list tetap bebas."""
import os
import sys
import tempfile
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "fleet"))
os.environ["NEXUS_FLEET_DB"] = os.path.join(tempfile.mkdtemp(), "gate.db")

from nexus_common import protocol as fc          # noqa: E402
from nexus_common import license as lic          # noqa: E402

_SEED, _PK = lic.generate_keypair()
os.environ["NEXUS_VENDOR_PUBKEY"] = _PK
os.environ["NEXUS_LICENSE"] = lic.issue(_SEED, "Gate", tier="pro", days=365, max_agents=50)

from nexus_manager import server as mgr           # noqa: E402

PORT = 8807
_fail = 0
PREMIUM = ["/canary/stats", "/comply/frameworks", "/atlas/stats", "/aware/templates",
           "/pack/catalog", "/replay", "/airgap", "/audit/verify", "/xdr/incidents"]


def check(name, cond):
    global _fail
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    if not cond:
        _fail += 1


def _u(path):
    return fc.manager_url("127.0.0.1", PORT, path)


def _status(path, token):
    """Kembalikan kode HTTP (200 sukses, atau kode error)."""
    try:
        fc.get_admin(_u(path), token)
        return 200
    except Exception as e:
        s = str(e)
        for code in ("403", "401", "400", "404", "500"):
            if code in s:
                return int(code)
        return -1


def main():
    r = mgr.run(host="127.0.0.1", port=str(PORT))
    admin = r["admin_token"]
    time.sleep(0.3)

    # --- Pro: semua endpoint premium boleh diakses (bukan 403) ---
    pro_ok = all(_status(p, admin) != 403 for p in PREMIUM)
    check("Pro: endpoint premium TIDAK 403", pro_ok)
    check("Pro: POST premium (canary mint) bukan 403", _post_status("/canary/mint",
          {"type": "url", "label": "t"}, admin) != 403)

    # --- Downgrade ke FREE (hot-reload) ---
    free = lic.issue(_SEED, "Gate", tier="free", days=365, max_agents=2)
    check("apply free license", mgr.apply_license(free).get("ok"))

    # --- Free: SEMUA endpoint premium = 403 ---
    free_blocked = all(_status(p, admin) == 403 for p in PREMIUM)
    check("Free: SEMUA endpoint premium -> 403 (9 pilar + fitur baru)", free_blocked)
    check("Free: POST premium (canary mint) -> 403",
          _post_status("/canary/mint", {"type": "url"}, admin) == 403)

    # --- Free: endpoint non-premium tetap bisa ---
    check("Free: /agents tetap bisa (non-premium)", _status("/agents", admin) == 200)
    check("Free: /audit (list) tetap bebas", _status("/audit", admin) == 200)
    check("Free: /stats tetap bebas", _status("/stats", admin) == 200)

    # --- Endpoint publik tetap bebas tanpa token (canary/aware trigger) ---
    # Disajikan di ROOT (URL umpan di-deploy di mana saja), bukan di /api/v1.
    import urllib.request as _ur

    def _root(path):
        try:
            with _ur.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=4) as resp:
                return resp.status
        except Exception as e:
            return int("".join(c for c in str(e) if c.isdigit())[:3] or 0)

    check("publik /c/<marker> bebas (breach signal)", _root("/c/nxc_test") == 200)
    check("publik /aw/<token> bebas (tracking)", _root("/aw/tok_test") == 200)

    mgr.stop()
    print("\nSEMUA TES GATE PREMIUM LULUS." if not _fail else f"\n{_fail} GAGAL.")
    return 1 if _fail else 0


def _post_status(path, body, token):
    try:
        fc.post_admin(_u(path), body, token)
        return 200
    except Exception as e:
        s = str(e)
        for code in ("403", "401", "400", "404", "500"):
            if code in s:
                return int(code)
        return -1


if __name__ == "__main__":
    sys.exit(main())

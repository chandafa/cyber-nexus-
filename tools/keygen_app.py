#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com
"""
Nexus Keygen — aplikasi VENDOR untuk menerbitkan token lisensi (offline).

Model device-bound: pelanggan kirim Device ID-nya (terlihat di app: Settings →
Lisensi), Anda tempel di sini, pilih tier + masa berlaku, klik Generate. Token
yang dihasilkan HANYA berlaku di device itu dan kedaluwarsa otomatis.

  - TANPA server / Firebase / Blaze / kartu kredit.
  - Ditandatangani Ed25519 dengan private key vendor (~/.nexus/vendor_private.key).
  - Private key TIDAK pernah ikut ke aplikasi pelanggan.

Jalankan:  python tools/keygen_app.py      (butuh Tkinter — sudah bawaan Python)
CLI    :   python tools/keygen_app.py --device <ID> --tier pro --days 30
"""
import argparse
import base64
import json
import os
import secrets
import sys
import time

# Jalur ke implementasi Ed25519 + format kanonik (sama dengan verifier app).
_HERE = os.path.dirname(os.path.abspath(__file__))
_NEXUS = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_NEXUS, "python", "fleet"))
from nexus_common import _ed25519 as ed  # noqa: E402

_PRO = ["sigma", "active_response", "advanced_rules", "webaudit", "report"]
TIER_FEATURES = {"free": [], "pro": _PRO, "enterprise": ["unlimited_agents"] + _PRO}
DEFAULT_MAX_AGENTS = {"free": 2, "pro": 50, "enterprise": 0}
SEED_FILE = os.path.join(os.path.expanduser("~"), ".nexus", "vendor_private.key")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def load_seed() -> str:
    if not os.path.isfile(SEED_FILE):
        raise FileNotFoundError(
            f"Private key vendor tidak ditemukan: {SEED_FILE}\n"
            "Buat dengan tool lisensi vendor (nexus-license) terlebih dahulu."
        )
    return open(SEED_FILE, encoding="utf-8").read().strip()


def issue_token(device: str, tier: str = "pro", days: int = 30, licensee: str = "") -> str:
    """Terbitkan token device-bound bertanda tangan (format kanonik = app)."""
    device = (device or "").strip()
    if not device:
        raise ValueError("Device ID kosong.")
    seed_hex = load_seed()
    seed = bytes.fromhex(seed_hex)
    pk = ed.publickey(seed)
    now = int(time.time())
    payload = {
        "id": _b64(os.urandom(8)),
        "tier": tier,
        "device": device,
        "code": "NEXUS-" + _b64(secrets.token_bytes(6)).upper().replace("_", "").replace("-", "")[:10],
        "licensee": licensee,
        "features": TIER_FEATURES.get(tier, []),
        "max_agents": DEFAULT_MAX_AGENTS.get(tier, 2),
        "issued": now,
        "expires": now + days * 86400,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = ed.signature(raw, seed, pk)
    return _b64(raw) + "." + _b64(sig)


# --------------------------------------------------------------------------- GUI
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title("Nexus Keygen — Vendor")
    root.configure(bg="#0f0f12")
    root.geometry("560x440")

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    FG, BG, ACC = "#f4f4f5", "#0f0f12", "#3ee6c0"
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("TButton", background=ACC, foreground="#04130f")
    style.configure("TCombobox", fieldbackground="#1a1a20", foreground=FG)

    tk.Label(root, text="NEXUS KEYGEN", bg=BG, fg=ACC,
             font=("Segoe UI", 16, "bold")).pack(pady=(16, 2))
    tk.Label(root, text="Terbitkan token lisensi device-bound (offline)", bg=BG,
             fg="#a6a6ad").pack()

    frm = tk.Frame(root, bg=BG)
    frm.pack(fill="x", padx=20, pady=14)

    tk.Label(frm, text="Device ID pelanggan", bg=BG, fg=FG).grid(row=0, column=0, sticky="w")
    e_dev = tk.Entry(frm, bg="#1a1a20", fg=FG, insertbackground=FG, width=52)
    e_dev.grid(row=1, column=0, columnspan=3, sticky="we", pady=(2, 10))

    tk.Label(frm, text="Tier", bg=BG, fg=FG).grid(row=2, column=0, sticky="w")
    tier = ttk.Combobox(frm, values=["pro", "enterprise"], state="readonly", width=12)
    tier.set("pro"); tier.grid(row=3, column=0, sticky="w")

    tk.Label(frm, text="Masa (hari)", bg=BG, fg=FG).grid(row=2, column=1, sticky="w", padx=(12, 0))
    e_days = tk.Entry(frm, bg="#1a1a20", fg=FG, insertbackground=FG, width=8)
    e_days.insert(0, "30"); e_days.grid(row=3, column=1, sticky="w", padx=(12, 0))

    tk.Label(frm, text="Nama pelanggan (ops.)", bg=BG, fg=FG).grid(row=2, column=2, sticky="w", padx=(12, 0))
    e_lic = tk.Entry(frm, bg="#1a1a20", fg=FG, insertbackground=FG, width=18)
    e_lic.grid(row=3, column=2, sticky="w", padx=(12, 0))

    out = tk.Text(root, height=5, bg="#08080a", fg=ACC, insertbackground=FG,
                  wrap="char", relief="flat")
    out.pack(fill="both", expand=True, padx=20, pady=(4, 8))

    def generate():
        try:
            tok = issue_token(e_dev.get(), tier.get(), int(e_days.get() or "30"), e_lic.get())
        except Exception as ex:
            messagebox.showerror("Gagal", str(ex)); return
        out.delete("1.0", "end"); out.insert("1.0", tok)

    def copy():
        txt = out.get("1.0", "end").strip()
        if txt:
            root.clipboard_clear(); root.clipboard_append(txt)
            messagebox.showinfo("Disalin", "Token disalin. Kirim ke pelanggan.")

    btns = tk.Frame(root, bg=BG); btns.pack(pady=(0, 14))
    tk.Button(btns, text="Generate Token", command=generate, bg=ACC, fg="#04130f",
              relief="flat", padx=14, pady=6, font=("Segoe UI", 10, "bold")).pack(side="left", padx=6)
    tk.Button(btns, text="Salin", command=copy, bg="#1a1a20", fg=FG, relief="flat",
              padx=14, pady=6).pack(side="left", padx=6)

    root.mainloop()


def main():
    ap = argparse.ArgumentParser(description="Nexus Keygen (vendor).")
    ap.add_argument("--device", help="Device ID pelanggan (mode CLI).")
    ap.add_argument("--tier", choices=["pro", "enterprise"], default="pro")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--licensee", default="")
    args = ap.parse_args()
    if args.device:
        print(issue_token(args.device, args.tier, args.days, args.licensee))
    else:
        run_gui()


if __name__ == "__main__":
    main()

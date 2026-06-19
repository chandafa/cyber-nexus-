#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com
"""
Nexus License Admin — aplikasi VENDOR (GUI) untuk mengelola kode lisensi.

Lihat semua data token, buat, edit, hapus, cabut, dan bersihkan — semua langsung
sinkron ke database (Cloudflare D1) lewat Worker. Hanya butuh URL Worker + ADMIN
token (disembunyikan, tidak disimpan kecuali Anda pilih simpan).

Jalankan:  python admin_app.py
Stdlib saja (tkinter + urllib) — tanpa dependensi.
"""
import json
import os
import time
import urllib.error
import urllib.request

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOKEN_FILE = os.path.join(_HERE, ".admin-token.local")
_CFG = os.path.join(os.path.dirname(_HERE), "python", "core", "license_config.py")

# Palet gelap.
BG, PANEL, FG, MUTED, ACC, ACC2, DANGER = "#0e0e11", "#17171c", "#f4f4f5", "#a6a6ad", "#3ee6c0", "#6d6cff", "#ff5d6c"


def _load_url() -> str:
    if os.environ.get("NEXUS_LICENSE_API"):
        return os.environ["NEXUS_LICENSE_API"].strip()
    try:
        for line in open(_CFG, encoding="utf-8"):
            if line.strip().startswith("LICENSE_API_BASE") and "=" in line:
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if v:
                    return v
    except Exception:
        pass
    return ""


def _load_token() -> str:
    if os.environ.get("NEXUS_ADMIN_TOKEN"):
        return os.environ["NEXUS_ADMIN_TOKEN"].strip()
    try:
        for line in open(_TOKEN_FILE, encoding="utf-8"):
            if line.startswith("ADMIN_TOKEN="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def _fmt(ts):
    if not ts:
        return "-"
    try:
        return time.strftime("%Y-%m-%d", time.localtime(int(ts)))
    except Exception:
        return "-"


class AdminApp:
    def __init__(self, root):
        self.root = root
        root.title("Nexus License Admin")
        root.configure(bg=BG)
        root.geometry("1040x600")
        root.minsize(900, 480)

        self.url = tk.StringVar(value=_load_url())
        self.token = tk.StringVar(value=_load_token())
        self.filter = tk.StringVar(value="all")
        self.rows = []

        self._style()
        self._build_topbar()
        self._build_toolbar()
        self._build_table()
        self._build_status()
        if self.url.get() and self.token.get():
            self.refresh()

    # ----------------------------------------------------------------- styling
    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                     rowheight=26, borderwidth=0, font=("Segoe UI", 9))
        st.configure("Treeview.Heading", background="#202028", foreground=MUTED,
                     font=("Segoe UI", 9, "bold"), borderwidth=0)
        st.map("Treeview", background=[("selected", "#243b36")], foreground=[("selected", FG)])
        st.configure("TCombobox", fieldbackground=PANEL, background=PANEL, foreground=FG)

    def _btn(self, parent, text, cmd, color=PANEL, fg=FG):
        return tk.Button(parent, text=text, command=cmd, bg=color, fg=fg, relief="flat",
                         activebackground="#2a2a32", activeforeground=FG, padx=12, pady=6,
                         font=("Segoe UI", 9, "bold"), cursor="hand2", bd=0)

    # ----------------------------------------------------------------- top bar
    def _build_topbar(self):
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(top, text="NEXUS", bg=BG, fg=ACC, font=("Segoe UI", 15, "bold")).pack(side="left")
        tk.Label(top, text="License Admin", bg=BG, fg=MUTED, font=("Segoe UI", 11)).pack(side="left", padx=(8, 0))

        conn = tk.Frame(self.root, bg=BG)
        conn.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(conn, text="Worker URL", bg=BG, fg=MUTED).grid(row=0, column=0, sticky="w")
        tk.Entry(conn, textvariable=self.url, bg=PANEL, fg=FG, insertbackground=FG,
                 relief="flat", width=46).grid(row=1, column=0, sticky="we", padx=(0, 10), ipady=3)
        tk.Label(conn, text="Admin token", bg=BG, fg=MUTED).grid(row=0, column=1, sticky="w")
        self.tok_entry = tk.Entry(conn, textvariable=self.token, bg=PANEL, fg=FG, insertbackground=FG,
                                  relief="flat", width=26, show="•")
        self.tok_entry.grid(row=1, column=1, sticky="we", padx=(0, 6), ipady=3)
        self.show_tok = tk.IntVar(value=0)
        tk.Checkbutton(conn, text="lihat", variable=self.show_tok, command=self._toggle_tok, bg=BG,
                       fg=MUTED, selectcolor=PANEL, activebackground=BG, activeforeground=FG).grid(row=1, column=2)
        self._btn(conn, "Connect / Refresh", self.refresh, ACC, "#04130f").grid(row=1, column=3, padx=(8, 4))
        self._btn(conn, "Simpan token", self._save_token).grid(row=1, column=4)
        conn.grid_columnconfigure(0, weight=1)

    def _toggle_tok(self):
        self.tok_entry.config(show="" if self.show_tok.get() else "•")

    def _save_token(self):
        try:
            with open(_TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write("ADMIN_TOKEN=" + self.token.get().strip() + "\n")
            messagebox.showinfo("Tersimpan", "Token disimpan lokal (gitignored).")
        except Exception as e:
            messagebox.showerror("Gagal", str(e))

    # ----------------------------------------------------------------- toolbar
    def _build_toolbar(self):
        tb = tk.Frame(self.root, bg=BG)
        tb.pack(fill="x", padx=16, pady=4)
        self._btn(tb, "+ Generate", self.do_generate, ACC, "#04130f").pack(side="left", padx=(0, 6))
        self._btn(tb, "Edit", self.do_edit).pack(side="left", padx=3)
        self._btn(tb, "Reset device", self.do_reset).pack(side="left", padx=3)
        self._btn(tb, "Revoke", self.do_revoke).pack(side="left", padx=3)
        self._btn(tb, "Hapus", self.do_delete, "#2a1416", DANGER).pack(side="left", padx=3)
        self._btn(tb, "Bersihkan kedaluwarsa", self.do_cleanup).pack(side="left", padx=3)
        tk.Label(tb, text="Filter:", bg=BG, fg=MUTED).pack(side="left", padx=(14, 4))
        cb = ttk.Combobox(tb, textvariable=self.filter, state="readonly", width=12,
                          values=["all", "unused", "redeemed", "revoked"])
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh())

    # ----------------------------------------------------------------- table
    def _build_table(self):
        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(fill="both", expand=True, padx=16, pady=8)
        cols = ("code", "tier", "status", "device", "days", "licensee", "created", "expires")
        heads = ("Kode", "Tier", "Status", "Device", "Hari", "Pemegang", "Dibuat", "Kedaluwarsa")
        widths = (220, 70, 90, 130, 50, 130, 100, 110)
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w")
        self.tree.tag_configure("unused", foreground=FG)
        self.tree.tag_configure("redeemed", foreground=ACC)
        self.tree.tag_configure("revoked", foreground=DANGER)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.do_edit())

    def _build_status(self):
        self.status = tk.Label(self.root, text="Belum terhubung.", bg=BG, fg=MUTED, anchor="w")
        self.status.pack(fill="x", padx=16, pady=(0, 10))

    def _set_status(self, msg, ok=True):
        self.status.config(text=msg, fg=ACC if ok else DANGER)

    # ----------------------------------------------------------------- API
    def _api(self, path, payload=None):
        base = self.url.get().strip().rstrip("/")
        tok = self.token.get().strip()
        if not base or not tok:
            raise RuntimeError("Isi Worker URL & Admin token dulu.")
        req = urllib.request.Request(
            base + path, data=json.dumps(payload or {}).encode(),
            headers={"Content-Type": "application/json", "x-admin-token": tok,
                     "User-Agent": "Mozilla/5.0 (compatible; NexusAdmin/1.1)"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RuntimeError("Admin token salah (401).")
            try:
                return json.loads(e.read().decode())
            except Exception:
                raise RuntimeError(f"HTTP {e.code}")

    def _selected_codes(self):
        return [self.tree.item(i, "values")[0] for i in self.tree.selection()]

    # ----------------------------------------------------------------- actions
    def refresh(self):
        try:
            f = self.filter.get()
            r = self._api("/admin/list", {"limit": 2000, **({"status": f} if f != "all" else {})})
        except Exception as e:
            self._set_status(str(e), ok=False)
            return
        self.rows = r.get("rows", [])
        self.tree.delete(*self.tree.get_children())
        for row in self.rows:
            dev = (row.get("device_id") or "")[:16]
            self.tree.insert("", "end", values=(
                row["code"], row.get("tier", ""), row.get("status", ""), dev,
                row.get("duration_days", ""), row.get("licensee", "") or "-",
                _fmt(row.get("created_at")), _fmt(row.get("expires_at")),
            ), tags=(row.get("status", "unused"),))
        n = len(self.rows)
        un = sum(1 for x in self.rows if x.get("status") == "unused")
        self._set_status(f"{n} kode  ·  {un} unused  ·  terhubung ke {self.url.get()}")

    def do_generate(self):
        dlg = GenDialog(self.root)
        if not dlg.result:
            return
        try:
            r = self._api("/admin/generate", dlg.result)
        except Exception as e:
            messagebox.showerror("Gagal", str(e)); return
        if r.get("ok"):
            messagebox.showinfo("Selesai", f"{r['count']} kode dibuat:\n\n" + "\n".join(r["codes"]))
            self.refresh()
        else:
            messagebox.showerror("Gagal", str(r.get("error")))

    def do_edit(self):
        codes = self._selected_codes()
        if len(codes) != 1:
            messagebox.showinfo("Pilih 1", "Pilih tepat satu kode untuk diedit.")
            return
        row = next((x for x in self.rows if x["code"] == codes[0]), None)
        dlg = EditDialog(self.root, row)
        if not dlg.result:
            return
        try:
            r = self._api("/admin/update", {"code": codes[0], **dlg.result})
        except Exception as e:
            messagebox.showerror("Gagal", str(e)); return
        if r.get("ok"):
            self.refresh()
        else:
            messagebox.showerror("Gagal", str(r.get("error")))

    def do_reset(self):
        codes = self._selected_codes()
        if not codes:
            return
        if not messagebox.askyesno("Reset device", f"Lepas device & jadikan UNUSED {len(codes)} kode?"):
            return
        for c in codes:
            self._api("/admin/update", {"code": c, "resetDevice": True})
        self.refresh()

    def do_revoke(self):
        codes = self._selected_codes()
        if not codes:
            return
        if not messagebox.askyesno("Cabut", f"Cabut {len(codes)} kode? (app pelanggan turun ke Free)"):
            return
        for c in codes:
            self._api("/admin/update", {"code": c, "status": "revoked"})
        self.refresh()

    def do_delete(self):
        codes = self._selected_codes()
        if not codes:
            return
        if not messagebox.askyesno("Hapus", f"HAPUS PERMANEN {len(codes)} kode dari database?"):
            return
        try:
            r = self._api("/admin/delete", {"codes": codes})
        except Exception as e:
            messagebox.showerror("Gagal", str(e)); return
        self._set_status(f"{r.get('deleted', 0)} kode dihapus.")
        self.refresh()

    def do_cleanup(self):
        try:
            r = self._api("/admin/cleanup", {})
        except Exception as e:
            messagebox.showerror("Gagal", str(e)); return
        messagebox.showinfo("Selesai", f"{r.get('deleted', 0)} kode terpakai-kedaluwarsa dihapus.")
        self.refresh()


class GenDialog:
    def __init__(self, parent):
        self.result = None
        d = tk.Toplevel(parent); d.title("Generate kode"); d.configure(bg=PANEL); d.grab_set()
        d.geometry("320x230")
        self.count = tk.StringVar(value="10"); self.tier = tk.StringVar(value="pro"); self.days = tk.StringVar(value="30")
        self.lic = tk.StringVar(value="")
        for i, (lbl, var, opts) in enumerate([
            ("Jumlah", self.count, None), ("Tier", self.tier, ["pro", "enterprise"]),
            ("Masa (hari)", self.days, None), ("Pemegang (ops.)", self.lic, None)]):
            tk.Label(d, text=lbl, bg=PANEL, fg=MUTED).grid(row=i, column=0, sticky="w", padx=12, pady=6)
            if opts:
                ttk.Combobox(d, textvariable=var, values=opts, state="readonly", width=18).grid(row=i, column=1, padx=12)
            else:
                tk.Entry(d, textvariable=var, bg=BG, fg=FG, insertbackground=FG, relief="flat", width=20).grid(row=i, column=1, padx=12, ipady=2)
        tk.Button(d, text="Generate", bg=ACC, fg="#04130f", relief="flat", padx=14, pady=6,
                  font=("Segoe UI", 9, "bold"), command=lambda: self._ok(d)).grid(row=5, column=0, columnspan=2, pady=14)
        parent.wait_window(d)

    def _ok(self, d):
        try:
            self.result = {"count": int(self.count.get()), "tier": self.tier.get(),
                           "days": int(self.days.get()), "licensee": self.lic.get()}
        except Exception:
            messagebox.showerror("Salah", "Jumlah/hari harus angka."); return
        d.destroy()


class EditDialog:
    def __init__(self, parent, row):
        self.result = None
        d = tk.Toplevel(parent); d.title("Edit kode"); d.configure(bg=PANEL); d.grab_set()
        d.geometry("340x250")
        tk.Label(d, text=row["code"], bg=PANEL, fg=ACC, font=("Consolas", 10, "bold")).grid(row=0, column=0, columnspan=2, pady=(12, 8))
        self.tier = tk.StringVar(value=row.get("tier", "pro"))
        self.status = tk.StringVar(value=row.get("status", "unused"))
        self.days = tk.StringVar(value=str(row.get("duration_days", 30)))
        self.lic = tk.StringVar(value=row.get("licensee", "") or "")
        rows = [("Tier", self.tier, ["pro", "enterprise"]),
                ("Status", self.status, ["unused", "redeemed", "revoked"]),
                ("Masa (hari)", self.days, None), ("Pemegang", self.lic, None)]
        for i, (lbl, var, opts) in enumerate(rows, start=1):
            tk.Label(d, text=lbl, bg=PANEL, fg=MUTED).grid(row=i, column=0, sticky="w", padx=12, pady=6)
            if opts:
                ttk.Combobox(d, textvariable=var, values=opts, state="readonly", width=18).grid(row=i, column=1, padx=12)
            else:
                tk.Entry(d, textvariable=var, bg=BG, fg=FG, insertbackground=FG, relief="flat", width=20).grid(row=i, column=1, padx=12, ipady=2)
        tk.Button(d, text="Simpan", bg=ACC, fg="#04130f", relief="flat", padx=14, pady=6,
                  font=("Segoe UI", 9, "bold"), command=lambda: self._ok(d)).grid(row=6, column=0, columnspan=2, pady=14)
        parent.wait_window(d)

    def _ok(self, d):
        try:
            self.result = {"tier": self.tier.get(), "status": self.status.get(),
                           "durationDays": int(self.days.get()), "licensee": self.lic.get()}
        except Exception:
            messagebox.showerror("Salah", "Hari harus angka."); return
        d.destroy()


def main():
    root = tk.Tk()
    AdminApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

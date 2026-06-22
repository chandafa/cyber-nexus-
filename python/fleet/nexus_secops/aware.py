# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/aware.py
"""
Nexus Aware — security-awareness / simulasi phishing internal.

Jalankan kampanye phishing-simulasi INTERNAL untuk melatih staf mengenali serangan
nyata. Template berbahasa Indonesia (umpan lokal: OTP m-banking, notifikasi paket
JNE/J&T, info gaji/THR dari HR, reset password Microsoft 365/Google, tagihan
PLN/PDAM, undangan meeting palsu, verifikasi e-wallet OVO/GoPay/DANA).

Modul ini HANYA mengelola state + merender email + mencatat event terlacak:
  • create_campaign() — cetak token unik per target (secrets.token_hex).
  • render_emails()   — isi {{name}} & {{link}}; manager menyerahkan ke channel email.
  • record()          — catat open/click/report saat endpoint HTTP /aw/<token> diakses.
  • score()           — hitung open/click/report rate + rincian per-pengguna.

Pengiriman email NYATA & endpoint HTTP pelacakan /aw/<token> di-wire oleh manager
terpisah. Semua best-effort, non-fatal, mengembalikan dict JSON-serializable ber-"ok".

Tabel: aware_campaigns (kampanye) + aware_targets (per-target tracking token).
Kontrak pelacakan: setiap target punya path "/aw/<token>"; manager memetakan
GET /aw/<token> → record(token, "open"|"click") dan tombol "Laporkan" → record(.,"report").
"""
import json
import secrets
import sqlite3
import time


# --------------------------------------------------------------------------- template
# Template simulasi (berorientasi pelatihan). body memuat {{name}} & {{link}}.
TEMPLATES = [
    {
        "id": "otp_bank",
        "name": "OTP / Verifikasi m-Banking",
        "category": "perbankan",
        "difficulty": "sulit",
        "subject": "[PENTING] Verifikasi transaksi mencurigakan di rekening Anda",
        "body": (
            "Yth. Bapak/Ibu {{name}},\n\n"
            "Kami mendeteksi upaya login tidak dikenal pada akun m-Banking Anda. "
            "Demi keamanan, mohon verifikasi identitas Anda dalam 1x24 jam, jika tidak "
            "akun akan diblokir sementara.\n\n"
            "Verifikasi sekarang: {{link}}\n\n"
            "Jangan pernah membagikan kode OTP kepada siapa pun.\n"
            "Hormat kami,\nTim Keamanan Bank\n"
        ),
    },
    {
        "id": "paket_jnt",
        "name": "Notifikasi Paket Tertahan (JNE/J&T)",
        "category": "logistik",
        "difficulty": "mudah",
        "subject": "Paket Anda tertahan - perlu konfirmasi alamat",
        "body": (
            "Halo {{name}},\n\n"
            "Paket Anda dengan nomor resi JX-883102 tidak dapat dikirim karena alamat "
            "tidak lengkap. Mohon konfirmasi alamat pengiriman agar paket segera "
            "dikirim ulang.\n\n"
            "Konfirmasi alamat: {{link}}\n\n"
            "Terima kasih,\nLayanan Pengiriman\n"
        ),
    },
    {
        "id": "thr_hr",
        "name": "Info Pencairan Gaji / THR dari HR",
        "category": "internal-hr",
        "difficulty": "sedang",
        "subject": "Slip THR 2026 & konfirmasi data rekening",
        "body": (
            "Kepada Yth. {{name}},\n\n"
            "Sehubungan dengan pencairan THR tahun ini, mohon setiap karyawan memeriksa "
            "slip dan mengonfirmasi nomor rekening yang terdaftar agar tidak terjadi "
            "kesalahan transfer.\n\n"
            "Periksa slip & konfirmasi rekening: {{link}}\n\n"
            "Batas konfirmasi: akhir pekan ini.\n"
            "Salam,\nTim HR & Payroll\n"
        ),
    },
    {
        "id": "m365_reset",
        "name": "Reset Password Microsoft 365",
        "category": "akun-it",
        "difficulty": "sulit",
        "subject": "Kata sandi Microsoft 365 Anda akan kedaluwarsa hari ini",
        "body": (
            "Hai {{name}},\n\n"
            "Kata sandi akun Microsoft 365 Anda akan kedaluwarsa hari ini. Untuk "
            "menghindari kehilangan akses ke email dan dokumen, mohon perbarui kata "
            "sandi Anda sekarang.\n\n"
            "Pertahankan kata sandi saat ini / perbarui: {{link}}\n\n"
            "Jika Anda tidak melakukan ini, akses akan ditangguhkan otomatis.\n"
            "Microsoft 365 - Tim Dukungan\n"
        ),
    },
    {
        "id": "google_reset",
        "name": "Peringatan Keamanan Akun Google",
        "category": "akun-it",
        "difficulty": "sedang",
        "subject": "Aktivitas masuk baru terdeteksi di Akun Google Anda",
        "body": (
            "Halo {{name}},\n\n"
            "Perangkat baru baru saja masuk ke Akun Google Anda. Jika ini bukan Anda, "
            "amankan akun Anda sekarang untuk mencegah akses tidak sah.\n\n"
            "Tinjau aktivitas & amankan akun: {{link}}\n\n"
            "Tim Keamanan Akun\n"
        ),
    },
    {
        "id": "tagihan_pln",
        "name": "Tagihan PLN/PDAM Belum Terbayar",
        "category": "utilitas",
        "difficulty": "mudah",
        "subject": "Pemberitahuan: tagihan listrik Anda menunggak",
        "body": (
            "Yth. Pelanggan {{name}},\n\n"
            "Tercatat tagihan listrik Anda belum terbayar. Untuk menghindari pemutusan "
            "sementara, mohon segera lakukan pembayaran melalui tautan resmi berikut.\n\n"
            "Cek tagihan & bayar: {{link}}\n\n"
            "Abaikan pesan ini jika sudah membayar.\nLayanan Pelanggan\n"
        ),
    },
    {
        "id": "meeting_palsu",
        "name": "Undangan Meeting Mendadak",
        "category": "kolaborasi",
        "difficulty": "sedang",
        "subject": "Undangan: rapat evaluasi mendadak (hari ini, 15.00)",
        "body": (
            "Halo {{name}},\n\n"
            "Anda diundang ke rapat evaluasi mendadak hari ini pukul 15.00. Mohon "
            "bergabung tepat waktu dan tinjau dokumen agenda sebelum rapat dimulai.\n\n"
            "Gabung rapat & buka agenda: {{link}}\n\n"
            "Terima kasih,\nSekretariat\n"
        ),
    },
    {
        "id": "ewallet_verif",
        "name": "Verifikasi Akun e-Wallet (OVO/GoPay/DANA)",
        "category": "e-wallet",
        "difficulty": "sulit",
        "subject": "Akun e-wallet Anda dibatasi - verifikasi diperlukan",
        "body": (
            "Halo {{name}},\n\n"
            "Akun e-wallet Anda untuk sementara dibatasi karena terdeteksi aktivitas "
            "tidak biasa. Saldo Anda aman, namun Anda perlu memverifikasi akun untuk "
            "membuka kembali transaksi.\n\n"
            "Verifikasi akun sekarang: {{link}}\n\n"
            "Jangan bagikan PIN atau OTP kepada siapa pun.\nTim Layanan e-Wallet\n"
        ),
    },
]

_TEMPLATE_BY_ID = {t["id"]: t for t in TEMPLATES}


def ensure_tables(c):
    """Buat tabel Aware pada koneksi `c` (tanpa commit) — dipanggil manager init_db
    agar skema disiapkan dalam SATU koneksi (hindari lock antar-koneksi)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS aware_campaigns (
            id TEXT PRIMARY KEY, name TEXT, template_id TEXT,
            tenant_id TEXT DEFAULT 'default', created INTEGER,
            status TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS aware_targets (
            id TEXT PRIMARY KEY, campaign_id TEXT, name TEXT, email TEXT,
            token TEXT, opened INTEGER DEFAULT 0, clicked INTEGER DEFAULT 0,
            reported INTEGER DEFAULT 0, last_event_ts INTEGER,
            tenant_id TEXT DEFAULT 'default'
        );
        CREATE INDEX IF NOT EXISTS idx_aware_token ON aware_targets(token);
        CREATE INDEX IF NOT EXISTS idx_aware_campaign ON aware_targets(campaign_id);
        """
    )


def _now():
    return int(time.time())


def _sa_conn():
    from nexus_common import protocol as fc
    return fc.connect()


# --------------------------------------------------------------------------- templates
def list_templates() -> dict:
    """Daftar template (tanpa body penuh) untuk dipilih operator."""
    return {"ok": True, "templates": [{
        "id": t["id"], "name": t["name"], "category": t["category"],
        "difficulty": t["difficulty"], "subject": t["subject"],
    } for t in TEMPLATES]}


# --------------------------------------------------------------------------- campaigns
def create_campaign(name, template_id, targets, tenant="default", conn=None) -> dict:
    """Buat kampanye + cetak token unik per target. targets = list {name,email}.
    Mengembalikan link_path "/aw/<token>" per target (manager menyusun URL penuh)."""
    if template_id not in _TEMPLATE_BY_ID:
        return {"ok": False, "error": f"template tidak dikenal: {template_id}"}
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    cid = "awc_" + secrets.token_hex(6)
    c.execute("INSERT INTO aware_campaigns(id,name,template_id,tenant_id,created,status) "
              "VALUES(?,?,?,?,?,'active')",
              (cid, name or "kampanye", template_id, tenant, _now()))
    out = []
    for t in targets or []:
        nm = (t.get("name") or "").strip()
        em = (t.get("email") or "").strip()
        if not em:
            continue
        token = secrets.token_hex(16)
        tid = "awt_" + secrets.token_hex(6)
        c.execute("INSERT INTO aware_targets(id,campaign_id,name,email,token,opened,"
                  "clicked,reported,tenant_id) VALUES(?,?,?,?,?,0,0,0,?)",
                  (tid, cid, nm, em, token, tenant))
        out.append({"name": nm, "email": em, "token": token,
                    "link_path": f"/aw/{token}"})
    if own:
        c.commit(); c.close()
    return {"ok": True, "campaign_id": cid, "count": len(out), "targets": out}


def list_campaigns(tenant="default", conn=None) -> dict:
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    rows = c.execute(
        "SELECT cp.id,cp.name,cp.template_id,cp.created,cp.status, "
        "COUNT(tg.id) AS targets, "
        "COALESCE(SUM(tg.opened),0) AS opened, "
        "COALESCE(SUM(tg.clicked),0) AS clicked, "
        "COALESCE(SUM(tg.reported),0) AS reported "
        "FROM aware_campaigns cp LEFT JOIN aware_targets tg ON tg.campaign_id=cp.id "
        "WHERE cp.tenant_id=? GROUP BY cp.id ORDER BY cp.created DESC", (tenant,)
    ).fetchall()
    if own:
        c.close()
    return {"ok": True, "campaigns": [{
        "id": r["id"], "name": r["name"], "template_id": r["template_id"],
        "created": r["created"], "status": r["status"], "targets": r["targets"],
        "opened": r["opened"], "clicked": r["clicked"], "reported": r["reported"],
    } for r in rows]}


def get_campaign(campaign_id, tenant="default", conn=None) -> dict:
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    cp = c.execute("SELECT id,name,template_id,tenant_id,created,status FROM aware_campaigns "
                   "WHERE id=? AND tenant_id=?", (campaign_id, tenant)).fetchone()
    if not cp:
        if own:
            c.close()
        return {"ok": False, "error": "kampanye tidak ditemukan"}
    rows = c.execute("SELECT id,name,email,token,opened,clicked,reported,last_event_ts "
                     "FROM aware_targets WHERE campaign_id=? ORDER BY rowid",
                     (campaign_id,)).fetchall()
    if own:
        c.close()
    tpl = _TEMPLATE_BY_ID.get(cp["template_id"], {})
    return {"ok": True, "campaign": {
        "id": cp["id"], "name": cp["name"], "template_id": cp["template_id"],
        "template_name": tpl.get("name", cp["template_id"]),
        "created": cp["created"], "status": cp["status"],
        "targets": [{
            "id": r["id"], "name": r["name"], "email": r["email"], "token": r["token"],
            "link_path": f"/aw/{r['token']}",
            "opened": bool(r["opened"]), "clicked": bool(r["clicked"]),
            "reported": bool(r["reported"]), "last_event_ts": r["last_event_ts"],
        } for r in rows],
    }}


def render_emails(campaign_id, base_url="", tenant="default", conn=None) -> dict:
    """Render email siap-kirim per target: {{name}} & {{link}} terisi.
    {{link}} = f"{base_url}/aw/<token>". Manager menyerahkan ke channel email."""
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    cp = c.execute("SELECT template_id FROM aware_campaigns WHERE id=? AND tenant_id=?",
                   (campaign_id, tenant)).fetchone()
    if not cp:
        if own:
            c.close()
        return {"ok": False, "error": "kampanye tidak ditemukan"}
    tpl = _TEMPLATE_BY_ID.get(cp["template_id"])
    if not tpl:
        if own:
            c.close()
        return {"ok": False, "error": "template kampanye tidak dikenal"}
    rows = c.execute("SELECT name,email,token FROM aware_targets WHERE campaign_id=? "
                     "ORDER BY rowid", (campaign_id,)).fetchall()
    if own:
        c.close()
    base = (base_url or "").rstrip("/")
    emails = []
    for r in rows:
        link = f"{base}/aw/{r['token']}"
        nm = r["name"] or r["email"]
        body = tpl["body"].replace("{{name}}", nm).replace("{{link}}", link)
        subject = tpl["subject"].replace("{{name}}", nm).replace("{{link}}", link)
        emails.append({"to": r["email"], "subject": subject, "body": body})
    return {"ok": True, "campaign_id": campaign_id, "template_id": tpl["id"],
            "emails": emails}


# --------------------------------------------------------------------------- tracking
def record(token, kind, source="", conn=None) -> dict:
    """Catat event terlacak untuk token target. kind in {open,click,report}.
    "click" mengimplikasikan "open". Dipanggil manager dari endpoint /aw/<token>."""
    kind = (kind or "").lower()
    if kind not in ("open", "click", "report"):
        return {"ok": False, "error": f"kind tidak dikenal: {kind}"}
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    row = c.execute("SELECT id,campaign_id,name,email,opened,clicked,reported "
                    "FROM aware_targets WHERE token=?", (token,)).fetchone()
    if not row:
        if own:
            c.close()
        return {"ok": False, "error": "token tidak dikenal"}
    sets = {"last_event_ts": _now()}
    if kind == "open":
        sets["opened"] = 1
    elif kind == "click":
        sets["opened"] = 1
        sets["clicked"] = 1
    elif kind == "report":
        sets["reported"] = 1
    cols = ", ".join(f"{k}=?" for k in sets)
    c.execute(f"UPDATE aware_targets SET {cols} WHERE id=?",
              list(sets.values()) + [row["id"]])
    if own:
        c.commit(); c.close()
    return {"ok": True, "campaign_id": row["campaign_id"], "target": row["email"],
            "name": row["name"], "kind": kind}


# --------------------------------------------------------------------------- scoring
def score(campaign_id="", tenant="default", conn=None) -> dict:
    """Skor kampanye (bila campaign_id diberikan) atau agregat tenant.
    sent = jumlah target. click_rate/report_rate dibulatkan 4 desimal."""
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    if campaign_id:
        rows = c.execute("SELECT name,email,opened,clicked,reported FROM aware_targets "
                         "WHERE campaign_id=? AND tenant_id=? ORDER BY rowid",
                         (campaign_id, tenant)).fetchall()
    else:
        rows = c.execute("SELECT name,email,opened,clicked,reported FROM aware_targets "
                         "WHERE tenant_id=? ORDER BY rowid", (tenant,)).fetchall()
    if own:
        c.close()
    sent = len(rows)
    opened = sum(1 for r in rows if r["opened"])
    clicked = sum(1 for r in rows if r["clicked"])
    reported = sum(1 for r in rows if r["reported"])
    click_rate = round(clicked / sent, 4) if sent else 0.0
    report_rate = round(reported / sent, 4) if sent else 0.0
    open_rate = round(opened / sent, 4) if sent else 0.0
    return {"ok": True, "campaign_id": campaign_id, "sent": sent, "opened": opened,
            "clicked": clicked, "reported": reported, "open_rate": open_rate,
            "click_rate": click_rate, "report_rate": report_rate,
            "per_user": [{
                "name": r["name"], "email": r["email"], "opened": bool(r["opened"]),
                "clicked": bool(r["clicked"]), "reported": bool(r["reported"]),
            } for r in rows]}


def delete_campaign(campaign_id, conn=None) -> dict:
    own = conn is None
    c = conn or _sa_conn()
    ensure_tables(c)
    n_t = c.execute("DELETE FROM aware_targets WHERE campaign_id=?", (campaign_id,)).rowcount
    n_c = c.execute("DELETE FROM aware_campaigns WHERE id=?", (campaign_id,)).rowcount
    if own:
        c.commit(); c.close()
    return {"ok": n_c > 0, "deleted_campaign": n_c, "deleted_targets": n_t}

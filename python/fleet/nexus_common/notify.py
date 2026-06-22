# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_common/notify.py
"""
Hub notifikasi multi-channel Nexus — stdlib-only (urllib + smtplib).

Channel GRATIS yang didukung (tanpa biaya per-pesan):
  • telegram — Bot API (bot_token + chat_id)
  • email    — SMTP apa pun (smtplib): Gmail app-password, Mailgun, dll.
  • slack    — Incoming Webhook
  • discord  — Webhook
  • webhook  — HTTP JSON generik
  • whatsapp — Meta WhatsApp Cloud API (token + phone_id); free-tier, perlu setup
               bisnis Meta. Adapter siap; nonaktif sampai kredensial diisi.

Setiap channel = dict konfigurasi (disimpan manager sebagai JSON). Pengiriman
best-effort & non-fatal: kegagalan satu channel tidak menggagalkan alert/ingest.
Routing per-channel via `min_level` (default ikut global) & filter `severity`.

Skema channel:
  {
    "id": "ch_xxxx", "type": "telegram", "name": "SOC Telegram",
    "enabled": true, "min_level": 12, "severities": ["high","critical"],  # opsional
    ...field spesifik tipe...
  }
"""
import json
import smtplib
import ssl as _ssl
import urllib.request
from email.mime.text import MIMEText

_TYPES = ("telegram", "email", "slack", "discord", "webhook", "whatsapp")


def _post_json(url, payload, headers=None, timeout=6):
    data = json.dumps(payload).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return 200 <= resp.status < 300


# --------------------------------------------------------------------------- adapter
def _send_telegram(ch, text, alert):
    token = ch.get("bot_token", "")
    chat_id = ch.get("chat_id", "")
    if not token or not chat_id:
        raise ValueError("telegram butuh bot_token & chat_id")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    return _post_json(url, {"chat_id": chat_id, "text": text, "disable_web_page_preview": True})


def _send_slack(ch, text, alert):
    if not ch.get("url"):
        raise ValueError("slack butuh url webhook")
    return _post_json(ch["url"], {"text": text})


def _send_discord(ch, text, alert):
    if not ch.get("url"):
        raise ValueError("discord butuh url webhook")
    return _post_json(ch["url"], {"content": text})


def _send_webhook(ch, text, alert):
    if not ch.get("url"):
        raise ValueError("webhook butuh url")
    # generik: sertakan text (Slack/Discord-compatible) + payload alert terstruktur
    return _post_json(ch["url"], {"text": text, "content": text, "alert": alert})


def _send_whatsapp(ch, text, alert):
    # Meta WhatsApp Cloud API — gratis (tanpa biaya per-pesan pd free tier), perlu
    # token + phone number id + nomor tujuan terdaftar.
    token = ch.get("token", "")
    phone_id = ch.get("phone_id", "")
    to = ch.get("to", "")
    if not (token and phone_id and to):
        raise ValueError("whatsapp butuh token, phone_id, to")
    ver = ch.get("api_version", "v20.0")
    url = f"https://graph.facebook.com/{ver}/{phone_id}/messages"
    payload = {"messaging_product": "whatsapp", "to": to,
               "type": "text", "text": {"body": text}}
    return _post_json(url, payload, headers={"Authorization": f"Bearer {token}"})


def _smtp_deliver(ch, subject, body, to_addrs):
    """Antar satu email via SMTP dari config channel email. Dipakai alert-notify
    maupun Nexus Aware (phishing-sim). Mengembalikan True bila terkirim."""
    host = ch.get("smtp_host", "")
    if not host:
        raise ValueError("email butuh smtp_host")
    port = int(ch.get("smtp_port", 587))
    user = ch.get("username", "")
    pwd = ch.get("password", "")
    from_addr = ch.get("from_addr") or user
    if isinstance(to_addrs, str):
        to_addrs = [a.strip() for a in to_addrs.split(",") if a.strip()]
    if not from_addr or not to_addrs:
        raise ValueError("email butuh from_addr & to_addrs")
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    use_tls = ch.get("use_tls", True)
    use_ssl = ch.get("use_ssl", False)
    timeout = int(ch.get("timeout", 10))
    if use_ssl:
        srv = smtplib.SMTP_SSL(host, port, timeout=timeout, context=_ssl.create_default_context())
    else:
        srv = smtplib.SMTP(host, port, timeout=timeout)
    try:
        srv.ehlo()
        if use_tls and not use_ssl:
            srv.starttls(context=_ssl.create_default_context())
            srv.ehlo()
        if user and pwd:
            srv.login(user, pwd)
        srv.sendmail(from_addr, to_addrs, msg.as_string())
    finally:
        try:
            srv.quit()
        except Exception:
            pass
    return True


def _send_email(ch, text, alert):
    subj = ch.get("subject_prefix", "[NEXUS]")
    sev = (alert.get("severity") or "").upper()
    subject = f"{subj} {sev} · {alert.get('title', 'alert')}"
    return _smtp_deliver(ch, subject, text, ch.get("to_addrs") or [])


def send_raw_email(ch, to_addr, subject, body) -> bool:
    """Kirim email subjek/isi KUSTOM lewat channel email (untuk Nexus Aware)."""
    return _smtp_deliver(ch, subject, body, [to_addr])


_ADAPTERS = {
    "telegram": _send_telegram,
    "email": _send_email,
    "slack": _send_slack,
    "discord": _send_discord,
    "webhook": _send_webhook,
    "whatsapp": _send_whatsapp,
}


# --------------------------------------------------------------------------- format & dispatch
def format_alert(alert) -> str:
    """Teks ringkas lintas-channel untuk satu alert."""
    rule = alert.get("rule") or {}
    rid = rule.get("id") if isinstance(rule, dict) else rule
    mitre = rule.get("mitre") if isinstance(rule, dict) else None
    parts = [f"[NEXUS {str(alert.get('severity','')).upper()}/L{alert.get('level','?')}] "
             f"{alert.get('title','(tanpa judul)')}"]
    if rid:
        parts.append(f"rule {rid}")
    if alert.get("agent_id"):
        parts.append(f"agent {alert['agent_id']}")
    if mitre:
        parts.append(f"MITRE {mitre}")
    if alert.get("detail"):
        parts.append(str(alert["detail"])[:300])
    return " · ".join(parts)


def _passes(ch, alert, global_min_level) -> bool:
    if not ch.get("enabled", True):
        return False
    min_level = int(ch.get("min_level", global_min_level))
    if int(alert.get("level", 0)) < min_level:
        return False
    sevs = ch.get("severities")
    if sevs and str(alert.get("severity", "")).lower() not in [s.lower() for s in sevs]:
        return False
    return True


def send_one(ch, alert, text=None) -> dict:
    """Kirim ke SATU channel (abaikan filter). Untuk uji koneksi."""
    typ = ch.get("type")
    fn = _ADAPTERS.get(typ)
    if not fn:
        return {"ok": False, "type": typ, "error": f"tipe channel tak dikenal: {typ}"}
    try:
        ok = fn(ch, text if text is not None else format_alert(alert), alert)
        return {"ok": bool(ok), "type": typ, "id": ch.get("id")}
    except Exception as e:
        return {"ok": False, "type": typ, "id": ch.get("id"), "error": str(e)}


def dispatch(channels, alert, global_min_level=12) -> list:
    """Kirim alert ke semua channel yang lolos filter. Mengembalikan ringkasan per-channel."""
    results = []
    text = format_alert(alert)
    for ch in channels or []:
        if not _passes(ch, alert, global_min_level):
            continue
        results.append(send_one(ch, alert, text))
    return results

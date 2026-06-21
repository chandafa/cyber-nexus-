# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_common/protocol.py
"""
Protokol bersama Nexus Fleet (agent <-> manager <-> cli <-> dashboard).

Stdlib-only (tidak ada dependency eksternal) sehingga komponen agent bisa
disalin ke endpoint mana pun yang punya Python 3.8+ tanpa pip install.

Keamanan:
  - Transport HTTP JSON di localhost/LAN — TIDAK ke internet.
  - Pesan agent ditandatangani HMAC-SHA256 dgn kunci per-agent.
  - Enrollment butuh enrollment key; API admin butuh admin token.
"""
import hashlib
import hmac
import json
import os
import platform
import socket
import ssl
import time
import uuid
import urllib.request
import urllib.error

API_VERSION = "v1"
DEFAULT_MANAGER_HOST = "127.0.0.1"
DEFAULT_MANAGER_PORT = 8765
HEARTBEAT_INTERVAL = 30          # detik antar-heartbeat (default policy)
COLLECT_INTERVAL = 120           # detik antar-siklus pengumpulan telemetri
OFFLINE_AFTER = 90               # detik tanpa heartbeat -> dianggap offline
REPLAY_WINDOW = 300              # detik: tolak pesan ber-stempel-waktu basi (anti-replay)

SEVERITIES = ("info", "low", "medium", "high", "critical")


# --------------------------------------------------------------------------- paths
def _data_dir() -> str:
    db = os.environ.get("NEXUS_DB_PATH", "")
    if db:
        d = os.path.dirname(os.path.abspath(db))
        if d:
            return d
    # Default: folder kerja proses (cocok untuk deploy standalone).
    return os.environ.get("NEXUS_FLEET_HOME") or os.getcwd()


def manager_db_path() -> str:
    return os.environ.get("NEXUS_FLEET_DB") or os.path.join(_data_dir(), "fleet_manager.db")


def agent_state_path() -> str:
    return os.environ.get("NEXUS_AGENT_DB") or os.path.join(_data_dir(), "fleet_agent.db")


# --------------------------------------------------------------------------- util
def now() -> int:
    return int(time.time())


def iso(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "—"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def gen_key() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex


def host_fingerprint() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os": platform.system() or "Unknown",
        "os_release": platform.release(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
    }


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(key: str, raw: bytes) -> str:
    return hmac.new(key.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def verify(key: str, raw: bytes, sig: str) -> bool:
    try:
        return hmac.compare_digest(sign(key, raw), sig or "")
    except Exception:
        return False


def manager_url(host: str, port, path: str = "", scheme: str = "http") -> str:
    base = f"{scheme}://{host}:{int(port)}/api/{API_VERSION}"
    if not path:
        return base
    return base + (path if path.startswith("/") else "/" + path)


# --------------------------------------------------------------------------- TLS
_CLIENT_CTX = None


def set_client_tls(cafile: str = "", insecure: bool = False,
                   clientcert: str = "", clientkey: str = ""):
    """Konfigurasi TLS klien (agent). cafile = cert manager yang di-pin;
    clientcert/clientkey = sertifikat klien untuk **mTLS**."""
    global _CLIENT_CTX
    if not cafile and not insecure and not clientcert:
        _CLIENT_CTX = None
        return
    ctx = ssl.create_default_context()
    if cafile:
        ctx.load_verify_locations(cafile)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if clientcert and clientkey:
        ctx.load_cert_chain(clientcert, clientkey)   # mTLS: agent presentasikan cert
    _CLIENT_CTX = ctx


def fetch_server_cert(host: str, port) -> str:
    """Ambil sertifikat server (PEM) untuk TOFU pinning saat enrollment HTTPS."""
    return ssl.get_server_certificate((host, int(port)))


# --------------------------------------------------------------------------- HTTP client (stdlib)
class HttpError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


def _request(method: str, url: str, raw: bytes = b"", headers=None, timeout=15) -> dict:
    req = urllib.request.Request(url, data=(raw if method == "POST" else None), method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    kw = {}
    if url.lower().startswith("https") and _CLIENT_CTX is not None:
        kw["context"] = _CLIENT_CTX
    try:
        with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
            data = r.read().decode("utf-8", "replace")
            return json.loads(data) if data.strip() else {}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        raise HttpError(e.code, body)


_CLOCK_OFFSET = 0   # detik: (waktu server - waktu lokal); koreksi clock-skew agent


def set_clock_offset(seconds: int):
    """Sinkronkan stempel waktu agent dgn server (anti-replay tahan clock drift)."""
    global _CLOCK_OFFSET
    try:
        _CLOCK_OFFSET = int(seconds)
    except Exception:
        _CLOCK_OFFSET = 0


def _stamped(body: dict) -> bytes:
    return canonical({**body, "_ts": now() + _CLOCK_OFFSET})


def fresh(body: dict, window: int = REPLAY_WINDOW) -> bool:
    """True bila stempel waktu `_ts` di body masih dalam jendela (anti-replay)."""
    try:
        return abs(now() - int(body.get("_ts", 0))) <= window
    except Exception:
        return False


def post_signed(url: str, body: dict, agent_id: str, agent_key: str, timeout=15) -> dict:
    raw = _stamped(body)                           # stempel waktu ter-koreksi (anti-replay)
    return _request("POST", url, raw, {
        "X-Agent-Id": agent_id,
        "X-Signature": sign(agent_key, raw),
    }, timeout)


def post_enroll(url: str, body: dict, enroll_key: str, timeout=15) -> dict:
    raw = _stamped(body)
    return _request("POST", url, raw, {"X-Enroll-Signature": sign(enroll_key, raw)}, timeout)


def get_admin(url: str, admin_token: str = "", timeout=15) -> dict:
    return _request("GET", url, b"", {"X-Admin-Token": admin_token}, timeout)


def post_admin(url: str, body: dict, admin_token: str = "", timeout=15) -> dict:
    return _request("POST", url, canonical(body), {"X-Admin-Token": admin_token}, timeout)

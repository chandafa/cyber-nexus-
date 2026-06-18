# nexus_common/cryptobox.py
"""
Enkripsi rahasia at-rest (opsional).

Bila operator menyetel env **NEXUS_MASTER_KEY** dan paket `cryptography` tersedia,
nilai rahasia di config (enroll key, admin token, license) disimpan TERENKRIPSI
(Fernet/AES). Tanpa master key / tanpa cryptography -> plaintext (perilaku lama,
kompatibel mundur) + peringatan.

PENTING: NEXUS_MASTER_KEY harus STABIL & dicadangkan. Bila hilang/berubah, nilai
terenkripsi tak bisa dibaca lagi.
"""
import base64
import hashlib
import os

_MARK = "enc:"        # penanda nilai terenkripsi


def _fernet():
    mk = os.environ.get("NEXUS_MASTER_KEY", "")
    if not mk:
        return None
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None
    key = base64.urlsafe_b64encode(hashlib.sha256(mk.encode("utf-8")).digest())
    return Fernet(key)


def enabled() -> bool:
    return _fernet() is not None


def encrypt(value):
    f = _fernet()
    if not f or value is None:
        return value
    if isinstance(value, str) and value.startswith(_MARK):
        return value      # sudah terenkripsi
    try:
        return _MARK + f.encrypt(str(value).encode("utf-8")).decode("utf-8")
    except Exception:
        return value


def decrypt(value):
    if not isinstance(value, str) or not value.startswith(_MARK):
        return value      # plaintext (kompatibel mundur)
    f = _fernet()
    if not f:
        return value
    try:
        return f.decrypt(value[len(_MARK):].encode("utf-8")).decode("utf-8")
    except Exception:
        return value

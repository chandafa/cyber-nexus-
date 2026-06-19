# nexus_common/_ed25519.py
"""
Ed25519 pure-Python (verify + sign) — TANPA dependency eksternal.

Dipakai untuk lisensi Nexus: vendor (pemilik private key) menandatangani token
lisensi; manager (punya public key) memverifikasinya. Karena asimetris,
pelanggan TIDAK bisa memalsukan lisensi tanpa private key vendor.

Berbasis implementasi referensi Ed25519 (D. J. Bernstein, public domain),
dengan modular-exponentiation memakai `pow()` bawaan (lebih cepat & tanpa
rekursi dalam). Cukup untuk operasi jarang (terbitkan/verifikasi lisensi).
"""
import hashlib

b = 256
q = 2 ** 255 - 19
_l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    return pow(x, q - 2, q)


_d = -121665 * _inv(121666) % q
_I = pow(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5) % q
_Bx = _xrecover(_By)
_B = [_Bx % q, _By % q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    # iteratif (hindari rekursi dalam)
    Q = [0, 1]
    while e > 0:
        if e & 1:
            Q = _edwards(Q, P)
        P = _edwards(P, P)
        e >>= 1
    return Q


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y):
    return bytes((y >> (8 * i)) & 0xFF for i in range(b // 8))


def _encodepoint(P):
    x, y = P
    val = (y & ((1 << (b - 1)) - 1)) | ((x & 1) << (b - 1))
    return bytes((val >> (8 * i)) & 0xFF for i in range(b // 8))


def _Hint(m):
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def publickey(seed: bytes) -> bytes:
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def signature(m: bytes, seed: bytes, pk: bytes) -> bytes:
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(h[b // 8:b // 4] + m)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % _l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % q == 0


def _decodeint(s):
    return sum(2 ** i * _bit(s, i) for i in range(0, b))


def _decodepoint(s):
    y = sum(2 ** i * _bit(s, i) for i in range(0, b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("titik tidak di kurva")
    return P


def checkvalid(sig: bytes, m: bytes, pk: bytes) -> bool:
    """True bila tanda tangan valid; False bila tidak."""
    try:
        if len(sig) != b // 4 or len(pk) != b // 8:
            return False
        R = _decodepoint(sig[0:b // 8])
        A = _decodepoint(pk)
        S = _decodeint(sig[b // 8:b // 4])
        h = _Hint(_encodepoint(R) + pk + m)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False

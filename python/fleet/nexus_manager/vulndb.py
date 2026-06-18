# nexus_manager/vulndb.py
"""
Vulnerability Detection (ala-Wazuh) — korelasi software inventory ↔ CVE.

Agent mengirim inventori software (nama+versi); manager mencocokkannya dengan
basis data kerentanan (offline, bisa diperbarui vendor). Versi terpasang yang
LEBIH RENDAH dari versi perbaikan → temuan kerentanan → alert.

DB default berisi CVE umum yang berdampak tinggi. Vendor/operator dapat
memperbarui via POST /vulndb (admin) atau mengganti seluruh daftar.
"""

# Pencocokan: `product` dicocokkan sebagai substring (lowercase) terhadap nama
# paket; `fixed` = versi pertama yang sudah aman.
DEFAULT_VULN_DB = [
    {"product": "openssl", "fixed": "1.1.1t", "cve": "CVE-2023-0286", "severity": "high",
     "cvss": 7.4, "mitre": ["T1190"], "title": "OpenSSL X.400 type confusion (X.509)"},
    {"product": "openssl", "fixed": "3.0.7", "cve": "CVE-2022-3602", "severity": "high",
     "cvss": 7.5, "mitre": ["T1190"], "title": "OpenSSL X.509 buffer overflow (punycode)"},
    {"product": "openssh", "fixed": "9.3", "cve": "CVE-2023-38408", "severity": "high",
     "cvss": 9.8, "mitre": ["T1210"], "title": "OpenSSH ssh-agent RCE (PKCS#11)"},
    {"product": "log4j", "fixed": "2.17.1", "cve": "CVE-2021-44228", "severity": "critical",
     "cvss": 10.0, "mitre": ["T1190"], "title": "Log4Shell — Log4j JNDI RCE"},
    {"product": "sudo", "fixed": "1.9.5", "cve": "CVE-2021-3156", "severity": "high",
     "cvss": 7.8, "mitre": ["T1068"], "title": "Sudo Baron Samedit heap overflow (LPE)"},
    {"product": "nginx", "fixed": "1.21.0", "cve": "CVE-2021-23017", "severity": "high",
     "cvss": 7.7, "mitre": ["T1190"], "title": "nginx DNS resolver off-by-one"},
    {"product": "httpd", "fixed": "2.4.51", "cve": "CVE-2021-42013", "severity": "critical",
     "cvss": 9.8, "mitre": ["T1190"], "title": "Apache httpd path traversal/RCE"},
    {"product": "apache", "fixed": "2.4.51", "cve": "CVE-2021-42013", "severity": "critical",
     "cvss": 9.8, "mitre": ["T1190"], "title": "Apache httpd path traversal/RCE"},
    {"product": "bash", "fixed": "4.3", "cve": "CVE-2014-6271", "severity": "critical",
     "cvss": 9.8, "mitre": ["T1190"], "title": "Shellshock — Bash env RCE"},
    {"product": "curl", "fixed": "7.84.0", "cve": "CVE-2022-32207", "severity": "high",
     "cvss": 9.8, "mitre": ["T1190"], "title": "curl cookie file overwrite"},
    {"product": "git", "fixed": "2.35.2", "cve": "CVE-2022-24765", "severity": "medium",
     "cvss": 6.2, "mitre": ["T1059"], "title": "Git multi-user repo privilege issue"},
    {"product": "python", "fixed": "3.9.2", "cve": "CVE-2021-3177", "severity": "high",
     "cvss": 9.8, "mitre": ["T1190"], "title": "Python ctypes buffer overflow"},
    {"product": "node", "fixed": "18.20.4", "cve": "CVE-2024-22020", "severity": "medium",
     "cvss": 6.5, "mitre": ["T1190"], "title": "Node.js bypass network import restriction"},
    {"product": "7-zip", "fixed": "21.07", "cve": "CVE-2022-29072", "severity": "high",
     "cvss": 7.8, "mitre": ["T1068"], "title": "7-Zip privilege escalation (help)"},
    {"product": "putty", "fixed": "0.81", "cve": "CVE-2024-31497", "severity": "high",
     "cvss": 7.4, "mitre": ["T1552"], "title": "PuTTY NIST P-521 ECDSA key recovery"},
    {"product": "jenkins", "fixed": "2.442", "cve": "CVE-2024-23897", "severity": "critical",
     "cvss": 9.8, "mitre": ["T1083"], "title": "Jenkins CLI arbitrary file read (RCE)"},
]

import re as _re
# Versi = angka dgn MINIMAL satu titik (mis. 1.1.1, 14.34) -> tahun polos (2015) terabaikan.
_VER_RE = _re.compile(r"\d+(?:\.\d+){1,3}")
_YEAR_RE = _re.compile(r"^(?:19|20)\d{2}$")


def _extract_version(name, version):
    """Ambil versi dari field version; bila kosong, urai dari nama — lewati tahun."""
    if version and any(ch.isdigit() for ch in str(version)):
        return str(version)
    for m in _VER_RE.finditer(str(name or "")):
        tok = m.group(0)
        if _YEAR_RE.match(tok.split(".")[0]):     # token diawali tahun -> bukan versi
            continue
        return tok
    return ""


def _product_in(product, name):
    """Cocok produk sebagai KATA UTUH (anti false-positive: 'git' tak cocok 'GitHub')."""
    try:
        return _re.search(r"(?<![a-z0-9])" + _re.escape(product) + r"(?![a-z0-9])", name) is not None
    except Exception:
        return product in name


def _parse_ver(v):
    out = []
    for part in str(v or "").replace("-", ".").replace("p", ".").split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return out


def _vless(a, b):
    """True bila versi a < b (perbandingan numerik per komponen)."""
    pa, pb = _parse_ver(a), _parse_ver(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa < pb


def match(packages, db=None):
    """Cocokkan list paket [{name,version}] dgn DB. Kembalikan list temuan."""
    db = db if db is not None else DEFAULT_VULN_DB
    findings = []
    seen = set()
    for pkg in packages or []:
        name = str(pkg.get("name", "")).lower()
        ver = _extract_version(pkg.get("name", ""), pkg.get("version", ""))
        if not name or not ver:
            continue
        for entry in db:
            if _product_in(entry["product"], name) and _vless(ver, entry["fixed"]):
                key = (name, entry["cve"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "package": pkg.get("name"), "installed": ver,
                    "fixed": entry["fixed"], "cve": entry["cve"],
                    "severity": entry["severity"], "cvss": entry.get("cvss"),
                    "mitre": entry.get("mitre", []), "title": entry["title"],
                })
    return findings

#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji modul desktop (python/modules/) via jalur DEMO / fallback tanpa tool eksternal.

Dijalankan TANPA biner eksternal terpasang: NEXUS_FORCE_DEMO=1 memaksa
tool_available()→False sehingga port_scanner/vuln_scanner memakai jalur demo.
Modul stdlib-murni (dns_recon, hash_tool, log_analyzer, security_score, dir_fuzz)
diuji pada logika lokal yang deterministik (tanpa jaringan).

Diinvokasi lewat jalur yang SAMA dengan GUI bila praktis (runner.dispatch),
selain memanggil run() modul langsung. Semua hasil divalidasi sbg dict berbentuk
baik (JSON-serializable).
"""
import os
import sys
import json
import tempfile

# Windows: paksa stdout UTF-8 agar karakter non-ASCII (panah, dsb.) tak crash cp1252.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)

# KRITIS: aktifkan SEBELUM import modul.
#  - NEXUS_FORCE_DEMO=1 → tool_available()→False (paksa jalur demo, tanpa biner).
#  - NEXUS_NO_DEMO=0    → demo_disabled()→False sehingga simulate_stream() TIDAK
#    mengangkat DemoDisabled. Harus eksplisit "0": default proyek adalah no_demo=True
#    (mode eksekusi nyata), jadi sekadar meng-unset env tidak cukup.
#  - NEXUS_DB_PATH terisolasi → security_score menulis ke DB sementara, bukan nyata.
os.environ["NEXUS_FORCE_DEMO"] = "1"
os.environ["NEXUS_NO_DEMO"] = "0"
_tmp = tempfile.mkdtemp(prefix="nexus_desktop_test_")
os.environ["NEXUS_DB_PATH"] = os.path.join(_tmp, "nexus.db")

import runner                                  # noqa: E402  (GUI dispatcher)
from modules import dns_recon, hash_tool, log_analyzer, security_score, dir_fuzz  # noqa: E402

FAILED = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


def is_jsonable(obj):
    try:
        json.dumps(obj)
        return True
    except Exception:
        return False


def main():
    # ----------------------------------------------------------- dns_recon
    print("== dns_recon (logika; domain rusak → error berbentuk baik) ==")
    # Domain kosong → error dict tanpa jaringan.
    r = dns_recon.run("")
    check("dns_recon domain kosong → dict dgn error",
          isinstance(r, dict) and r.get("module") == "dns_recon" and "error" in r)
    # Normalisasi domain (logika murni, tanpa resolusi nyata yg perlu).
    check("dns_recon normalisasi buang skema/path",
          dns_recon._normalize_domain("https://Example.COM/path?x=1") == "example.com")
    check("dns_recon normalisasi buang port & userinfo",
          dns_recon._normalize_domain("user@host.test:8080") == "host.test")

    # ----------------------------------------------------------- hash_tool
    print("== hash_tool identify (stdlib murni) ==")
    md5 = "5f4dcc3b5aa765d61d8327deb882cf99"  # 32 hex
    r = hash_tool.run(submode="identify", hash=md5)
    check("hash_tool identify → dict berbentuk baik",
          isinstance(r, dict) and r["module"] == "hash_tool" and r["submode"] == "identify")
    names = [c["name"] for c in r["candidates"]]
    check("hash_tool 32-hex → kandidat MD5/NTLM", "MD5" in names and "NTLM" in names)
    check("hash_tool length dilaporkan benar", r["length"] == 32)
    bcrypt = "$2b$12$" + "a" * 53
    rb = hash_tool.run(submode="identify", hash=bcrypt)
    check("hash_tool bcrypt dikenali",
          any(c["name"] == "bcrypt" for c in rb["candidates"]))
    re = hash_tool.run(submode="identify", hash="")
    check("hash_tool input kosong → error dict", "error" in re and re["candidates"] == [])

    # ----------------------------------------------------------- log_analyzer
    print("== log_analyzer (demo fallback: file tak ada) ==")
    r = log_analyzer.run(log_path="/nonexistent/path.log")
    check("log_analyzer → dict berbentuk baik",
          isinstance(r, dict) and r["module"] == "log" and "anomalies" in r)
    check("log_analyzer demo mendeteksi anomali", r["total"] >= 3)
    types = {a["attack_type"] for a in r["anomalies"]}
    check("log_analyzer mendeteksi SSH brute-force & SQLi (demo)",
          "SSH Brute Force" in types and "SQL Injection" in types)
    check("log_analyzer by_severity terisi", isinstance(r["by_severity"], dict) and r["by_severity"])
    # Logika nyata atas file log buatan (bukan demo).
    logf = os.path.join(_tmp, "real.log")
    with open(logf, "w", encoding="utf-8") as f:
        f.write('1.2.3.4 - - "GET /p?id=1 UNION SELECT a,b FROM users" 200\n')
        f.write('5.6.7.8 - - "GET /../../../../etc/passwd HTTP/1.1" 404\n')
    rr = log_analyzer.run(log_path=logf)
    real_types = {a["attack_type"] for a in rr["anomalies"]}
    check("log_analyzer file nyata: SQLi & Directory Traversal terdeteksi",
          "SQL Injection" in real_types and "Directory Traversal" in real_types)

    # ----------------------------------------------------------- security_score
    print("== security_score (compute, DB terisolasi) ==")
    calc = security_score.SecurityScoreCalculator()
    s = calc.calculate({"unnecessary_open_ports": 0, "vuln_counts": {},
                        "tls_critical_findings": 0, "weak_credentials_found": 0,
                        "lynis_index": 100})
    check("security_score sempurna → grade A & skor tinggi",
          s["grade"] == "A" and s["overall_score"] >= 90)
    sbad = calc.calculate({"unnecessary_open_ports": 10,
                           "vuln_counts": {"critical": 5, "high": 5},
                           "tls_critical_findings": 4, "weak_credentials_found": 5,
                           "lynis_index": 10})
    check("security_score buruk → grade rendah (D/F)", sbad["grade"] in ("D", "F"))
    check("security_score breakdown punya semua pilar",
          set(s["breakdown"].keys()) == set(security_score.SecurityScoreCalculator.WEIGHTS.keys()))
    # run() penuh: agregasi DB (kosong/tak ada tabel → default) + simpan history.
    rs = security_score.run()
    check("security_score run() → dict berbentuk baik",
          isinstance(rs, dict) and rs["module"] == "score" and "overall_score" in rs)

    # ----------------------------------------------------------- dir_fuzz
    print("== dir_fuzz (logika wordlist/normalisasi; tanpa jaringan) ==")
    check("dir_fuzz normalisasi target tambah skema default",
          dir_fuzz._normalize_target("example.com") == "http://example.com")
    check("dir_fuzz normalisasi pertahankan https & buang trailing slash",
          dir_fuzz._normalize_target("https://x.test/") == "https://x.test")
    paths = dir_fuzz._load_wordlist("", "php,bak")
    check("dir_fuzz wordlist bawaan termuat", len(paths) > 50)
    check("dir_fuzz ekstensi ditambahkan ke entri tanpa titik",
          "admin.php" in paths and "admin.bak" in paths)
    check("dir_fuzz file (punya titik) tak diberi ekstensi tambahan",
          "robots.txt.php" not in paths)
    rdf = dir_fuzz.run("", "")
    check("dir_fuzz target kosong → error dict",
          isinstance(rdf, dict) and "error" in rdf)

    # ----------------------------------------------------------- port_scanner (demo via dispatch)
    print("== port_scanner demo-fallback via runner.dispatch (jalur GUI) ==")
    rp = runner.dispatch("port_scan", {"target": "demo.local", "mode": "standard"})
    check("port_scan dispatch → dict berbentuk baik",
          isinstance(rp, dict) and rp["module"] == "port" and "ports" in rp)
    check("port_scan demo mengembalikan port", len(rp["ports"]) >= 3)
    check("port_scan port entry punya port/service",
          all("port" in p and "service" in p for p in rp["ports"]))
    check("port_scan hasil JSON-serializable", is_jsonable(rp))

    # ----------------------------------------------------------- vuln_scanner (demo via dispatch)
    print("== vuln_scanner demo-fallback via runner.dispatch (jalur GUI) ==")
    rv = runner.dispatch("vuln_scan", {"target": "http://demo.local",
                                       "tools": "nikto,gobuster,nuclei"})
    # vuln_scan adalah command Pro: di lingkungan tanpa lisensi (mis. CI), gerbang
    # mengembalikan dict 'locked'. Uji jalur demo modul secara langsung — perilaku
    # demo identik, tanpa bergantung pada lisensi desktop.
    if isinstance(rv, dict) and rv.get("locked"):
        from modules import vuln_scanner
        rv = vuln_scanner.run("http://demo.local", "nikto,gobuster,nuclei",
                              "wordlists/common_dirs.txt")
    check("vuln_scan dispatch → dict berbentuk baik",
          isinstance(rv, dict) and rv["module"] == "vuln" and "vulnerabilities" in rv)
    check("vuln_scan demo mengembalikan temuan", rv["total"] >= 1)
    check("vuln_scan demo mengembalikan direktori (gobuster)", len(rv["directories"]) >= 1)
    check("vuln_scan temuan punya tool & severity",
          all("tool" in v and "severity" in v for v in rv["vulnerabilities"]))
    check("vuln_scan hasil JSON-serializable", is_jsonable(rv))

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES DESKTOP TOOLS LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

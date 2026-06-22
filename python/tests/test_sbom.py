#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji modul SBOM (python/modules/sbom.py) — supply-chain shift-left.

Stdlib-murni, offline, deterministik. Membuat manifest sampel di temp dir
terisolasi lalu memverifikasi:
  - parsing komponen multi-ekosistem (pypi/npm),
  - temuan vuln dari DB seed terdeteksi,
  - emit CycloneDX bekerja,
  - semantik exit-code CI gate (ok=false saat ada high/critical),
  - jalur GUI lewat runner.dispatch('sbom_scan'),
  - jalur CLI `scan`/`sbom` mengembalikan exit non-zero saat gate gagal.
"""
import os
import sys
import json
import tempfile

# Windows: paksa stdout UTF-8 agar karakter non-ASCII tak crash cp1252.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)

# Mode demo eksplisit off (modul ini tak butuh demo), tapi set agar konsisten.
os.environ["NEXUS_NO_DEMO"] = "0"

from modules import sbom          # noqa: E402
import runner                     # noqa: E402  (GUI dispatcher)

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


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _make_fixtures(root):
    # requirements.txt — django vulnerable (<3.2.18), requests aman (>=2.31.0).
    _write(os.path.join(root, "requirements.txt"),
           "# project deps\n"
           "Django==3.1.0\n"
           "requests>=2.31.0\n"
           "flask==2.0.0           # vulnerable (<2.2.5)\n"
           "pyyaml==3.13           # known-bad pin + vuln\n")
    # package.json — lodash vulnerable (<4.17.21).
    _write(os.path.join(root, "package.json"), json.dumps({
        "name": "fixture-app",
        "version": "1.0.0",
        "dependencies": {"lodash": "4.17.20", "left-pad": "1.3.0"},
        "devDependencies": {"minimist": "1.2.5"},
    }, indent=2))
    # Manifest dalam dir yang harus DILEWATI (node_modules) — tak boleh ikut.
    nm = os.path.join(root, "node_modules", "ignored")
    os.makedirs(nm, exist_ok=True)
    _write(os.path.join(nm, "package.json"), json.dumps({
        "dependencies": {"should-not-appear": "9.9.9"}}))
    # go.mod
    _write(os.path.join(root, "go.mod"),
           "module example.com/app\n\ngo 1.21\n\n"
           "require (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n")


def main():
    tmp = tempfile.mkdtemp(prefix="nexus_sbom_test_")
    _make_fixtures(tmp)

    # ----------------------------------------------------------- parsing
    print("== sbom.run parsing (multi-ekosistem) ==")
    r = sbom.run(path=tmp)
    check("sbom run() → dict berbentuk baik",
          isinstance(r, dict) and r.get("module") == "sbom" and "components" in r)
    check("sbom hasil JSON-serializable", is_jsonable(r))
    names = {(c["ecosystem"], c["name"]) for c in r["components"]}
    check("parse requirements.txt (pypi django)", ("pypi", "django") in names)
    check("parse package.json (npm lodash)", ("npm", "lodash") in names)
    check("parse go.mod (go gin)", ("go", "github.com/gin-gonic/gin") in names)
    check("node_modules DILEWATI (tak ada should-not-appear)",
          all(c["name"] != "should-not-appear" for c in r["components"]))
    dj = [c for c in r["components"] if c["name"] == "django"]
    check("django version terurai 3.1.0", dj and dj[0]["version"].startswith("3.1"))

    # ----------------------------------------------------------- vuln findings (seed DB)
    print("== sbom temuan vuln dari DB seed ==")
    fcomps = {f["component"] for f in r["findings"]}
    check("django (3.1.0 < 3.2.18) → temuan vuln", "Django" in fcomps or "django" in fcomps)
    check("lodash (4.17.20 < 4.17.21) → temuan vuln", "lodash" in fcomps)
    check("requests (>=2.31.0) → AMAN (tak ada temuan)", "requests" not in fcomps)
    cves = {f.get("cve") for f in r["findings"] if f.get("cve")}
    check("temuan menyertakan CVE id", len(cves) >= 1)
    check("vulndb_source dilaporkan", bool(r.get("vulndb_source")))

    # ----------------------------------------------------------- known-bad pin + secret
    print("== sbom known-bad pin & secret detection ==")
    kinds = {f["kind"] for f in r["findings"]}
    check("pyyaml==3.13 → known_bad_pin terdeteksi", "known_bad_pin" in kinds)
    # secret di manifest: tulis requirements dgn token plaintext.
    sroot = tempfile.mkdtemp(prefix="nexus_sbom_secret_")
    _write(os.path.join(sroot, "package.json"), json.dumps({
        "dependencies": {"x": "1.0.0"},
        "config": {"api_key": "supersecretvalue123"}}))
    rs = sbom.run(path=sroot)
    check("plaintext secret di manifest terdeteksi",
          any(f["kind"] == "plaintext_secret" for f in rs["findings"]))

    # ----------------------------------------------------------- CI gate semantics
    print("== sbom CI-gate exit semantics ==")
    check("ada high/critical → ok=false (gate gagal)",
          r["ok"] is False and r["gate_failed"] is True)
    check("counts punya 4 tingkat severity",
          set(r["counts"].keys()) == {"critical", "high", "medium", "low"})
    check("counts high+critical > 0", (r["counts"]["critical"] + r["counts"]["high"]) > 0)
    # Proyek bersih → ok=true.
    clean = tempfile.mkdtemp(prefix="nexus_sbom_clean_")
    _write(os.path.join(clean, "requirements.txt"), "requests>=2.31.0\n")
    rc = sbom.run(path=clean)
    check("proyek bersih → ok=true (gate lolos)",
          rc["ok"] is True and rc["gate_failed"] is False)
    check("proyek bersih → tetap punya komponen", rc["total_components"] >= 1)

    # ----------------------------------------------------------- CycloneDX emit
    print("== sbom emit CycloneDX ==")
    bom = sbom.emit_cyclonedx(r["components"], r["findings"])
    check("CycloneDX bomFormat benar", bom.get("bomFormat") == "CycloneDX")
    check("CycloneDX components terisi", len(bom.get("components", [])) >= 1)
    check("CycloneDX punya purl", all("purl" in c for c in bom["components"]))
    check("CycloneDX JSON-serializable", is_jsonable(bom))
    vuln_comp = [c for c in bom["components"] if c.get("vulnerabilities")]
    check("CycloneDX menempelkan vulnerabilities ke komponen rentan", len(vuln_comp) >= 1)
    # emit_sbom via run()
    re = sbom.run(path=tmp, emit_sbom="true")
    check("run(emit_sbom=true) menyertakan dokumen cyclonedx",
          isinstance(re.get("cyclonedx"), dict) and re["cyclonedx"]["bomFormat"] == "CycloneDX")

    # ----------------------------------------------------------- runner.dispatch (jalur GUI)
    print("== sbom via runner.dispatch (jalur GUI) ==")
    rd = runner.dispatch("sbom_scan", {"path": tmp})
    check("dispatch sbom_scan → dict berbentuk baik",
          isinstance(rd, dict) and rd["module"] == "sbom")
    check("dispatch sbom_scan ok=false saat gate gagal", rd["ok"] is False)
    check("dispatch sbom_scan JSON-serializable", is_jsonable(rd))

    # ----------------------------------------------------------- explicit manifest
    print("== sbom manifest eksplisit ==")
    rm = sbom.run(manifest=os.path.join(tmp, "requirements.txt"))
    check("manifest eksplisit hanya urai requirements.txt",
          all(c["ecosystem"] == "pypi" for c in rm["components"]))
    rmiss = sbom.run(manifest=os.path.join(tmp, "nope.txt"))
    check("manifest hilang → ok=false + error", rmiss["ok"] is False and "error" in rmiss)

    # ----------------------------------------------------------- CLI exit-code gate
    print("== nexus_tools CLI `scan` exit-code gate ==")
    from nexus_tools import cli
    # Redirect stdout JSON ke devnull lewat --quiet agar tes tetap rapi.
    rc_fail = cli.main(["--quiet", "scan", "--path", tmp])
    check("CLI scan exit!=0 saat high/critical (gate gagal)", rc_fail != 0)
    rc_pass = cli.main(["--quiet", "scan", "--path", clean])
    check("CLI scan exit==0 saat bersih (gate lolos)", rc_pass == 0)
    rc_sbom = cli.main(["--quiet", "sbom", "--path", clean])
    check("CLI sbom (bersih) exit==0", rc_sbom == 0)

    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES SBOM LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

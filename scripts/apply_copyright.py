#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com
"""
Sisipkan header copyright ke semua file source first-party Nexus.

- Idempotent (lewati bila sudah ada).
- Menjaga shebang (.py) dan direktif ("use client"/"use server") tetap di atas.
- Mempertahankan gaya newline (LF/CRLF) tiap file (tanpa diff bising).
- Lewati: node_modules, target, .next, dist, build, python-runtime, gen, _up_,
  __pycache__, .d.ts, *.min.*, _ed25519.py (impl publik), JSON/lockfile.

Pakai:  python apply_copyright.py [--check]   (--check = laporkan saja, exit 1 bila kurang)
"""
import os
import re
import sys

MARKER = "Copyright (c) 2026 chandafa (Nexus Security)"
LINES = [
    "NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.",
    "Part of the Nexus security platform. Proprietary and confidential.",
    "Unauthorized copying, modification, or distribution is prohibited.",
    "This notice and embedded metadata must not be removed. See LICENSE / NOTICE.",
    "Contact: ck271138@gmail.com",
]

_HERE = os.path.dirname(os.path.abspath(__file__))
_NEXUS = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_NEXUS)

ROOTS = [
    (os.path.join(_NEXUS, "python"), (".py",)),
    (os.path.join(_NEXUS, "src"), (".ts", ".tsx", ".css")),
    (os.path.join(_NEXUS, "src-tauri", "src"), (".rs",)),
    (os.path.join(_NEXUS, "firebase", "functions"), (".py",)),
    (os.path.join(_NEXUS, "firebase", "admin"), (".py",)),
    (os.path.join(_ROOT, "nexus-landing", "app"), (".ts", ".tsx", ".css")),
    (os.path.join(_ROOT, "nexus-landing", "components"), (".ts", ".tsx")),
    (os.path.join(_ROOT, "nexus-landing", "lib"), (".ts", ".tsx")),
]

EXCLUDE_DIRS = {"node_modules", "target", ".next", "dist", "build",
                "python-runtime", "gen", "_up_", "__pycache__", ".git", "venv", ".venv"}
EXCLUDE_SUBSTR = ["_ed25519.py", ".d.ts", ".min."]
DIRECTIVE_RE = re.compile(r'''^["'](use client|use server|use strict)["'];?$''')


def header_for(ext: str) -> list:
    if ext == ".css":
        return ["/*"] + [" * " + ln for ln in LINES] + [" */"]
    if ext == ".py":
        return ["# " + ln for ln in LINES]
    return ["// " + ln for ln in LINES]  # ts/tsx/js/jsx/rs


def process(path: str, ext: str, check: bool) -> bool:
    with open(path, "r", encoding="utf-8", newline="") as f:
        text = f.read()
    if MARKER in text[:1500]:
        return False  # sudah ada
    if check:
        return True  # butuh header (tapi tidak menulis)

    nl = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(nl)

    i = 0
    preserved = []
    if ext == ".py":
        if lines and lines[0].startswith("#!"):
            preserved.append(lines[0]); i = 1
            if i < len(lines) and "coding" in lines[i] and lines[i].startswith("#"):
                preserved.append(lines[i]); i += 1
    elif ext in (".ts", ".tsx", ".js", ".jsx"):
        while i < len(lines):
            s = lines[i].strip()
            if s == "":
                break
            if DIRECTIVE_RE.match(s):
                preserved.append(lines[i]); i += 1
                continue
            break

    rest = lines[i:]
    out_lines = []
    if preserved:
        out_lines += preserved
    out_lines += header_for(ext)
    out_lines += [""]            # baris kosong pemisah
    out_lines += rest
    out = nl.join(out_lines)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    return True


def main():
    check = "--check" in sys.argv
    changed, missing = [], []
    for root, exts in ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            for fn in filenames:
                ext = os.path.splitext(fn)[1]
                if ext not in exts:
                    continue
                if any(s in fn for s in EXCLUDE_SUBSTR):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    if process(p, ext, check):
                        (missing if check else changed).append(os.path.relpath(p, _ROOT))
                except Exception as e:
                    print(f"[SKIP] {p}: {e}")
    if check:
        if missing:
            print(f"[!] {len(missing)} file TANPA header copyright:")
            for m in missing[:50]:
                print("   " + m)
            sys.exit(1)
        print("[OK] Semua file source punya header copyright.")
    else:
        print(f"[OK] Header copyright disisipkan ke {len(changed)} file.")
        for c in changed:
            print("   + " + c)


if __name__ == "__main__":
    main()

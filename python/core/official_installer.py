# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/official_installer.py
"""
Installer "resmi" — jembatan instalasi untuk tool yang tidak tersedia di
package manager OS. Memakai metode official tiap tool:
  - github  : unduh binary rilis resmi dari GitHub (lintas-OS, tanpa admin)
  - git     : git clone repo resmi + buat shim (tool berbasis script)
  - pip     : pip install (tool Python)
  - doc     : tidak bisa otomatis di OS ini -> tampilkan perintah/link resmi

Semua dipasang ke ~/.nexus/tools/bin (sudah masuk PATH deteksi Nexus),
tanpa butuh admin.
"""
import os
import sys
import platform
import tempfile
import zipfile
import tarfile
import shutil
import stat
import json
import subprocess
import urllib.request

from .dependency_checker import NEXUS_TOOLS_BIN
from .stream_handler import emit_line

IS_WIN = platform.system() == "Windows"
TOOLS_ROOT = os.path.dirname(NEXUS_TOOLS_BIN)  # ~/.nexus/tools

# Binary rilis resmi GitHub (Go tools -> satu file, lintas-OS).
GITHUB_RECIPES = {
    "nuclei":   {"repo": "projectdiscovery/nuclei", "bin": "nuclei"},
    "ffuf":     {"repo": "ffuf/ffuf", "bin": "ffuf"},
    "gobuster": {"repo": "OJ/gobuster", "bin": "gobuster"},
    "trivy":    {"repo": "aquasecurity/trivy", "bin": "trivy"},
    "httpx":    {"repo": "projectdiscovery/httpx", "bin": "httpx"},
    "naabu":    {"repo": "projectdiscovery/naabu", "bin": "naabu"},
}

# Tool berbasis script -> git clone repo resmi + shim ke interpreter.
GIT_RECIPES = {
    "nikto":        {"repo": "https://github.com/sullo/nikto.git",
                     "entry": os.path.join("program", "nikto.pl"), "interp": "perl",
                     "find": "nikto.pl"},
    "searchsploit": {"repo": "https://gitlab.com/exploit-database/exploitdb.git",
                     "entry": "searchsploit", "interp": "bash"},
    "lynis":        {"repo": "https://github.com/CISOfy/lynis.git",
                     "entry": "lynis", "interp": "bash"},
    "whatweb":      {"repo": "https://github.com/urbanadventurer/WhatWeb.git",
                     "entry": "whatweb", "interp": "ruby"},
}

PIP_RECIPES = {"sslyze": "sslyze", "prowler": "prowler"}
# Tool pip "berat" (banyak dependency, mis. numpy) → pasang di venv terisolasi
# agar tidak bentrok dengan Python global (cegah error f2py.exe/numpy upgrade).
ISOLATED_PIP = {"prowler"}

# Tool yang realistis hanya tersedia di Linux/WSL (butuh raw socket / kompilasi /
# driver). Bukan "error" — ditandai opsional & disarankan via WSL di Windows.
LINUX_ONLY = {"hydra", "arp-scan", "hping3", "suricata", "aircrack-ng", "lynis"}

# Link dokumentasi resmi / cara pasang per tool yang tak bisa otomatis di OS ini.
DOC_LINKS = {
    "hydra": "Linux/WSL: apt install hydra · https://github.com/vanhauser-thc/thc-hydra",
    "arp-scan": "Linux/WSL: apt install arp-scan (di Windows pakai 'arp -a' / nmap -PR)",
    "aircrack-ng": "Linux/WSL: apt install aircrack-ng (butuh adapter monitor mode)",
    "hping3": "Linux/WSL: apt install hping3",
    "suricata": "Linux/WSL: apt install suricata · atau MSI Windows: https://suricata.io/download/",
    "lynis": "Unix/WSL only: git clone https://github.com/CISOfy/lynis.git (bash required)",
    "nc": "Bagian dari Nmap (Ncat) — pasang Nmap, atau Linux/WSL: apt install netcat",
}


def _ensure_dirs():
    os.makedirs(NEXUS_TOOLS_BIN, exist_ok=True)


# Token OS lain (untuk EKSKLUSI agar tidak salah arsitektur, mis. 'win' di 'darwin').
_OTHER_OS = {
    "windows": ["linux", "darwin", "macos", "apple", "osx", "freebsd", ".deb", ".rpm"],
    "darwin": ["linux", "windows", ".exe", "freebsd", ".deb", ".rpm"],
    "linux": ["windows", "darwin", "macos", "apple", "osx", ".exe", ".deb", ".rpm"],
}


def _cur_os():
    if IS_WIN:
        return "windows"
    if platform.system() == "Darwin":
        return "darwin"
    return "linux"


def _os_tokens():
    if IS_WIN:
        return ["windows", "win64", "win32", "win-"]
    if platform.system() == "Darwin":
        return ["darwin", "macos", "apple", "osx"]
    return ["linux"]


def _arch_tokens():
    m = platform.machine().lower()
    if m in ("amd64", "x86_64", "x64"):
        return ["amd64", "x86_64", "x64", "64bit", "64-bit"]
    if m in ("arm64", "aarch64"):
        return ["arm64", "aarch64"]
    return [m]


def _os_matches(name: str) -> bool:
    """OS cocok TANPA salah-cocok (mis. 'win' tidak boleh match 'darwin')."""
    n = name.lower()
    # Tolak tegas bila mengandung token OS lain.
    if any(o in n for o in _OTHER_OS[_cur_os()]):
        return False
    if IS_WIN:
        return ("windows" in n or "win64" in n or "win32" in n or n.endswith(".exe")
                or n.endswith(".zip"))
    return any(t in n for t in _os_tokens())


def _pick_asset(assets):
    arch_t = _arch_tokens()
    bad = (".sha256", ".sha256sum", ".asc", ".sig", ".txt", ".md", "checksums", ".pem", ".deb", ".rpm")
    # Hanya aset yang OS-nya cocok (anti salah arsitektur).
    cands = [a for a in assets
             if not any(b in a["name"].lower() for b in bad) and _os_matches(a["name"])]
    if not cands:
        return None

    def score(a):
        n = a["name"].lower()
        s = 0
        if any(t in n for t in arch_t):
            s += 5
        if "windows" in n or "linux" in n or "darwin" in n:
            s += 3
        if n.endswith((".zip", ".tar.gz", ".tgz")):
            s += 2
        return s

    cands.sort(key=score, reverse=True)
    return cands[0] if cands else None


def _download(url, dest, cb):
    cb(f"[*] Mengunduh {os.path.basename(dest)} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "Nexus-Installer"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def _extract_find(archive, bin_name, cb):
    """Ekstrak arsip & temukan binary, kembalikan path-nya."""
    tmpd = tempfile.mkdtemp(prefix="nexus_ext_")
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(tmpd)
    else:
        with tarfile.open(archive) as t:
            t.extractall(tmpd)
    targets = {bin_name.lower(), (bin_name + ".exe").lower()}
    for root, _dirs, files in os.walk(tmpd):
        for fn in files:
            if fn.lower() in targets:
                return os.path.join(root, fn)
    return None


def install_github(tool, cb) -> bool:
    rec = GITHUB_RECIPES[tool]
    api = f"https://api.github.com/repos/{rec['repo']}/releases/latest"
    cb(f"[*] {tool}: mengambil rilis resmi dari github.com/{rec['repo']}")
    try:
        req = urllib.request.Request(api, headers={"User-Agent": "Nexus-Installer",
                                                   "Accept": "application/vnd.github+json"})
        data = json.load(urllib.request.urlopen(req, timeout=60))
        asset = _pick_asset(data.get("assets", []))
        if not asset:
            cb(f"[!] {tool}: tidak ada binary cocok untuk OS/arch ini.")
            return False
        tmpd = tempfile.mkdtemp(prefix="nexus_dl_")
        arch_path = os.path.join(tmpd, asset["name"])
        _download(asset["browser_download_url"], arch_path, cb)
        binpath = _extract_find(arch_path, rec["bin"], cb)
        if not binpath:
            cb(f"[!] {tool}: binary tidak ditemukan di arsip.")
            return False
        _ensure_dirs()
        target = os.path.join(NEXUS_TOOLS_BIN, rec["bin"] + (".exe" if IS_WIN else ""))
        shutil.copy2(binpath, target)
        if not IS_WIN:
            os.chmod(target, os.stat(target).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        cb(f"[OK] {tool} terpasang: {target}")
        return True
    except Exception as e:
        cb(f"[!] {tool}: gagal install resmi ({e}).")
        return False


def install_git(tool, cb) -> bool:
    rec = GIT_RECIPES[tool]
    if not shutil.which("git"):
        cb(f"[!] {tool}: butuh git untuk clone resmi.")
        return False
    interp = rec["interp"]
    # Cek interpreter (perl/ruby/bash) tersedia.
    if interp == "bash" and IS_WIN and not shutil.which("bash"):
        cb(f"[!] {tool}: script {interp} — di Windows perlu WSL/Git-Bash. Lewati.")
        return False
    if interp in ("perl", "ruby") and not shutil.which(interp):
        cb(f"[!] {tool}: butuh {interp} terpasang lebih dulu.")
        return False
    _ensure_dirs()
    dest = os.path.join(TOOLS_ROOT, tool)
    try:
        if os.path.isdir(os.path.join(dest, ".git")):
            cb(f"[*] {tool}: update repo (git pull)...")
            subprocess.run(["git", "-C", dest, "pull", "--ff-only"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        else:
            cb(f"[*] {tool}: git clone {rec['repo']} ...")
            clone = ["git", "clone", "--depth", "1"]
            if rec.get("branch"):
                clone += ["--branch", rec["branch"]]
            clone += [rec["repo"], dest]
            r = subprocess.run(clone, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=600)
            if r.returncode != 0:
                cb(f"[!] {tool}: clone gagal: {r.stderr[:160]}")
                return False

        entry = os.path.join(dest, rec["entry"])
        # Verifikasi entry file ada; bila tidak, cari berdasarkan nama (glob).
        if not os.path.isfile(entry) and rec.get("find"):
            matches = []
            for root, _d, files in os.walk(dest):
                if rec["find"] in files:
                    matches.append(os.path.join(root, rec["find"]))
            entry = matches[0] if matches else entry
        if not os.path.isfile(entry):
            cb(f"[!] {tool}: file utama tidak ditemukan di repo — lewati (tetap mode demo).")
            shutil.rmtree(dest, ignore_errors=True)
            return False

        # Buat shim di bin dir.
        if IS_WIN:
            shim = os.path.join(NEXUS_TOOLS_BIN, tool + ".bat")
            # Perl/bash dari Git (MSYS) lebih andal dengan forward-slash + cwd repo.
            fwd = entry.replace("\\", "/")
            workdir = os.path.dirname(entry)  # dir berisi script (untuk config relatif)
            with open(shim, "w", encoding="utf-8") as f:
                f.write(f'@echo off\r\ncd /d "{workdir}"\r\n{interp} "{fwd}" %*\r\n')
        else:
            shim = os.path.join(NEXUS_TOOLS_BIN, tool)
            with open(shim, "w", encoding="utf-8") as f:
                f.write(f'#!/bin/sh\nexec {interp} "{entry}" "$@"\n')
            os.chmod(shim, 0o755)
        cb(f"[OK] {tool} terpasang (shim -> {interp}).")
        return True
    except Exception as e:
        cb(f"[!] {tool}: gagal ({e}).")
        return False


def install_pip(tool, cb) -> bool:
    pkg = PIP_RECIPES[tool]
    # Tool berat → venv terisolasi (cegah bentrok numpy/f2py dengan Python global).
    if tool in ISOLATED_PIP:
        return _install_pip_venv(tool, pkg, cb)
    cb(f"[*] {tool}: pip install {pkg}")
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "--timeout", "120", "--retries", "5", pkg],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        if r.returncode == 0:
            cb(f"[OK] {tool} terpasang via pip.")
            return True
        cb(f"[!] {tool}: pip gagal: {(r.stderr or r.stdout)[-200:]}")
        return False
    except Exception as e:
        cb(f"[!] {tool}: {e}")
        return False


def _install_pip_venv(tool, pkg, cb) -> bool:
    """Pasang tool pip berat di venv terisolasi + buat shim ke executable-nya."""
    venv_dir = os.path.join(TOOLS_ROOT, "venvs", tool)
    scripts = os.path.join(venv_dir, "Scripts" if IS_WIN else "bin")
    vpy = os.path.join(scripts, "python.exe" if IS_WIN else "python")
    cb(f"[*] {tool}: membuat venv terisolasi + pip install {pkg} (bisa beberapa menit)...")
    try:
        if not os.path.isfile(vpy):
            r = subprocess.run([sys.executable, "-m", "venv", venv_dir],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            if r.returncode != 0:
                cb(f"[!] {tool}: gagal buat venv: {(r.stderr or '')[-160:]}")
                return False
        r = subprocess.run([vpy, "-m", "pip", "install", "--upgrade", "--quiet", "--timeout", "120", "--retries", "5", pkg],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1500)
        if r.returncode != 0:
            cb(f"[!] {tool}: pip(venv) gagal: {(r.stderr or r.stdout)[-200:]}")
            return False
        # Shim ke executable tool di venv.
        exe = os.path.join(scripts, pkg + (".exe" if IS_WIN else ""))
        _ensure_dirs()
        if IS_WIN:
            shim = os.path.join(NEXUS_TOOLS_BIN, tool + ".bat")
            target = exe if os.path.isfile(exe) else f'"{vpy}" -m {pkg}'
            with open(shim, "w", encoding="utf-8") as f:
                if os.path.isfile(exe):
                    f.write(f'@echo off\r\n"{exe}" %*\r\n')
                else:
                    f.write(f'@echo off\r\n"{vpy}" -m {pkg} %*\r\n')
        else:
            shim = os.path.join(NEXUS_TOOLS_BIN, tool)
            with open(shim, "w", encoding="utf-8") as f:
                if os.path.isfile(exe):
                    f.write(f'#!/bin/sh\nexec "{exe}" "$@"\n')
                else:
                    f.write(f'#!/bin/sh\nexec "{vpy}" -m {pkg} "$@"\n')
            os.chmod(shim, 0o755)
        cb(f"[OK] {tool} terpasang (venv terisolasi).")
        return True
    except Exception as e:
        cb(f"[!] {tool}: {e}")
        return False


def can_auto_install(tool) -> bool:
    """Apakah tool ini punya jalur instalasi resmi otomatis di OS ini?"""
    if tool in GITHUB_RECIPES or tool in PIP_RECIPES:
        return True
    if tool in GIT_RECIPES:
        interp = GIT_RECIPES[tool]["interp"]
        if interp == "bash" and IS_WIN:
            return False
        return True
    return False


def install_official(tool, cb=None) -> bool:
    """Pasang satu tool memakai metode resmi yang sesuai. Kembalikan sukses."""
    cb = cb or emit_line
    if tool in GITHUB_RECIPES:
        return install_github(tool, cb)
    if tool in PIP_RECIPES:
        return install_pip(tool, cb)
    if tool in GIT_RECIPES:
        return install_git(tool, cb)
    link = DOC_LINKS.get(tool)
    if link:
        cb(f"[i] {tool}: belum bisa otomatis di OS ini. Dokumentasi resmi: {link}")
    else:
        cb(f"[i] {tool}: tidak ada metode instalasi otomatis.")
    return False

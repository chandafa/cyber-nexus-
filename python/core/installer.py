# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/installer.py
"""
Auto-installer tools — SDD §3.3 (Auto Install).
Menjalankan instalasi paket dengan elevasi privilege otomatis:
  - Windows : Chocolatey via UAC (Start-Process -Verb RunAs -Wait)
  - Linux   : pkexec (GUI sudo) / sudo
  - macOS   : Homebrew (tanpa sudo)
Setelah instalasi, status tiap tool diperiksa ulang dan dikembalikan
(sehingga UI bisa langsung memperbarui checklist).
"""
import subprocess
import shutil
import platform

from .dependency_checker import build_install_command, check_tool
from .stream_handler import emit_line


def install_tools(tools: list, output_callback=None) -> dict:
    cb = output_callback or emit_line
    from . import official_installer as oi
    output_lines = []
    ran = False
    error = None
    handled_official = []

    # 1. UTAMAKAN metode RESMI tanpa-admin (binary GitHub / pip / git clone).
    #    Ini menghindari UAC/Chocolatey untuk Go-tools (nuclei, ffuf, gobuster,
    #    trivy, dll.) sehingga lebih cepat & tidak berisiko membekukan UI.
    for t in tools:
        if check_tool(t)["installed"]:
            continue
        if oi.can_auto_install(t):
            cb(f"[*] {t}: instalasi resmi tanpa-admin...")
            if oi.install_official(t, cb):
                ran = True
                handled_official.append(t)

    # 2. Sisa yang belum terpasang -> pakai package manager OS.
    remaining = [t for t in tools if not check_tool(t)["installed"]]
    info = build_install_command(remaining)
    pm = info["pkg_manager"]
    packages = info["packages"]
    pip_packages = info.get("pip_packages", [])

    if pip_packages:
        cb(f"[*] Memasang via pip: {', '.join(pip_packages)}")
        try:
            import sys as _sys
            r = subprocess.run(
                [_sys.executable, "-m", "pip", "install", "--upgrade", *pip_packages],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            output_lines += [r.stdout, r.stderr]
            ran = True
        except Exception as e:  # pragma: no cover
            error = str(e)
            cb(f"[ERROR] pip: {e}")

    if packages:
        cb(f"[*] Memasang via {pm}: {', '.join(packages)}")
        try:
            ran = True
            if pm == "scoop":
                # Scoop: tanpa admin, binari bersih (ideal untuk Windows).
                scoop = shutil.which("scoop") or "scoop"
                r = subprocess.run([scoop, "install", *packages],
                                   capture_output=True, text=True, encoding="utf-8", errors="replace", shell=False)
                output_lines += [r.stdout, r.stderr]
            elif pm == "choco":
                cb("[*] Meminta izin Administrator (UAC) untuk Chocolatey...")
                if not shutil.which("choco"):
                    raise RuntimeError(
                        "Chocolatey belum terpasang. Pasang Chocolatey atau Scoop dulu. "
                        "Scoop disarankan (tanpa admin): "
                        "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser; "
                        "irm get.scoop.sh | iex"
                    )
                arg_list = ",".join(f"'{p}'" for p in (["install", "-y"] + packages))
                ps = f"Start-Process -FilePath 'choco' -ArgumentList {arg_list} -Verb RunAs -Wait"
                r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                   capture_output=True, text=True, encoding="utf-8", errors="replace")
                output_lines += [r.stdout, r.stderr]
            elif pm == "brew":
                r = subprocess.run(["brew", "install", *packages], capture_output=True, text=True, encoding="utf-8", errors="replace")
                output_lines += [r.stdout, r.stderr]
            elif pm in ("apt", "dnf", "yum", "zypper", "pacman"):
                cb("[*] Meminta izin root (pkexec/sudo)...")
                cmd = info["command"]  # sudah mengandung 'sudo ...'
                if shutil.which("pkexec"):
                    r = subprocess.run(["pkexec", "sh", "-c", cmd.replace("sudo ", "")],
                                       capture_output=True, text=True, encoding="utf-8", errors="replace")
                else:
                    r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, encoding="utf-8", errors="replace")
                output_lines += [r.stdout, r.stderr]
            else:
                raise RuntimeError(f"Package manager tidak didukung: {pm}")
        except Exception as e:  # pragma: no cover
            error = str(e)
            cb(f"[ERROR] {e}")

    # 3. Periksa ulang status tiap tool agar UI bisa update checklist.
    results = {t: check_tool(t)["installed"] for t in tools}
    installed_now = [t for t, ok in results.items() if ok]
    if installed_now:
        cb(f"[OK] Terpasang: {', '.join(installed_now)}")

    not_installed = [t for t in tools if not results.get(t)]
    # Pisahkan: tool Linux/WSL (opsional, bukan error) vs yang benar2 gagal.
    linux_only = [t for t in not_installed if t in oi.LINUX_ONLY]
    manual = [t for t in not_installed if t not in oi.LINUX_ONLY]
    if linux_only:
        cb(f"[i] Opsional (hanya Linux/WSL — bukan error): {', '.join(linux_only)}")
    for t in not_installed:
        link = oi.DOC_LINKS.get(t)
        if link:
            cb(f"[i] {t}: {link}")

    return {
        "module": "install_run",
        "pkg_manager": pm,
        "ran": ran,
        "manual": manual,
        "linux_only": linux_only,
        "official_installed": handled_official,
        "doc_links": {t: oi.DOC_LINKS.get(t, "") for t in not_installed},
        "results": results,
        "output": "\n".join([l for l in output_lines if l]).strip(),
        "error": error,
        # "Berhasil" jika semua yang BUKAN linux-only sudah terpasang.
        "success": all(results.get(t) for t in tools if t not in oi.LINUX_ONLY) if tools else False,
    }

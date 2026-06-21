# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/subprocess_runner.py
"""
Subprocess runner — pembungkus aman untuk menjalankan security tools.
Sesuai SDD: streaming output line-by-line, demo fallback bila tool tidak ada.
"""
import subprocess
import shutil
import platform
import time
from typing import Callable, List, Optional

from .stream_handler import emit_line


def tool_available(name: str) -> bool:
    """Cek apakah sebuah tool tersedia (PATH, alias Windows, atau modul Python).
    Jika NEXUS_FORCE_DEMO=1 (mode fallback global), selalu kembalikan False
    agar modul memakai jalur demo yang dijamin aman."""
    import os
    if os.environ.get('NEXUS_FORCE_DEMO') == '1':
        return False
    try:
        from .dependency_checker import PYTHON_MODULE_TOOLS, _module_available
        if name in PYTHON_MODULE_TOOLS and _module_available(PYTHON_MODULE_TOOLS[name]):
            return True
    except Exception:
        pass
    if _resolve_exec(name):
        return True
    alt = {'python3': 'python', 'nc': 'ncat', 'aircrack-ng': 'airodump-ng'}
    if alt.get(name) and _resolve_exec(alt[name]):
        return True
    # Fallback transparan: tool Linux-only bisa dijalankan via WSL (Windows).
    try:
        from . import wsl_backend
        if wsl_backend.should_use_wsl(name, native_available=False):
            return True
    except Exception:
        pass
    return False


def tool_argv(name: str, args: list) -> list:
    """Bangun argv lengkap untuk sebuah tool lintas-OS:
      - tool Linux-only via WSL → [wsl, -d, distro, --, name, ...]
      - tool modul Python (sslyze, prowler) → [python, -m, modul, ...]
      - .bat/.cmd Windows → cmd /c <full> ...
      - lainnya → [full_path, ...]"""
    native = _resolve_exec(name)
    # Routing WSL (auto-route transparan) bila sesuai mode backend.
    try:
        from . import wsl_backend
        if wsl_backend.should_use_wsl(name, native_available=bool(native)):
            return wsl_backend.wrap_argv(name, list(args))
    except Exception:
        pass
    if native:
        return fix_tool_cmd([name] + list(args))
    try:
        from .dependency_checker import PYTHON_MODULE_TOOLS, _module_available
        if name in PYTHON_MODULE_TOOLS and _module_available(PYTHON_MODULE_TOOLS[name]):
            import sys
            return [sys.executable, '-m', PYTHON_MODULE_TOOLS[name]] + list(args)
    except Exception:
        pass
    return fix_tool_cmd([name] + list(args))


def _resolve_exec(name: str):
    """Cari executable memakai PATH lengkap (registry + ~/.nexus/tools/bin + dll.),
    tidak hanya os.environ — agar tool yang baru di-install selalu ketemu."""
    import os
    if os.path.isabs(name) and os.path.exists(name):
        return name
    p = shutil.which(name)
    if p:
        return p
    try:
        from .dependency_checker import _search_path
        return shutil.which(name, path=_search_path())
    except Exception:
        return None


def fix_tool_cmd(cmd):
    """Lintas-OS: resolusi executable + ROUTING WSL transparan + bungkus shim
    .bat/.cmd Windows via `cmd /c`. Karena mayoritas modul memanggil tool lewat
    fungsi ini, di sinilah auto-route WSL diterapkan agar tool Linux-only (atau
    semua tool dalam mode backend 'wsl') berjalan NYATA via WSL."""
    import os
    if not cmd:
        return cmd
    name = cmd[0]
    native = _resolve_exec(name)
    # Routing WSL (sama keputusannya dengan tool_argv) — argumen path Windows
    # otomatis diterjemahkan ke path WSL (/mnt/...).
    try:
        from . import wsl_backend
        if wsl_backend.should_use_wsl(name, native_available=bool(native)):
            return wsl_backend.wrap_argv(name, list(cmd[1:]))
    except Exception:
        pass
    if not native:
        return cmd  # biarkan gagal natural -> ditangani fallback modul
    if os.name == 'nt' and native.lower().endswith(('.bat', '.cmd')):
        return ['cmd', '/c', native] + list(cmd[1:])
    return [native] + list(cmd[1:])


def resolve_python() -> str:
    """Kembalikan executable python yang benar untuk OS ini."""
    if platform.system() == 'Windows':
        return shutil.which('python') or shutil.which('python3') or 'python'
    return shutil.which('python3') or shutil.which('python') or 'python3'


def run_streaming(
    cmd: List[str],
    output_callback: Optional[Callable[[str], None]] = None,
    timeout: Optional[int] = None,
) -> int:
    """
    Jalankan command, stream stdout+stderr baris-per-baris ke callback.
    Kembalikan exit code. Tidak pernah memakai shell=True (anti injection).
    """
    cb = output_callback or emit_line
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            bufsize=1,
        )
    except FileNotFoundError:
        cb(f"[ERROR] Tool tidak ditemukan: {cmd[0]}")
        return 127
    except Exception as e:  # pragma: no cover
        cb(f"[ERROR] Gagal menjalankan: {e}")
        return 1

    start = time.time()
    assert proc.stdout is not None
    for line in proc.stdout:
        cb(line.rstrip('\n'))
        if timeout and (time.time() - start) > timeout:
            proc.terminate()
            cb(f"[WARN] Timeout {timeout}s tercapai, proses dihentikan.")
            break
    proc.wait()
    return proc.returncode


class DemoDisabled(RuntimeError):
    """Diangkat ketika mode eksekusi-nyata aktif tapi sebuah modul mencoba
    fallback ke demo. Membuat error nyata muncul, bukan data palsu."""


def demo_disabled() -> bool:
    """True bila pengguna mengaktifkan 'Mode Eksekusi Nyata' (tanpa demo)."""
    import os
    if os.environ.get('NEXUS_NO_DEMO', '').lower() in ('1', 'true', 'yes', 'on'):
        return True
    try:
        from . import wsl_backend
        return wsl_backend.get_no_demo()
    except Exception:
        return False


def simulate_stream(lines: List[str], output_callback: Optional[Callable] = None,
                    delay: float = 0.04) -> None:
    """
    Demo fallback: streaming baris contoh agar terasa seperti output nyata.
    Bila mode eksekusi-nyata aktif (NEXUS_NO_DEMO), JANGAN keluarkan data palsu —
    angkat DemoDisabled agar error nyata yang muncul ke pengguna.
    """
    cb = output_callback or emit_line
    if demo_disabled():
        cb('[REAL] Mode eksekusi nyata aktif — fallback demo dinonaktifkan. '
           'Menampilkan error nyata (tool gagal / tidak tersedia / butuh privilege).')
        raise DemoDisabled('demo dinonaktifkan (NEXUS_NO_DEMO)')
    for line in lines:
        cb(line)
        if delay:
            time.sleep(delay)

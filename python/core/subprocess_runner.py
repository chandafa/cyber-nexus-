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
    return bool(alt.get(name) and _resolve_exec(alt[name]))


def tool_argv(name: str, args: list) -> list:
    """Bangun argv lengkap untuk sebuah tool lintas-OS:
      - tool modul Python (sslyze, prowler) → [python, -m, modul, ...]
      - .bat/.cmd Windows → cmd /c <full> ...
      - lainnya → [full_path, ...]"""
    if _resolve_exec(name):
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
    """Lintas-OS: resolusi executable + bungkus shim .bat/.cmd Windows via `cmd /c`.
    Resolusi pakai PATH lengkap sehingga tool di ~/.nexus/tools/bin tetap ketemu
    walau belum masuk os.environ PATH."""
    import os
    if not cmd:
        return cmd
    full = _resolve_exec(cmd[0])
    if not full:
        return cmd  # biarkan gagal natural -> ditangani fallback modul
    if os.name == 'nt' and full.lower().endswith(('.bat', '.cmd')):
        return ['cmd', '/c', full] + list(cmd[1:])
    return [full] + list(cmd[1:])


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


def simulate_stream(lines: List[str], output_callback: Optional[Callable] = None,
                    delay: float = 0.04) -> None:
    """
    Demo fallback: streaming baris contoh dengan jeda kecil agar terasa
    seperti output nyata. Dipakai saat tool tidak terpasang.
    """
    cb = output_callback or emit_line
    for line in lines:
        cb(line)
        if delay:
            time.sleep(delay)

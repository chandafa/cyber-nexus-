# nexus/python/core/wsl_backend.py
"""
Backend WSL — menjalankan tool keamanan yang hanya tersedia di Linux melalui
WSL (Windows Subsystem for Linux) di komputer yang sama, secara transparan.

Strategi (dipilih user): "WSL lokal + auto-route".
  - backend = "auto"    -> pakai tool native Windows bila ada; bila tidak ada
                           native tapi ada di WSL, jalankan via WSL otomatis.
  - backend = "windows" -> selalu native Windows (tidak pernah WSL).
  - backend = "wsl"     -> utamakan WSL bila tool ada di sana.

Preferensi disimpan di ~/.nexus/config.json (juga bisa di-override env
NEXUS_BACKEND / NEXUS_WSL_DISTRO). File ini ditulis oleh frontend (Settings)
lewat command `set_backend`, lalu dibaca tiap kali scan dijalankan.
"""
import os
import re
import json
import shlex
import shutil
import platform
import subprocess

# Path absolut Windows (C:\..., D:/...) — diterjemahkan ke /mnt/... untuk WSL.
_WIN_ABS = re.compile(r'^[A-Za-z]:[\\/]')

IS_WIN = platform.system() == "Windows"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".nexus", "config.json")

# Cache hasil deteksi (mahal: tiap panggilan spawn wsl.exe).
_cache = {}


def _wsl_exe() -> str:
    return shutil.which("wsl") or shutil.which("wsl.exe") or "wsl.exe"


def _decode(b: bytes) -> str:
    """wsl.exe sering menulis UTF-16LE; tool di dalamnya UTF-8. Pilih otomatis."""
    if not b:
        return ""
    if b"\x00" in b:
        return b.decode("utf-16-le", "replace")
    return b.decode("utf-8", "replace")


def _run(cmd, timeout=20):
    return subprocess.run(cmd, capture_output=True, timeout=timeout)


# --------------------------------------------------------------- konfigurasi
def load_config() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def get_backend() -> str:
    val = os.environ.get("NEXUS_BACKEND") or load_config().get("backend", "auto")
    val = str(val).lower().strip()
    return val if val in ("auto", "windows", "wsl") else "auto"


def set_backend(backend: str = "", distro: str = "", no_demo=None, wsl_user: str = "") -> dict:
    cfg = load_config()
    backend = str(backend).lower().strip()
    if backend in ("auto", "windows", "wsl"):
        cfg["backend"] = backend
    if distro:
        cfg["wsl_distro"] = distro
    if no_demo is not None:
        cfg["no_demo"] = str(no_demo).lower() in ("1", "true", "yes", "on")
    if wsl_user:
        cfg["wsl_user"] = wsl_user
    save_config(cfg)
    return {"backend": cfg.get("backend", "auto"),
            "wsl_distro": cfg.get("wsl_distro", ""),
            "no_demo": cfg.get("no_demo", False),
            "wsl_user": cfg.get("wsl_user", "root")}


def get_wsl_user() -> str:
    """User WSL untuk eksekusi tool. Default 'root' (privilege penuh, tanpa
    prompt password). 'default' = user default distro."""
    return os.environ.get("NEXUS_WSL_USER") or load_config().get("wsl_user", "root")


def get_no_demo() -> bool:
    """Mode eksekusi nyata: bila True, NONAKTIFKAN fallback demo — tool yang
    gagal memunculkan error nyata, bukan data palsu."""
    env = os.environ.get("NEXUS_NO_DEMO")
    if env is not None:
        return env.lower() in ("1", "true", "yes", "on")
    return bool(load_config().get("no_demo", False))


# ------------------------------------------------------------------ deteksi
def wsl_available() -> bool:
    if not IS_WIN:
        return False
    if "available" not in _cache:
        _cache["available"] = len(list_distros()) > 0
    return _cache["available"]


def list_distros() -> list:
    """Daftar distro WSL terinstall (yang berstatus bisa dipakai)."""
    if not IS_WIN:
        return []
    if "distros" in _cache:
        return _cache["distros"]
    distros = []
    try:
        p = _run([_wsl_exe(), "-l", "-q"])
        if p.returncode == 0:
            for ln in _decode(p.stdout).replace("\r", "").split("\n"):
                name = ln.strip()
                if name:
                    distros.append(name)
    except Exception:
        distros = []
    _cache["distros"] = distros
    return distros


def default_distro() -> str:
    cfg_distro = os.environ.get("NEXUS_WSL_DISTRO") or load_config().get("wsl_distro", "")
    distros = list_distros()
    if cfg_distro and cfg_distro in distros:
        return cfg_distro
    return distros[0] if distros else ""


def _ensure_warm(distro: str) -> None:
    """Pastikan distro sudah hidup SEKALI per proses sebelum deteksi — mencegah
    kegagalan deteksi akibat cold-start (race saat distro baru bangun)."""
    if not distro or _cache.get(f"warm::{distro}"):
        return
    warmup(distro)
    _cache[f"warm::{distro}"] = True


def tool_in_wsl(name: str, distro: str = "") -> bool:
    """Apakah `name` dapat dieksekusi di dalam WSL (cek `command -v`)."""
    if not wsl_available():
        return False
    distro = distro or default_distro()
    if not distro:
        return False
    key = f"has::{distro}::{name}"
    if key in _cache:
        return _cache[key]
    _ensure_warm(distro)
    ok = False
    try:
        p = _run([_wsl_exe(), "-d", distro, "--", "bash", "-lc",
                  f"command -v {shlex.quote(name)}"], timeout=40)
        ok = p.returncode == 0 and bool(_decode(p.stdout).strip())
    except Exception:
        ok = False
    _cache[key] = ok
    return ok


def tools_in_wsl(names, distro: str = "") -> set:
    """Cek BANYAK tool sekaligus dalam satu pemanggilan wsl (jauh lebih cepat
    daripada satu-satu). Kembalikan set nama tool yang tersedia, sekaligus
    memperbarui cache per-tool."""
    if not wsl_available():
        return set()
    distro = distro or default_distro()
    names = [n for n in names if n]
    if not distro or not names:
        return set()
    _ensure_warm(distro)
    script = "; ".join(
        f"command -v {shlex.quote(n)} >/dev/null 2>&1 && echo {shlex.quote(n)}"
        for n in names
    )
    found = set()
    try:
        p = _run([_wsl_exe(), "-d", distro, "--", "bash", "-lc", script], timeout=60)
        found = {ln.strip() for ln in _decode(p.stdout).replace("\r", "").split("\n") if ln.strip()}
    except Exception:
        found = set()
    for n in names:
        _cache[f"has::{distro}::{n}"] = n in found
    return found


def warmup(distro: str = "") -> bool:
    """Nyalakan distro WSL lebih awal (mengurangi latensi scan pertama).
    Dipanggil saat aplikasi Nexus dibuka."""
    if not wsl_available():
        return False
    distro = distro or default_distro()
    if not distro:
        return False
    try:
        _run([_wsl_exe(), "-d", distro, "--", "true"], timeout=60)
        return True
    except Exception:
        return False


# ----------------------------------------------------- eksekusi via WSL
def _to_wsl_path(distro: str, win_path: str) -> str:
    try:
        p = _run([_wsl_exe(), "-d", distro, "--", "wslpath", "-a",
                  win_path.replace("\\", "/")])
        out = _decode(p.stdout).strip()
        return out or win_path
    except Exception:
        return win_path


def _xlate(distro: str, tok: str) -> str:
    """Terjemahkan satu token bila berupa path Windows.
    - Path absolut (C:\\..., \\\\server\\...) → selalu (walau file belum ada,
      mis. file output -oX/--json_out yang akan DIBUAT tool).
    - Path relatif → hanya bila benar-benar ada (mis. wordlist)."""
    if _WIN_ABS.match(tok) or tok.startswith("\\\\"):
        return _to_wsl_path(distro, tok)
    if os.path.exists(tok):
        return _to_wsl_path(distro, os.path.abspath(tok))
    return tok


def wrap_argv(name: str, args: list, distro: str = "") -> list:
    """Bangun argv `wsl -d <distro> -u root -- <name> <args...>`, menerjemahkan
    argumen path Windows → path WSL (/mnt/...), termasuk bentuk `--key=PATH`.

    Dijalankan sebagai root (tanpa prompt password di WSL) agar tool yang butuh
    raw socket / privilege (nmap -sS/-O, arp-scan, suricata, hping3, tshark)
    berjalan NYATA — bukan jatuh ke mode demo karena 'requires root'."""
    distro = distro or default_distro()
    out_args = []
    for a in args:
        a = str(a)
        if a.startswith("-") and "=" in a:  # bentuk --key=value
            k, _, v = a.partition("=")
            out_args.append(f"{k}={_xlate(distro, v)}" if v else a)
        else:
            out_args.append(_xlate(distro, a))
    user = [] if get_wsl_user() == "default" else ["-u", get_wsl_user()]
    return [_wsl_exe(), "-d", distro] + user + ["--", name] + out_args


def should_use_wsl(name: str, native_available: bool) -> bool:
    """Putuskan apakah tool dijalankan via WSL, sesuai mode backend."""
    if not IS_WIN or not wsl_available():
        return False
    backend = get_backend()
    if backend == "windows":
        return False
    if backend == "wsl":
        return tool_in_wsl(name)
    # auto: WSL hanya bila tidak ada native tapi ada di WSL.
    return (not native_available) and tool_in_wsl(name)


# ---------------------------------------------------------- install di WSL
def install_tools_wsl(tools: list, apt_packages: dict, cb, distro: str = "") -> dict:
    """Pasang tool ke dalam WSL via apt-get (sebagai root, tanpa prompt sudo).

    apt_packages: map {tool_name: 'nama-paket-apt' | None}.
    Kembalikan ringkasan per tool.
    """
    distro = distro or default_distro()
    if not wsl_available() or not distro:
        cb("[ERROR] WSL tidak terdeteksi. Pasang WSL dulu: jalankan 'wsl --install' "
           "di PowerShell (Administrator), lalu restart komputer.")
        return {"module": "wsl_install", "ok": False, "error": "wsl_unavailable",
                "results": {}, "distro": ""}

    pkgs = []
    skipped = []
    for t in tools:
        pkg = apt_packages.get(t)
        if pkg:
            pkgs.append(pkg)
        else:
            skipped.append(t)

    if not pkgs:
        cb("[i] Tidak ada paket apt untuk tool terpilih.")
        return {"module": "wsl_install", "ok": False, "error": "no_packages",
                "results": {}, "distro": distro, "skipped": skipped}

    pkg_str = " ".join(shlex.quote(p) for p in pkgs)
    cb(f"[*] WSL ({distro}): apt-get install {pkg_str}")
    script = ("export DEBIAN_FRONTEND=noninteractive; "
              "apt-get update && apt-get install -y " + pkg_str)
    cmd = [_wsl_exe(), "-d", distro, "-u", "root", "--", "bash", "-lc", script]

    error = None
    try:
        # Streaming output baris-per-baris ke terminal UI.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, bufsize=1)
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            if not raw:
                break
            cb(_decode(raw).rstrip("\r\n"))
        proc.wait()
        rc = proc.returncode
    except Exception as e:  # pragma: no cover
        error = str(e)
        rc = 1
        cb(f"[ERROR] {e}")

    # Verifikasi ulang per tool (reset cache dulu).
    _cache.clear()
    results = {t: tool_in_wsl(t, distro) for t in tools}
    ok = all(results.get(t) for t in tools if t not in skipped) and rc == 0
    done = [t for t, v in results.items() if v]
    if done:
        cb(f"[OK] Terpasang di WSL: {', '.join(done)}")
    failed = [t for t in tools if not results.get(t)]
    if failed:
        cb(f"[!] Belum terpasang di WSL: {', '.join(failed)}")

    return {"module": "wsl_install", "ok": ok, "error": error,
            "results": results, "distro": distro, "skipped": skipped}


def _ps_run_elevated(ps_args_list, cb, timeout=1800):
    """Jalankan satu proses ELEVATED (UAC) via PowerShell Start-Process -Verb RunAs.
    Output proses elevated tidak bisa di-stream langsung; kita kembalikan exit code.
    ps_args_list: list argumen untuk executable (mis. ['--install','--no-launch']).
    """
    arg_items = ",".join("'" + a.replace("'", "''") + "'" for a in ps_args_list)
    ps = (
        "$ErrorActionPreference='Stop';"
        f"$p = Start-Process -FilePath 'wsl.exe' -ArgumentList {arg_items} "
        "-Verb RunAs -Wait -PassThru;"
        "exit $p.ExitCode"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        cb("[ERROR] Proses instalasi WSL melebihi batas waktu.")
        return 1, "timeout"
    except Exception as e:  # pragma: no cover
        cb(f"[ERROR] Gagal menjalankan installer elevated: {e}")
        return 1, str(e)


def _init_distro(distro: str, cb) -> bool:
    """Inisialisasi distro (root) tanpa wizard interaktif; kembalikan True bila siap."""
    try:
        p = _run([_wsl_exe(), "-d", distro, "-u", "root", "--", "bash", "-lc",
                  "echo nexus-wsl-ready"], timeout=120)
        out = _decode(p.stdout)
        if "nexus-wsl-ready" in out:
            cb(f"[OK] WSL distro '{distro}' siap dipakai.")
            return True
    except Exception:
        pass
    return False


def provision_wsl(cb, tools=None, apt_packages=None, distro: str = "Ubuntu") -> dict:
    """Pasang + konfigurasi WSL otomatis (sekali klik). Bila WSL/distro belum ada,
    minta izin Administrator (UAC) lalu jalankan `wsl --install`. Setelah siap,
    opsional langsung memasang `tools` ke dalam WSL.

    Kembalikan dict status; bila butuh restart, reboot_required=True.
    """
    apt_packages = apt_packages or {}
    if not IS_WIN:
        cb("[i] Provisioning WSL hanya relevan di Windows.")
        return {"module": "wsl_provision", "ok": True, "available": False,
                "reboot_required": False, "is_windows": False}

    _cache.clear()
    # 1) Sudah ada distro yang siap?
    if wsl_available():
        d = default_distro()
        cb(f"[i] WSL sudah aktif (distro: {d}).")
        if _init_distro(d, cb) and tools:
            return {**install_tools_wsl(tools, apt_packages, cb, d),
                    "module": "wsl_provision", "ok": True, "available": True,
                    "reboot_required": False}
        return {"module": "wsl_provision", "ok": True, "available": True,
                "reboot_required": False, "distro": d}

    # 2) Belum ada → jalankan wsl --install (elevated).
    cb("[*] WSL belum aktif. Meminta izin Administrator (UAC) untuk memasang WSL...")
    cb("[*] Sebuah jendela installer Windows akan muncul. Mohon tunggu hingga selesai.")
    # `--no-launch` mencegah wizard pembuatan user interaktif yang akan menggantung.
    rc, _out = _ps_run_elevated(["--install", "-d", distro, "--no-launch"], cb)
    if rc != 0:
        # Fallback: versi wsl lama tak kenal --no-launch / -d.
        cb("[*] Mencoba metode instalasi alternatif...")
        rc, _out = _ps_run_elevated(["--install"], cb)

    _cache.clear()
    if wsl_available():
        d = default_distro()
        cb("[OK] WSL berhasil dipasang.")
        _init_distro(d, cb)
        if tools and _init_distro(d, cb):
            return {**install_tools_wsl(tools, apt_packages, cb, d),
                    "module": "wsl_provision", "ok": True, "available": True,
                    "reboot_required": False}
        return {"module": "wsl_provision", "ok": True, "available": True,
                "reboot_required": False, "distro": d}

    # 3) Terpasang tapi belum aktif → hampir selalu butuh RESTART.
    cb("[!] WSL terpasang, namun komputer perlu DI-RESTART untuk mengaktifkannya.")
    cb("[!] Silakan restart komputer, lalu buka Nexus lagi dan klik tombol ini "
       "sekali lagi untuk menyelesaikan setup + memasang tools.")
    return {"module": "wsl_provision", "ok": False, "available": False,
            "reboot_required": True}


def status(warm: bool = True) -> dict:
    """Ringkasan status WSL untuk frontend. Bila warm=True (default), distro
    dinyalakan lebih awal sehingga scan pertama tidak lambat — inilah yang
    membuat 'membuka Nexus otomatis menjalankan WSL'."""
    distros = list_distros()
    active = default_distro()
    if warm and active:
        warmup(active)
    return {
        "module": "wsl_status",
        "is_windows": IS_WIN,
        "available": wsl_available(),
        "distros": distros,
        "active_distro": active,
        "backend": get_backend(),
        "no_demo": get_no_demo(),
        "wsl_user": get_wsl_user(),
    }

# nexus/python/core/dependency_checker.py
"""
Dependency checker — memeriksa ketersediaan tools keamanan yang dibutuhkan Nexus.
Sesuai SDD bagian 3.3. Dipakai oleh Setup Wizard dan Settings.
"""
import os
import re
import shutil
import subprocess
import platform

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# Tool yang berupa modul Python (dijalankan via `python -m <modul>`), bukan .exe.
PYTHON_MODULE_TOOLS = {'sslyze': 'sslyze', 'prowler': 'prowler'}


def _module_available(mod: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False

try:
    import winreg  # Windows only
except ImportError:  # pragma: no cover
    winreg = None

# Direktori instalasi umum yang kadang tidak otomatis masuk PATH proses lama.
_COMMON_WIN_DIRS = [
    r"C:\ProgramData\chocolatey\bin",
    os.path.expanduser(r"~\scoop\shims"),
    r"C:\ProgramData\scoop\shims",
    r"C:\Program Files\Nmap",
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Wireshark",
    r"C:\Program Files\Git\bin",
    r"C:\Program Files\Git\cmd",
    r"C:\Program Files\Git\usr\bin",  # perl, bash (untuk nikto/searchsploit/lynis)
    r"C:\Program Files (x86)\Git\usr\bin",
    r"C:\tools",
    os.path.expanduser(r"~\AppData\Local\Microsoft\WinGet\Links"),
]


def _windows_registry_paths() -> list:
    """Baca PATH terbaru dari registry (HKLM + HKCU) — mencerminkan tool yang
    baru saja di-install tanpa perlu restart aplikasi."""
    paths = []
    if not winreg:
        return paths
    roots = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        (winreg.HKEY_CURRENT_USER, r"Environment"),
    ]
    for root, sub in roots:
        try:
            with winreg.OpenKey(root, sub) as k:
                val, _ = winreg.QueryValueEx(k, "Path")
                val = os.path.expandvars(val)
                paths += [p for p in val.split(os.pathsep) if p]
        except OSError:
            pass
    return paths


# Direktori bin tempat Nexus memasang tool resmi (binary GitHub / git clone shim).
NEXUS_TOOLS_BIN = os.path.join(os.path.expanduser("~"), ".nexus", "tools", "bin")


def _python_script_dirs() -> list:
    """Direktori 'Scripts'/'bin' Python tempat console-script pip (sslyze, prowler)
    dipasang, agar tool berbasis pip terdeteksi."""
    import sys
    import sysconfig
    import site
    dirs = []
    try:
        dirs.append(sysconfig.get_path("scripts"))
    except Exception:
        pass
    base = os.path.dirname(sys.executable)
    dirs += [base, os.path.join(base, "Scripts")]  # Windows
    try:
        ub = site.getuserbase()
        dirs += [os.path.join(ub, "Scripts"), os.path.join(ub, "bin")]
    except Exception:
        pass
    return [d for d in dirs if d and os.path.isdir(d)]


def _search_path() -> str:
    """Gabungkan PATH proses + PATH registry terbaru + direktori umum +
    direktori tool resmi Nexus + direktori Scripts Python (untuk tool pip)."""
    parts = [NEXUS_TOOLS_BIN] + _python_script_dirs()
    env_path = os.environ.get("PATH", "")
    if env_path:
        parts += env_path.split(os.pathsep)
    if platform.system() == "Windows":
        parts += _windows_registry_paths()
        parts += [d for d in _COMMON_WIN_DIRS if os.path.isdir(d)]
    seen, out = set(), []
    for p in parts:
        key = p.rstrip("\\/").lower()
        if p and key not in seen:
            seen.add(key)
            out.append(p)
    return os.pathsep.join(out)


def refresh_process_path() -> None:
    """Perbarui os.environ['PATH'] proses ini dengan PATH terbaru sehingga
    shutil.which() dan subprocess menemukan tool yang baru di-install
    tanpa restart aplikasi. Dipanggil di awal runner.py."""
    os.environ["PATH"] = _search_path()

# install map: per package-manager nama paket (None = tidak tersedia di pm itu).
REQUIRED_TOOLS = {
    'nmap':     {'min_ver': '7.90', 'desc': 'Port scanning & OS detection',
                 'install': {'apt': 'nmap', 'dnf': 'nmap', 'pacman': 'nmap',
                             'brew': 'nmap', 'choco': 'nmap', 'scoop': 'nmap'}},
    'tshark':   {'min_ver': '3.6',  'desc': 'Packet capture (Wireshark CLI)',
                 'install': {'apt': 'tshark', 'dnf': 'wireshark-cli', 'pacman': 'wireshark-cli',
                             'brew': 'wireshark', 'choco': 'wireshark', 'scoop': 'wireshark'}},
    'nikto':    {'min_ver': '2.1',  'desc': 'Web vulnerability scanner',
                 'install': {'apt': 'nikto', 'dnf': 'nikto', 'pacman': 'nikto',
                             'brew': 'nikto', 'choco': None, 'scoop': None}},
    'gobuster': {'min_ver': '3.1',  'desc': 'Directory & DNS bruteforce',
                 'install': {'apt': 'gobuster', 'dnf': 'gobuster', 'pacman': 'gobuster',
                             'brew': 'gobuster', 'choco': 'gobuster', 'scoop': 'gobuster'}},
    'python3':  {'min_ver': '3.10', 'desc': 'Engine utama subprocess runner',
                 'install': {'apt': 'python3', 'dnf': 'python3', 'pacman': 'python',
                             'brew': 'python', 'choco': 'python', 'scoop': 'python'}},
    'git':      {'min_ver': '2.30', 'desc': 'Update wordlist & template',
                 'install': {'apt': 'git', 'dnf': 'git', 'pacman': 'git',
                             'brew': 'git', 'choco': 'git', 'scoop': 'git'}},
    'nc':       {'min_ver': '0',    'desc': 'Port listening, banner grab',
                 'install': {'apt': 'netcat-openbsd', 'dnf': 'nmap-ncat', 'pacman': 'openbsd-netcat',
                             'brew': 'netcat', 'choco': None, 'scoop': None}},
}

OPTIONAL_TOOLS = {
    'hydra':   {'min_ver': '9.3', 'desc': 'Online password brute force',
                'install': {'apt': 'hydra', 'dnf': 'hydra', 'pacman': 'hydra',
                            'brew': 'hydra', 'choco': None, 'scoop': None}},
    'hashcat': {'min_ver': '6.2', 'desc': 'Offline hash cracking (GPU)',
                'install': {'apt': 'hashcat', 'dnf': 'hashcat', 'pacman': 'hashcat',
                            'brew': 'hashcat', 'choco': 'hashcat', 'scoop': 'hashcat'}},
    'nuclei':  {'min_ver': '2.9', 'desc': 'Template-based CVE scanner',
                'install': {'apt': None, 'dnf': None, 'pacman': 'nuclei',
                            'brew': 'nuclei', 'choco': None, 'scoop': 'nuclei'}},
    'lynis':   {'min_ver': '3.0', 'desc': 'System hardening audit',
                'install': {'apt': 'lynis', 'dnf': 'lynis', 'pacman': 'lynis',
                            'brew': 'lynis', 'choco': None, 'scoop': None}},
    # --- Tools baru SDD v2 ---
    'whatweb':     {'min_ver': '0.5', 'desc': 'Fingerprinting teknologi web (CMS/framework)',
                    'install': {'apt': 'whatweb', 'dnf': None, 'pacman': 'whatweb',
                                'brew': 'whatweb', 'choco': None, 'scoop': None}},
    'sslyze':      {'min_ver': '5.0', 'desc': 'Audit konfigurasi SSL/TLS',
                    'install': {'apt': None, 'brew': None, 'choco': None, 'scoop': None, 'pip': 'sslyze'}},
    'searchsploit':{'min_ver': '0', 'desc': 'Lookup exploit publik (Exploit-DB)',
                    'install': {'apt': 'exploitdb', 'dnf': None, 'pacman': 'exploitdb',
                                'brew': 'exploitdb', 'choco': None, 'scoop': None}},
    'arp-scan':    {'min_ver': '1.9', 'desc': 'Discovery cepat host di local network',
                    'install': {'apt': 'arp-scan', 'dnf': 'arp-scan', 'pacman': 'arp-scan',
                                'brew': 'arp-scan', 'choco': None, 'scoop': None}},
    'ffuf':        {'min_ver': '2.0', 'desc': 'Fuzzing endpoint API & parameter',
                    'install': {'apt': None, 'dnf': None, 'pacman': 'ffuf',
                                'brew': 'ffuf', 'choco': 'ffuf', 'scoop': 'ffuf'}},
    'aircrack-ng': {'min_ver': '1.7', 'desc': 'Audit WiFi (butuh adapter monitor mode)',
                    'install': {'apt': 'aircrack-ng', 'dnf': 'aircrack-ng', 'pacman': 'aircrack-ng',
                                'brew': 'aircrack-ng', 'choco': 'aircrack-ng', 'scoop': None}},
    'trivy':       {'min_ver': '0.45', 'desc': 'Scan vulnerability image Docker',
                    'install': {'apt': None, 'dnf': None, 'pacman': 'trivy',
                                'brew': 'trivy', 'choco': 'trivy', 'scoop': 'trivy'}},
    'suricata':    {'min_ver': '6.0', 'desc': 'IDS/IPS monitoring real-time',
                    'install': {'apt': 'suricata', 'dnf': 'suricata', 'pacman': 'suricata',
                                'brew': 'suricata', 'choco': None, 'scoop': None}},
    'hping3':      {'min_ver': '3.0', 'desc': 'Packet crafting (lab DoS simulation)',
                    'install': {'apt': 'hping3', 'dnf': 'hping3', 'pacman': 'hping',
                                'brew': 'hping', 'choco': None, 'scoop': None}},
    'prowler':     {'min_ver': '3.0', 'desc': 'Cloud misconfiguration checker',
                    'install': {'apt': None, 'brew': 'prowler', 'choco': None, 'scoop': None, 'pip': 'prowler'}},
}

# Beberapa tool dipanggil dengan nama berbeda di Windows.
_WINDOWS_ALIASES = {
    'tshark': ['tshark'],
    'python3': ['python3', 'python'],
    'nc': ['nc', 'ncat'],
}


def _candidate_names(name: str) -> list:
    if platform.system() == 'Windows' and name in _WINDOWS_ALIASES:
        return _WINDOWS_ALIASES[name]
    if name == 'python3':
        return ['python3', 'python']
    if name == 'nc':
        return ['nc', 'ncat']
    return [name]


def check_tool(name: str) -> dict:
    """Periksa apakah satu tool terpasang, kembalikan path & versi.
    Memakai PATH terbaru (registry) agar tool yang baru di-install langsung
    terdeteksi tanpa restart aplikasi."""
    import sys
    # Tool berupa modul Python (sslyze, prowler) → deteksi via import.
    if name in PYTHON_MODULE_TOOLS and _module_available(PYTHON_MODULE_TOOLS[name]):
        return {'installed': True,
                'path': f'{sys.executable} -m {PYTHON_MODULE_TOOLS[name]}',
                'version': 'python module'}
    search = _search_path()
    path = None
    for cand in _candidate_names(name):
        found = shutil.which(cand, path=search)
        if found:
            path = found
            break
    if not path:
        return {'installed': False, 'path': None, 'version': None}
    try:
        # Pakai path lengkap agar tetap jalan walau belum ada di PATH proses.
        ver = subprocess.check_output(
            [path, '--version'],
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", timeout=5
        ).strip().split('\n')[0].strip()
        ver = _ANSI_RE.sub('', ver).strip()  # buang kode warna ANSI
        # Bersihkan output yang bukan versi (mis. shim .bat rusak -> error shell).
        bad = ('not recognized', 'is not r', 'cannot be loaded', 'tidak dikenali',
               'term ', 'cmdlet', 'syntaxerror', 'traceback')
        if not ver or any(b in ver.lower() for b in bad):
            ver = 'terpasang'
    except Exception:
        ver = 'terpasang'
    return {'installed': True, 'path': path, 'version': ver}


def run_all_checks() -> dict:
    """Jalankan pengecekan untuk semua required + optional tools."""
    results = {}
    for name, meta in {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}.items():
        r = check_tool(name)
        r['required'] = name in REQUIRED_TOOLS
        r['min_ver'] = meta.get('min_ver', '')
        r['desc'] = meta.get('desc', '')
        r['install'] = meta.get('install', {})
        r['via'] = 'native' if r['installed'] else None
        results[name] = r

    # Tool apa pun yang tak ada native di Windows: tandai tersedia bila ada di
    # WSL (auto-route akan menjalankannya via WSL secara transparan). Deteksi
    # batch (satu pemanggilan wsl) agar cepat.
    try:
        from . import wsl_backend
        if wsl_backend.wsl_available():
            distro = wsl_backend.default_distro()
            missing = [n for n, r in results.items() if not r['installed']]
            in_wsl = wsl_backend.tools_in_wsl(missing, distro)
            for name in in_wsl:
                r = results[name]
                r['installed'] = True
                r['via'] = 'wsl'
                r['version'] = f'via WSL ({distro})'
                r['path'] = f'wsl:{distro}'
    except Exception:
        pass
    return results


def get_package_manager() -> str:
    """Tentukan package manager sesuai OS.
    Windows: utamakan Scoop (tanpa admin, binari bersih) bila ada, lalu Choco."""
    os_name = platform.system()
    search = _search_path()
    if os_name == 'Linux':
        for pm in ('apt', 'dnf', 'yum', 'pacman', 'zypper'):
            if shutil.which(pm):
                return 'dnf' if pm == 'yum' else pm
        return 'unknown'
    if os_name == 'Darwin':
        return 'brew'
    if os_name == 'Windows':
        if shutil.which('scoop', path=search):
            return 'scoop'
        return 'choco'
    return 'unknown'


def build_install_command(missing: list) -> dict:
    """
    Bangun perintah instalasi untuk tools yang kurang.
    Kembalikan {pkg_manager, command, packages, manual_notes}.
    """
    pm = get_package_manager()
    all_tools = {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}
    packages, pip_packages, manual = [], [], []
    for name in missing:
        meta = all_tools.get(name, {})
        inst = meta.get('install', {})
        pkg = inst.get(pm)
        if pkg:
            packages.append(pkg)
        elif inst.get('pip'):
            pip_packages.append(inst['pip'])
        else:
            manual.append(name)

    pkgs = ' '.join(packages)
    if pm == 'apt':
        cmd = f"sudo apt-get update && sudo apt-get install -y {pkgs}" if packages else ''
    elif pm == 'brew':
        cmd = f"brew install {pkgs}" if packages else ''
    elif pm == 'choco':
        cmd = f"choco install -y {pkgs}" if packages else ''
    elif pm == 'scoop':
        cmd = f"scoop install {pkgs}" if packages else ''
    elif pm in ('dnf', 'yum'):
        cmd = f"sudo {pm} install -y {pkgs}" if packages else ''
    elif pm == 'zypper':
        cmd = f"sudo zypper install -y {pkgs}" if packages else ''
    elif pm == 'pacman':
        cmd = f"sudo pacman -S --noconfirm {pkgs}" if packages else ''
    else:
        cmd = ''

    pip_cmd = f"python -m pip install --upgrade {' '.join(pip_packages)}" if pip_packages else ''

    return {
        'pkg_manager': pm,
        'command': cmd,
        'packages': packages,
        'pip_command': pip_cmd,
        'pip_packages': pip_packages,
        'manual_notes': manual,
        # scoop & brew tidak butuh admin/root.
        'needs_admin': pm in ('apt', 'choco', 'dnf', 'yum', 'zypper', 'pacman'),
    }


def check_privileges() -> dict:
    """Cek apakah aplikasi dijalankan dengan privilege admin/root."""
    is_admin = False
    try:
        if platform.system() == 'Windows':
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            import os
            is_admin = (os.geteuid() == 0)
    except Exception:
        is_admin = False
    return {'is_admin': is_admin, 'platform': platform.system()}


if __name__ == '__main__':
    import json
    print(json.dumps(run_all_checks(), indent=2))

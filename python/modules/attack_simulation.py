# nexus/python/modules/attack_simulation.py
"""Modul Attack Simulation — SDD v2 §5.9. Terstruktur & ter-scope.
Setiap simulasi WAJIB lolos Scope Guard (target authorized) sebelum jalan."""
from typing import Callable, Optional

from core.scope_guard import ScopeGuard, ScopeError
from core.subprocess_runner import tool_available, simulate_stream, tool_argv, run_streaming
from core.stream_handler import emit_line

SIMULATIONS = {
    'brute_force': {
        'label': 'Brute Force Login', 'tool': 'hydra',
        'goal': 'Memahami pentingnya rate-limiting & lockout policy',
    },
    'dir_fuzzing': {
        'label': 'Directory/Param Fuzzing', 'tool': 'ffuf',
        'goal': 'Menemukan endpoint tersembunyi & parameter rentan',
    },
    'dos_lab': {
        'label': 'Denial of Service (Lab Only)', 'tool': 'hping3',
        'goal': 'Memahami dampak flood request & cara mitigasinya',
    },
    'mitm_demo': {
        'label': 'Man-in-the-Middle Demo', 'tool': 'arpspoof',
        'goal': 'Memahami risiko jaringan tanpa enkripsi',
    },
    'privesc_check': {
        'label': 'Privilege Escalation Check', 'tool': 'linpeas',
        'goal': 'Mengenali vektor privilege escalation umum (read-only)',
    },
}


def _demo_run(sim_key: str, target: str, cb: Callable):
    sim = SIMULATIONS[sim_key]
    cb(f'[SIM] {sim["label"]} terhadap {target} (mode demo / lab)')
    cb(f'[SIM] Tujuan pembelajaran: {sim["goal"]}')
    if sim_key == 'brute_force':
        lines = [f'[*] hydra -L users.txt -P rockyou.txt {target} ssh (demo)',
                 '[ATTEMPT] admin:123456 ... gagal',
                 '[ATTEMPT] admin:password ... gagal',
                 '[FOUND] admin:admin123  <-- rate-limit tidak aktif!',
                 '[LESSON] Aktifkan fail2ban / account lockout setelah N percobaan.']
    elif sim_key == 'dir_fuzzing':
        lines = [f'[*] ffuf -u {target}/FUZZ (demo)',
                 '200  /admin', '403  /config', '200  /backup.zip  <-- sensitif!',
                 '[LESSON] Hapus file sensitif & batasi direktori publik.']
    elif sim_key == 'dos_lab':
        lines = [f'[*] hping3 --flood -S {target} -p 80 (LAB ONLY, rate-limited demo)',
                 'Mengirim 1000 SYN/detik (disimulasikan)...',
                 'Target latency naik 12ms -> 480ms',
                 '[LESSON] Terapkan SYN cookies, rate-limit, dan WAF/CDN.']
    elif sim_key == 'mitm_demo':
        lines = [f'[*] arpspoof + tshark di jaringan sendiri (demo)',
                 'Spoof ARP gateway <-> korban (lab)',
                 'Menangkap kredensial HTTP plaintext (disimulasikan)',
                 '[LESSON] Gunakan HTTPS/TLS & ARP inspection.']
    else:  # privesc_check
        lines = [f'[*] linpeas (read-only enumeration) (demo)',
                 'Mencari SUID binaries, cron writable, sudo misconfig...',
                 '[!] /usr/bin/find ber-SUID (GTFOBins)',
                 '[LESSON] Audit SUID & konfigurasi sudo secara berkala.']
    simulate_stream(lines, cb, delay=0.1)


def _real_cmd(sim_key: str, target: str, kwargs: dict):
    """Bangun perintah NYATA per simulasi. Kembalikan list argumen atau None."""
    if sim_key == 'brute_force':
        service = kwargs.get('service', 'ssh')
        passlist = kwargs.get('passlist') or kwargs.get('wordlist') or 'wordlists/rockyou.txt'
        user = kwargs.get('username', '')
        userlist = kwargs.get('userlist', '')
        cmd = ['hydra']
        if user:
            cmd += ['-l', user]
        elif userlist:
            cmd += ['-L', userlist]
        else:
            cmd += ['-l', 'admin']
        cmd += ['-P', passlist, '-t', str(kwargs.get('threads', '4')), f'{service}://{target}']
        return cmd
    if sim_key == 'dir_fuzzing':
        wl = kwargs.get('wordlist', 'wordlists/common_dirs.txt')
        url = target if str(target).startswith('http') else f'http://{target}'
        return ['ffuf', '-u', f'{url}/FUZZ', '-w', wl,
                '-mc', '200,204,301,302,307,401,403']
    if sim_key == 'dos_lab':
        # Lab: SYN terbatas (bukan --flood tak terbatas) — aman & terukur.
        port = str(kwargs.get('port', '80'))
        count = str(kwargs.get('count', '2000'))
        return ['hping3', '-S', '-p', port, '-i', 'u1000', '-c', count, target]
    if sim_key == 'mitm_demo':
        return ['arpspoof', '-i', kwargs.get('interface', 'eth0'), target]
    if sim_key == 'privesc_check':
        return ['linpeas']
    return None


def _real_run(sim_key: str, target: str, cb: Callable, kwargs: dict) -> int:
    """Jalankan tool NYATA bila tersedia; kalau tidak, fallback demo
    (yang akan mengangkat error bila mode eksekusi-nyata aktif)."""
    sim = SIMULATIONS[sim_key]
    tool = sim['tool']
    if not tool_available(tool):
        cb(f'[!] Tool "{tool}" tidak tersedia (pasang via Settings / WSL).')
        _demo_run(sim_key, target, cb)  # raise DemoDisabled bila NEXUS_NO_DEMO
        return 0
    cmd = _real_cmd(sim_key, target, kwargs)
    if not cmd:
        _demo_run(sim_key, target, cb)
        return 0
    argv = tool_argv(cmd[0], cmd[1:])
    cb(f'$ {" ".join(cmd)}')
    return run_streaming(argv, cb, timeout=int(kwargs.get('timeout', 180)))


def run(simulation: str = '', target: str = '', confirmed: str = 'false', **kwargs) -> dict:
    cb = emit_line
    if simulation not in SIMULATIONS:
        return {'module': 'attack_sim', 'error': f'Simulasi tidak dikenal: {simulation}',
                'available': SIMULATIONS}

    # Scope Guard — wajib (otorisasi target, BUKAN pembatasan read-only).
    guard = ScopeGuard()
    try:
        guard.require_authorization(target)
    except ScopeError as e:
        cb(f'[BLOCKED] {e}')
        return {'module': 'attack_sim', 'simulation': simulation, 'target': target,
                'blocked': True, 'reason': str(e)}

    if confirmed not in ('true', 'True', '1', True):
        return {'module': 'attack_sim', 'simulation': simulation, 'target': target,
                'blocked': True, 'reason': 'Konfirmasi eksekusi diperlukan.'}

    sim = SIMULATIONS[simulation]
    cb(f'[SCOPE OK] Target {target} terotorisasi. Menjalankan {sim["label"]} (NYATA)...')
    rc = _real_run(simulation, target, cb, kwargs)
    return {'module': 'attack_sim', 'simulation': simulation, 'label': sim['label'],
            'target': target, 'goal': sim['goal'], 'completed': True,
            'exit_code': rc, 'tool_present': tool_available(sim['tool'])}


def catalog() -> dict:
    return {'module': 'attack_sim_catalog',
            'simulations': [{'key': k, **v} for k, v in SIMULATIONS.items()]}

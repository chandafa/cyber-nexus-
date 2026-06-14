# nexus/python/modules/attack_simulation.py
"""Modul Attack Simulation — SDD v2 §5.9. Terstruktur & ter-scope.
Setiap simulasi WAJIB lolos Scope Guard (target authorized) sebelum jalan."""
from typing import Callable, Optional

from core.scope_guard import ScopeGuard, ScopeError
from core.subprocess_runner import tool_available, simulate_stream
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


def run(simulation: str = '', target: str = '', confirmed: str = 'false', **kwargs) -> dict:
    cb = emit_line
    if simulation not in SIMULATIONS:
        return {'module': 'attack_sim', 'error': f'Simulasi tidak dikenal: {simulation}',
                'available': SIMULATIONS}

    # Scope Guard — wajib.
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
    cb(f'[SCOPE OK] Target {target} terotorisasi. Menjalankan {sim["label"]}...')
    # Selalu jalankan versi demo/edukatif (aman) — real tooling hanya untuk lab lanjutan.
    _demo_run(simulation, target, cb)
    return {'module': 'attack_sim', 'simulation': simulation, 'label': sim['label'],
            'target': target, 'goal': sim['goal'], 'completed': True,
            'tool_present': tool_available(sim['tool'])}


def catalog() -> dict:
    return {'module': 'attack_sim_catalog',
            'simulations': [{'key': k, **v} for k, v in SIMULATIONS.items()]}

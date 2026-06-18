#!/usr/bin/env python3
# nexus/python/runner.py
"""
Central CLI dispatcher untuk Nexus Python engine.
Dipanggil oleh Rust (executor.rs) sebagai:

    python runner.py <command> --key value --key2 value2 ...

Output:
  - Baris biasa  -> di-stream ke terminal UI (xterm.js).
  - Baris result -> diawali sentinel `__NEXUS_RESULT__ <json>`.
  - Baris progress -> diawali sentinel `__NEXUS_PROGRESS__ <json>`.

Command yang didukung:
  check_deps, install_info, privileges, list_interfaces,
  port_scan, network_scan, vuln_scan, password_audit,
  log_analyze, network_map, defense_check, generate_report
"""
import sys
import os
import argparse
import traceback
import subprocess

# --- KRITIS (Windows): cegah kedipan jendela console/PowerShell ---
# Semua subprocess yang dijalankan engine (wsl.exe, where, version-check tool,
# installer, dll.) akan memunculkan jendela console sekejap karena Nexus adalah
# aplikasi GUI tanpa console. Patch Popen agar selalu memakai CREATE_NO_WINDOW
# di Windows — satu titik ini menutup SEMUA pemanggilan subprocess di engine.
if sys.platform == "win32":
    _CREATE_NO_WINDOW = 0x08000000
    _orig_popen = subprocess.Popen

    class _HiddenPopen(_orig_popen):
        def __init__(self, *args, **kwargs):
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CREATE_NO_WINDOW
            super().__init__(*args, **kwargs)

    subprocess.Popen = _HiddenPopen  # subprocess.run/call/check_output ikut terpengaruh

# Pastikan folder python/ ada di sys.path agar `core`, `modules` bisa di-import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.stream_handler import emit_line, emit_result  # noqa: E402
from core.sanitizer import (  # noqa: E402
    sanitize_target, sanitize_url, sanitize_port, sanitize_filepath, SanitizeError,
)


def _parse_kwargs(argv):
    """Parse `--key value` pasangan menjadi dict."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('command')
    args, extra = parser.parse_known_args(argv)
    kwargs = {}
    i = 0
    while i < len(extra):
        token = extra[i]
        if token.startswith('--'):
            key = token[2:].replace('-', '_')
            if i + 1 < len(extra) and not extra[i + 1].startswith('--'):
                kwargs[key] = extra[i + 1]
                i += 2
            else:
                kwargs[key] = True
                i += 1
        else:
            i += 1
    return args.command, kwargs


def dispatch(command: str, kwargs: dict) -> dict:
    # -------------------------------------------------- info / utility
    if command == 'check_deps':
        from core.dependency_checker import run_all_checks
        return {'module': 'deps', 'results': run_all_checks()}

    if command == 'install_info':
        from core.dependency_checker import build_install_command
        missing = [m.strip() for m in str(kwargs.get('missing', '')).split(',') if m.strip()]
        return {'module': 'install', **build_install_command(missing)}

    if command == 'install_tools':
        from core.installer import install_tools
        tools = [t.strip() for t in str(kwargs.get('tools', '')).split(',') if t.strip()]
        return install_tools(tools)

    if command == 'privileges':
        from core.dependency_checker import check_privileges
        return {'module': 'privileges', **check_privileges()}

    if command == 'list_interfaces':
        from modules.network_scanner import list_interfaces
        return {'module': 'interfaces', **list_interfaces()}

    # -------------------------------------------------- scanning modules
    if command == 'port_scan':
        from modules import port_scanner
        target = sanitize_target(kwargs.get('target', ''))
        return port_scanner.run(target, kwargs.get('mode', 'standard'))

    if command == 'network_scan':
        from modules import network_scanner
        return network_scanner.run(
            interface=kwargs.get('interface', '1'),
            filter=kwargs.get('filter', ''),
            pcap_file=kwargs.get('pcap_file', ''),
            packet_limit=kwargs.get('packet_limit', 40),
        )

    if command == 'vuln_scan':
        from modules import vuln_scanner
        target = sanitize_url(kwargs.get('target', ''))
        return vuln_scanner.run(target, kwargs.get('tools', 'nikto,gobuster,nuclei'),
                                kwargs.get('wordlist', 'wordlists/common_dirs.txt'))

    if command == 'password_audit':
        from modules import password_auditor
        submode = kwargs.get('submode', 'hydra')
        if submode in ('hydra',):
            target = sanitize_target(kwargs.get('target', ''))
            kwargs['target'] = target
        return password_auditor.run(**kwargs)

    if command == 'log_analyze':
        from modules import log_analyzer
        lp = kwargs.get('log_path', '')
        if lp:
            sanitize_filepath(lp)
        return log_analyzer.run(lp, kwargs.get('log_type', 'auto'))

    if command == 'network_map':
        from modules import network_mapper
        target = sanitize_target(kwargs.get('target', ''))
        return network_mapper.run(target)

    if command == 'defense_check':
        from modules import defense_monitor
        return defense_monitor.run(kwargs.get('submode', 'all'))

    if command == 'waf':
        from modules import waf
        # args: listen_port, backend, backend_port, max_rps, max_log_mb, ssl_enabled, ssl_cert_type, ssl_cert_path, ssl_key_path
        fg = str(kwargs.get('foreground', '')).lower() in ('1', 'true', 'yes')
        run_args = {
            'listen_port': kwargs.get('listen_port', '8080'),
            'backend': kwargs.get('backend', '127.0.0.1'),
            'backend_port': kwargs.get('backend_port', '8000'),
            'max_rps': kwargs.get('max_rps', '10'),
            'max_log_mb': kwargs.get('max_log_mb', '10'),
            'learning_mode': kwargs.get('learning_mode', 'false'),
            'allowlist_ips': kwargs.get('allowlist_ips', ''),
            'allowlist_paths': kwargs.get('allowlist_paths', ''),
            'ssl_enabled': kwargs.get('ssl_enabled', 'false'),
            'ssl_cert_type': kwargs.get('ssl_cert_type', 'self_signed'),
            'ssl_cert_path': kwargs.get('ssl_cert_path', ''),
            'ssl_key_path': kwargs.get('ssl_key_path', ''),
            'blacklist_ips': kwargs.get('blacklist_ips', '')
        }
        if fg:
            return waf.run_foreground(**run_args)
        return waf.run(**run_args)

    if command == 'waf_stop':
        from modules import waf
        return waf.stop()

    if command == 'waf_status':
        from modules import waf
        return waf.status()

    if command == 'waf_logs':
        from modules import waf
        limit = int(kwargs.get('limit', '200'))
        return waf.get_logs(limit=limit)

    if command == 'waf_clear_logs':
        from modules import waf
        return waf.clear_logs()

    if command == 'waf_get_vhosts':
        from modules import waf
        return waf.get_vhosts()

    if command == 'waf_save_vhost':
        from modules import waf
        return waf.save_vhost(
            hostname=kwargs.get('hostname', ''),
            backend_host=kwargs.get('backend_host', '127.0.0.1'),
            backend_port=kwargs.get('backend_port', '8000'),
            max_rps=kwargs.get('max_rps', '10'),
            learning_mode=kwargs.get('learning_mode', 'false'),
            allowlist_ips=kwargs.get('allowlist_ips', ''),
            allowlist_paths=kwargs.get('allowlist_paths', ''),
            rules_json=kwargs.get('rules_json', '[]'),
            vhost_type=kwargs.get('vhost_type', 'proxy'),
            root_directory=kwargs.get('root_directory', ''),
            blacklist_ips=kwargs.get('blacklist_ips', '')
        )

    if command == 'waf_delete_vhost':
        from modules import waf
        return waf.delete_vhost(hostname=kwargs.get('hostname', ''))

    if command == 'waf_get_rules':
        from modules import waf
        return waf.get_custom_rules()

    if command == 'waf_save_rule':
        from modules import waf
        return waf.save_custom_rule(
            name=kwargs.get('name', ''),
            pattern=kwargs.get('pattern', ''),
            description=kwargs.get('description', ''),
            enabled=kwargs.get('enabled', 'true')
        )

    if command == 'waf_delete_rule':
        from modules import waf
        return waf.delete_custom_rule(name=kwargs.get('name', ''))

    # ----------------------------------------------------- modul baru SDD v2
    if command == 'ssl_audit':
        from modules import ssl_auditor
        target = sanitize_target(kwargs.get('target', ''))
        return ssl_auditor.run(target, kwargs.get('port', 443))

    if command == 'exploit_lookup':
        from modules import exploit_lookup
        return exploit_lookup.run(kwargs.get('services', ''), kwargs.get('service', ''),
                                  kwargs.get('version', ''))

    if command == 'api_test':
        from modules import api_tester
        target = sanitize_url(kwargs.get('target', ''))
        return api_tester.run(target, kwargs.get('submode', 'endpoints'),
                              kwargs.get('wordlist', 'wordlists/common_dirs.txt'))

    if command == 'wireless_scan':
        from modules import wireless_auditor
        return wireless_auditor.run(kwargs.get('interface', 'wlan0'),
                                    kwargs.get('duration', 12))

    if command == 'container_scan':
        from modules import container_scanner
        return container_scanner.run(kwargs.get('image', 'nginx:latest'))

    if command == 'cloud_check':
        from modules import cloud_checker
        return cloud_checker.run(kwargs.get('provider', 'aws'))

    if command == 'asset_inventory':
        from modules import asset_inventory
        return asset_inventory.run(kwargs.get('submode', 'list'))

    if command == 'security_score':
        from modules import security_score
        if kwargs.get('submode') == 'history':
            return security_score.history()
        return security_score.run()

    if command == 'scan_diff':
        from modules import scan_diff
        return scan_diff.run(kwargs.get('old_session', ''), kwargs.get('new_session', ''))

    if command == 'scheduler':
        from modules import scheduler
        return scheduler.run(**kwargs)

    if command == 'wordlist':
        from modules import wordlist_manager
        return wordlist_manager.run(kwargs.get('submode', 'list'), kwargs.get('name', ''))

    if command == 'firewall_advisor':
        from modules import firewall_advisor
        return firewall_advisor.run(kwargs.get('ports', ''),
                                    kwargs.get('essential', '22,80,443'))

    if command == 'patch_advisor':
        from modules import patch_advisor
        return patch_advisor.run(kwargs.get('findings', ''))

    if command == 'ids_monitor':
        from modules import ids_monitor
        return ids_monitor.run(kwargs.get('interface', 'eth0'), kwargs.get('duration', 15))

    # ----------------------------------------------------- modul baru (recon/offensive)
    if command == 'dns_recon':
        from modules import dns_recon
        domain = sanitize_target(kwargs.get('domain', ''))
        wl = kwargs.get('wordlist', '')
        if wl:
            sanitize_filepath(wl)
        return dns_recon.run(domain, wl)

    if command == 'dir_fuzz':
        from modules import dir_fuzz
        target = sanitize_url(kwargs.get('target', ''))
        wl = kwargs.get('wordlist', '')
        if wl:
            sanitize_filepath(wl)
        return dir_fuzz.run(target, wl, kwargs.get('extensions', ''))

    if command == 'listener':
        from modules import listener
        return listener.run(**kwargs)

    if command == 'hash_tool':
        from modules import hash_tool
        wl = kwargs.get('wordlist', '')
        if wl:
            sanitize_filepath(wl)
        return hash_tool.run(**kwargs)

    if command == 'scope':
        from core import scope_guard
        return scope_guard.run(**kwargs)

    if command == 'attack_sim':
        from modules import attack_simulation
        if kwargs.get('submode') == 'catalog':
            return attack_simulation.catalog()
        return attack_simulation.run(kwargs.get('simulation', ''),
                                     kwargs.get('target', ''),
                                     kwargs.get('confirmed', 'false'))

    # -------------------------------------------------- Fleet (agent <-> manager)
    if command == 'manager_start':
        from modules import fleet_manager
        host = kwargs.get('host', '127.0.0.1')
        port = kwargs.get('port', '8765')
        if str(kwargs.get('foreground', '')).lower() in ('1', 'true', 'yes'):
            return fleet_manager.run_foreground(host=host, port=port)
        return fleet_manager.run(host=host, port=port)

    if command == 'manager_status':
        from modules import fleet_manager
        return fleet_manager.manager_status(kwargs.get('host', '127.0.0.1'),
                                            kwargs.get('port', '8765'))

    if command == 'fleet_agents':
        from modules import fleet_manager
        return fleet_manager.list_agents()

    if command == 'fleet_events':
        from modules import fleet_manager
        return fleet_manager.list_events(int(kwargs.get('limit', 200)),
                                         kwargs.get('agent_id', ''),
                                         kwargs.get('severity', ''))

    if command == 'fleet_stats':
        from modules import fleet_manager
        return fleet_manager.stats()

    if command == 'fleet_alerts':
        from modules import fleet_manager
        return fleet_manager.list_alerts(int(kwargs.get('limit', 200)),
                                         kwargs.get('status', ''),
                                         kwargs.get('severity', ''),
                                         int(kwargs.get('min_level', 0)))

    if command == 'fleet_alert_ack':
        from modules import fleet_manager
        return fleet_manager.ack_alert(kwargs.get('id', ''), kwargs.get('status', 'ack'))

    if command == 'fleet_rules_get':
        from modules import fleet_manager
        return {'module': 'fleet_manager', 'rules': fleet_manager.get_rules()}

    if command == 'fleet_rules_set':
        from modules import fleet_manager
        return fleet_manager.set_rules(kwargs.get('rules', '[]'))

    if command == 'fleet_audit':
        from modules import fleet_manager
        return fleet_manager.list_audit(int(kwargs.get('limit', 200)))

    if command == 'fleet_report':
        from modules import fleet_manager
        return fleet_manager.report(kwargs.get('scope', 'fleet'))

    if command == 'fleet_posture':
        from modules import fleet_manager
        return {'module': 'fleet_manager', 'posture': fleet_manager.posture(kwargs.get('agent_id', ''))}

    if command == 'fleet_license':
        from modules import fleet_manager
        if str(kwargs.get('reload', '')).lower() in ('1', 'true', 'yes'):
            fleet_manager.reload_license()
        return fleet_manager.license_status()

    if command == 'fleet_license_apply':
        from modules import fleet_manager
        return fleet_manager.apply_license(kwargs.get('token', ''))

    if command == 'fleet_vulndb_get':
        from modules import fleet_manager
        return {'module': 'fleet_manager', 'vuln_db': fleet_manager.get_vulndb()}

    if command == 'fleet_vulndb_set':
        from modules import fleet_manager
        return fleet_manager.set_vulndb(kwargs.get('vuln_db', '[]'))

    if command == 'fleet_sigma_import':
        from modules import fleet_manager
        return fleet_manager.import_sigma(kwargs.get('sigma', '[]'))

    if command == 'fleet_respond':
        from modules import fleet_manager
        return fleet_manager.response_action(kwargs.get('agent_id', ''),
                                             kwargs.get('action', ''),
                                             kwargs.get('ip', ''), kwargs.get('target', ''),
                                             kwargs.get('process', ''))

    if command == 'fleet_notify':
        from modules import fleet_manager
        return fleet_manager.set_notify(kwargs.get('webhook', ''),
                                        int(kwargs.get('min_level', 12)))

    if command == 'fleet_policy_get':
        from modules import fleet_manager
        return fleet_manager.get_policy()

    if command == 'fleet_policy_set':
        from modules import fleet_manager
        return fleet_manager.set_policy(kwargs.get('policy', '{}'))

    if command == 'fleet_command':
        from modules import fleet_manager
        import json as _json
        try:
            cargs = _json.loads(kwargs.get('args', '{}') or '{}')
        except Exception:
            cargs = {}
        return fleet_manager.queue_command(kwargs.get('agent_id', ''),
                                           kwargs.get('cmd', ''), cargs)

    if command == 'agent_enroll':
        from modules import fleet_agent
        return fleet_agent.enroll(kwargs.get('host', '127.0.0.1'),
                                  kwargs.get('port', '8765'),
                                  kwargs.get('enroll_key', ''),
                                  kwargs.get('name', ''),
                                  kwargs.get('labels', ''),
                                  watch=kwargs.get('watch', ''))

    if command == 'agent_start':
        from modules import fleet_agent
        return fleet_agent.run_foreground()

    if command == 'agent_status':
        from modules import fleet_agent
        return fleet_agent.status()

    if command == 'agent_reset':
        from modules import fleet_agent
        return fleet_agent.reset()

    # -------------------------------------------------- backend WSL
    if command == 'wsl_status':
        from core import wsl_backend
        return wsl_backend.status()

    if command == 'set_backend':
        from core import wsl_backend
        return {'module': 'set_backend',
                **wsl_backend.set_backend(kwargs.get('backend', ''),
                                          kwargs.get('distro', ''),
                                          no_demo=kwargs.get('no_demo'),
                                          wsl_user=kwargs.get('wsl_user', ''))}

    if command in ('wsl_install', 'wsl_provision'):
        from core import wsl_backend
        from core.dependency_checker import REQUIRED_TOOLS, OPTIONAL_TOOLS
        all_tools = {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}
        apt = {t: (m.get('install', {}).get('apt') or t) for t, m in all_tools.items()}
        tools = [t.strip() for t in str(kwargs.get('tools', '')).split(',') if t.strip()]
        distro = kwargs.get('distro', '')
        if command == 'wsl_provision':
            return wsl_backend.provision_wsl(emit_line, tools=tools,
                                             apt_packages=apt, distro=distro or 'Ubuntu')
        return wsl_backend.install_tools_wsl(tools, apt, emit_line, distro)

    # -------------------------------------------------- report
    if command == 'generate_report':
        from report import generator
        return generator.run(
            session_json=kwargs.get('session', '{}'),
            report_type=kwargs.get('report_type', 'full'),
            output_path=kwargs.get('output_path', ''),
        )

    raise ValueError(f'Command tidak dikenal: {command}')


def main():
    if len(sys.argv) < 2:
        emit_line('[ERROR] Tidak ada command diberikan.')
        emit_result({'error': 'no command'})
        sys.exit(1)

    # Paksa stdout/stderr ke UTF-8 (errors='replace') — KRITIS di Windows:
    # output tool keamanan sering memuat karakter non-ASCII (—, ->, ©, box-draw)
    # yang akan crash bila stdout pakai cp1252. Cegah seluruh modul gagal.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    # Segarkan PATH proses dari registry agar tool yang baru di-install
    # langsung terdeteksi & bisa dijalankan tanpa restart aplikasi.
    try:
        from core.dependency_checker import refresh_process_path
        refresh_process_path()
    except Exception:
        pass

    # Mode eksekusi nyata (no-demo) dari config → set env agar konsisten di
    # seluruh modul (mereka cek NEXUS_NO_DEMO).
    try:
        from core.wsl_backend import get_no_demo
        if get_no_demo():
            os.environ['NEXUS_NO_DEMO'] = '1'
    except Exception:
        pass

    command, kwargs = _parse_kwargs(sys.argv[1:])
    try:
        result = dispatch(command, kwargs)
        emit_result(result)
    except SanitizeError as e:
        emit_line(f'[VALIDATION ERROR] {e}')
        emit_result({'error': str(e), 'kind': 'validation'})
        sys.exit(2)
    except Exception as e:  # pragma: no cover
        no_demo = os.environ.get('NEXUS_NO_DEMO', '').lower() in ('1', 'true', 'yes', 'on')
        # Mode eksekusi nyata: JANGAN palsukan data — tampilkan error BERSIH
        # (tanpa traceback yang menakutkan), kecuali error benar-benar tak terduga.
        if no_demo:
            try:
                from core.subprocess_runner import DemoDisabled
            except Exception:
                DemoDisabled = ()
            if isinstance(e, DemoDisabled):
                emit_line('[INFO] Tidak ada output nyata dari tool (lihat pesan di atas). '
                          'Mode eksekusi nyata aktif — data demo tidak ditampilkan.')
                emit_result({'error': 'no_real_output', 'kind': 'no_demo'})
            else:
                emit_line(f'[ERROR] {e}')
                emit_result({'error': str(e), 'kind': 'runtime'})
            sys.exit(1)
        # Default: safety net — ulangi sekali dalam mode demo agar modul tetap
        # menghasilkan output (tidak hard-error ke user).
        emit_line(f'[WARN] Tool gagal saat runtime: {e}')
        emit_line('[!] Beralih ke mode demo agar modul tetap bisa dipakai...')
        os.environ['NEXUS_FORCE_DEMO'] = '1'
        try:
            result = dispatch(command, kwargs)
            result['_fallback_demo'] = True
            emit_result(result)
        except Exception as e2:
            emit_line(f'[ERROR] {e2}')
            emit_line(traceback.format_exc())
            emit_result({'error': str(e2), 'kind': 'runtime'})
            sys.exit(1)


if __name__ == '__main__':
    main()

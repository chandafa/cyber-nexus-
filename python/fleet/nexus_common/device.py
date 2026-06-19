# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com
# nexus_common/device.py
"""
Fingerprint perangkat (device id) — sumber TUNGGAL untuk GUI desktop maupun
fleet (CLI/manager/agent), agar 1 token device-bound berlaku di kedua aplikasi
pada mesin yang sama. Stdlib-only.
"""
import hashlib
import os
import platform
import subprocess


def _raw_machine_id() -> str:
    """Identitas hardware paling stabil per-OS."""
    osname = platform.system()
    try:
        if osname == "Windows":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Cryptography") as k:
                val, _ = winreg.QueryValueEx(k, "MachineGuid")
                if val:
                    return str(val)
        elif osname == "Linux":
            for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                if os.path.isfile(p):
                    with open(p, encoding="utf-8") as f:
                        v = f.read().strip()
                        if v:
                            return v
        elif osname == "Darwin":
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
            ).decode(errors="ignore")
            import re
            m = re.search(r'IOPlatformUUID"\s*=\s*"([^"]+)"', out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return f"{platform.node()}|{platform.machine()}|{osname}"


def device_id() -> str:
    """Hash fingerprint device (32 hex). HARUS sama di GUI & fleet."""
    raw = _raw_machine_id() or "unknown"
    return hashlib.sha256(("nexus-device:" + raw).encode()).hexdigest()[:32]

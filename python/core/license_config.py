# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/license_config.py
"""
Konfigurasi server lisensi (diisi VENDOR sebelum build/distribusi).

LICENSE_API_BASE = URL dasar server lisensi (Cloudflare Worker / dll), mis.:
    https://nexus-license.<subdomain>.workers.dev

App akan memanggil:
    {LICENSE_API_BASE}/redeem_license     (aktivasi kode)
    {LICENSE_API_BASE}/validate_license   (cek revoke/expired)

Kosongkan untuk menonaktifkan aktivasi online (hanya lisensi manual/device-bound).
Dapat ditimpa saat runtime dengan env NEXUS_LICENSE_API.
"""

LICENSE_API_BASE = "https://nexus-license.kiranacandra150.workers.dev"

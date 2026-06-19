# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/license_config.py
"""
Konfigurasi server lisensi (diisi VENDOR sebelum build/distribusi).

LICENSE_API_BASE = URL dasar Cloud Functions Firebase Anda, mis.:
    https://asia-southeast2-NAMAPROJECT.cloudfunctions.net

App akan memanggil:
    {LICENSE_API_BASE}/redeem_license     (aktivasi kode)
    {LICENSE_API_BASE}/validate_license   (cek revoke/expired)

Kosongkan untuk menonaktifkan aktivasi online (hanya lisensi manual).
Dapat ditimpa saat runtime dengan env NEXUS_LICENSE_API.
"""

LICENSE_API_BASE = ""

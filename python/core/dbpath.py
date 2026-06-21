# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/core/dbpath.py
"""Resolusi path database SQLite — sama dengan yang dipakai Rust.
Rust menyetel env NEXUS_DB_PATH saat spawn python; fallback ke 'nexus.db'."""
import os


def db_path() -> str:
    return os.environ.get("NEXUS_DB_PATH", "nexus.db")

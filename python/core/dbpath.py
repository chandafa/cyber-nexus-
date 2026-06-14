# nexus/python/core/dbpath.py
"""Resolusi path database SQLite — sama dengan yang dipakai Rust.
Rust menyetel env NEXUS_DB_PATH saat spawn python; fallback ke 'nexus.db'."""
import os


def db_path() -> str:
    return os.environ.get("NEXUS_DB_PATH", "nexus.db")

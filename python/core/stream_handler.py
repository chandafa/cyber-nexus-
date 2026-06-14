# nexus/python/core/stream_handler.py
"""
Stream handler — utilitas untuk mengirim output baris-per-baris ke stdout
agar di-forward oleh Rust ke terminal UI (xterm.js), serta protokol
sentinel untuk mengirim hasil terstruktur (JSON) ke frontend.

Protokol:
  - Baris biasa  -> langsung ditampilkan di terminal.
  - Baris result -> diawali sentinel `__NEXUS_RESULT__ ` diikuti JSON.
                    Frontend mendeteksi prefix ini dan menyimpan hasil.
"""
import sys
import json

RESULT_SENTINEL = '__NEXUS_RESULT__'
PROGRESS_SENTINEL = '__NEXUS_PROGRESS__'


def emit_line(line: str) -> None:
    """Kirim satu baris output ke terminal UI (flush langsung)."""
    sys.stdout.write(line.rstrip('\n') + '\n')
    sys.stdout.flush()


def emit_progress(percent: float, label: str = '') -> None:
    """Kirim update progress (0-100) yang dipakai progress bar UI."""
    payload = json.dumps({'percent': max(0, min(100, percent)), 'label': label})
    sys.stdout.write(f'{PROGRESS_SENTINEL} {payload}\n')
    sys.stdout.flush()


def emit_result(result: dict) -> None:
    """Kirim hasil terstruktur akhir sebagai JSON ber-sentinel."""
    sys.stdout.write(f'{RESULT_SENTINEL} {json.dumps(result, default=str)}\n')
    sys.stdout.flush()


def make_callback():
    """Buat callback sederhana untuk modul-modul (callback(line))."""
    return emit_line

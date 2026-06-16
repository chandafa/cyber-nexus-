# nexus_common/log.py
"""Logger yang bisa di-plug.

Default: tulis ke stdout (cocok untuk service console / `python -m`).
Desktop app memanggil `set_sink(emit_line)` agar log mengalir ke terminal UI.
"""
import sys

_sink = None


def set_sink(fn):
    """Arahkan log ke callback lain (mis. emit_line desktop)."""
    global _sink
    _sink = fn


def log(msg: str = "") -> None:
    if _sink is not None:
        try:
            _sink(str(msg))
            return
        except Exception:
            pass
    # Default: log ke stderr agar stdout tetap bersih untuk output JSON
    # (praktik standar: data -> stdout, log -> stderr).
    try:
        sys.stderr.write(str(msg) + "\n")
        sys.stderr.flush()
    except Exception:
        pass

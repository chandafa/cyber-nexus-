# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_manager/sigma.py
"""
Konverter aturan **Sigma** -> rule native Nexus (item: Sigma import + MITRE map).

Sigma adalah format signature terbuka untuk deteksi berbasis log. Karena paket
ini stdlib-only (tanpa PyYAML), Sigma diterima sebagai **JSON** (YAML bisa
dikonversi ke JSON di luar: `yq -o=json rule.yml`). Subset yang didukung:
  - detection: satu `selection` dict (modifier endswith/startswith/contains, list -> in)
  - tags: `attack.tXXXX(.XXX)` -> MITRE technique ids
  - level: informational|low|medium|high|critical -> level numerik
"""
from nexus_common import schema

# Peta field umum Sigma -> field schema Nexus.
_FIELD_MAP = {
    "targetfilename": "target.path", "filename": "target.path", "path": "target.path",
    "image": "actor.process", "process": "actor.process",
    "commandline": "data.command", "user": "actor.user",
    "destinationport": "data.port", "dport": "data.port",
    "eventtype": "event_type", "category": "category",
}
_LEVEL = {"informational": "info", "info": "info", "low": "low",
          "medium": "medium", "high": "high", "critical": "critical"}


def convert(sig: dict) -> dict:
    det = sig.get("detection", {}) or {}
    sel = None
    for k, v in det.items():
        if k != "condition" and isinstance(v, dict):
            sel = v
            break
    conditions = {}
    for field, val in (sel or {}).items():
        name, op = (field.split("|", 1) + [None])[:2] if "|" in field else (field, None)
        key = _FIELD_MAP.get(name.lower(), "data." + name)
        first = val[0] if isinstance(val, list) and val else val
        if op in (None, "equals"):
            conditions[key] = {"in": val} if isinstance(val, list) else val
        elif op == "endswith":
            conditions[key] = {"ends_with": first}
        elif op == "startswith":
            conditions[key] = {"starts_with": first}
        elif op == "contains":
            conditions[key] = {"contains": first}
        elif op == "re":
            conditions[key] = {"regex": first}
    mitre = [t.split(".", 1)[1].upper() for t in sig.get("tags", [])
             if isinstance(t, str) and t.lower().startswith("attack.t")]
    sev = _LEVEL.get(str(sig.get("level", "medium")).lower(), "medium")
    rid = sig.get("id") or ("SIGMA-" + str(sig.get("title", "rule"))[:24])
    return {
        "id": str(rid), "name": sig.get("title", "Sigma rule"),
        "category": (sig.get("logsource", {}) or {}).get("category", "sigma"),
        "level": schema.severity_to_level(sev), "mitre": mitre,
        "conditions": conditions,
        "recommendation": sig.get("description", "Tinjau sesuai deskripsi Sigma."),
        "response": ["notify"], "source": "sigma",
    }


def convert_many(sigmas) -> list:
    if isinstance(sigmas, dict):
        sigmas = [sigmas]
    out = []
    for s in sigmas or []:
        try:
            out.append(convert(s))
        except Exception:
            continue
    return out

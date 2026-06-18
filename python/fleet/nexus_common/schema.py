# nexus_common/schema.py
"""
Skema baku Nexus Fleet — SATU bentuk untuk event, alert, dan report (item #5).

Condong ke gaya OCSF / Wazuh agar tidak "bubur security":
  event = { event_id, agent_id, tenant_id, ts, timestamp(iso), source, category,
            event_type, severity, origin(real|demo), title, detail,
            host{}, actor{}, target{}, evidence{}, data{}, rule{} }
  alert = event + rule{id,name,mitre,recommendation,response} + level + status

`origin` memisahkan temuan ASLI ("real") dari "demo" (item #4) — deployment
serius menolak demo. `category` memetakan ke kelas OCSF (file_integrity,
software_inventory, config_assessment, vulnerability, authentication, dst.).
"""
import time
import uuid

SEVERITIES = ("info", "low", "medium", "high", "critical")
ORIGINS = ("real", "demo")

SEVERITY_LEVEL = {"info": 3, "low": 5, "medium": 8, "high": 12, "critical": 14}
_LEVEL_BANDS = [(14, "critical"), (12, "high"), (8, "medium"), (5, "low"), (0, "info")]

# Pemetaan tipe-event collector -> (category OCSF-ish, event_type) bila tak diisi.
CATEGORY_MAP = {
    "system": ("device_inventory", "host_info"),
    "listening_ports": ("network_activity", "listening_ports"),
    "exposure": ("network_activity", "port_exposed"),
    "logged_users": ("authentication", "session_list"),
    "disk": ("device_inventory", "disk_usage"),
    "firewall": ("config_assessment", "firewall_state"),
    "failed_logins": ("authentication", "failed_login"),
    "fim_change": ("file_integrity", "file_modified"),
    "fim_new": ("file_integrity", "file_created"),
    "fim_deleted": ("file_integrity", "file_deleted"),
    "software_inventory": ("software_inventory", "package_list"),
    "sca": ("config_assessment", "policy_check"),
    "vulnerability": ("vulnerability_finding", "cve_match"),
    "log": ("log_activity", "log_event"),
    "webaudit": ("config_assessment", "web_config"),
    "processes": ("process_activity", "process_list"),
    "network": ("network_activity", "network_inventory"),
}


def now() -> int:
    return int(time.time())


def iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)) if ts else ""


def clamp_severity(s):
    s = (s or "info").lower()
    return s if s in SEVERITIES else "info"


def clamp_origin(s):
    s = (s or "real").lower()
    return s if s in ORIGINS else "real"


def level_to_severity(level):
    for thr, name in _LEVEL_BANDS:
        if level >= thr:
            return name
    return "info"


def severity_to_level(sev):
    return SEVERITY_LEVEL.get(clamp_severity(sev), 3)


# --------------------------------------------------------------------------- EVENT
def make_event(source, severity, title, detail="", *, type=None, category=None,
               event_type=None, data=None, target=None, actor=None, evidence=None,
               origin="real", ts=None):
    """Bangun event baku. `source` = produser (mis. 'fim','sca','port_scan')."""
    t = type or source
    cat, etype = CATEGORY_MAP.get(t, (category or "finding", event_type or t))
    return {
        "ts": int(ts or now()),
        "source": str(source),
        "type": str(t),
        "category": category or cat,
        "event_type": event_type or etype,
        "severity": clamp_severity(severity),
        "origin": clamp_origin(origin),
        "title": str(title or "")[:300],
        "detail": str(detail or "")[:2000],
        "target": target or {},
        "actor": actor or {},
        "evidence": evidence or {},
        "data": data or {},
    }


def normalize_event(raw, default_origin="real"):
    """Terima event mentah (termasuk format lama {type,severity,title,detail,data})
    dan kembalikan bentuk baku lengkap."""
    raw = raw or {}
    src = raw.get("source") or raw.get("type") or "generic"
    return make_event(
        source=src,
        severity=raw.get("severity", "info"),
        title=raw.get("title", ""),
        detail=raw.get("detail", ""),
        type=raw.get("type"),
        category=raw.get("category"),
        event_type=raw.get("event_type"),
        data=raw.get("data") if isinstance(raw.get("data"), dict) else {},
        target=raw.get("target") if isinstance(raw.get("target"), dict) else {},
        actor=raw.get("actor") if isinstance(raw.get("actor"), dict) else {},
        evidence=raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {},
        origin=raw.get("origin", default_origin),
        ts=raw.get("ts"),
    )


def enrich_event(event, event_id=None, agent_id="", tenant_id="default", host=None):
    """Lengkapi event dengan identitas (dipasang manager saat ingest)."""
    event = dict(event)
    event["event_id"] = event_id or ("evt_" + uuid.uuid4().hex[:16])
    event["agent_id"] = agent_id
    event["tenant_id"] = tenant_id
    event["timestamp"] = iso(event.get("ts", now()))
    if host:
        event["host"] = host
    return event


# --------------------------------------------------------------------------- ALERT
def make_alert(agent_id, rule, event, tenant_id="default", ts=None):
    """Bangun alert dari sebuah rule yang cocok + event sumbernya."""
    level = max(0, min(15, int(rule.get("level", severity_to_level(rule.get("severity", "medium"))))))
    t = int(ts or event.get("ts") or now())
    return {
        "id": "alt_" + uuid.uuid4().hex[:12],
        "ts": t,
        "timestamp": iso(t),
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "level": level,
        "severity": level_to_severity(level),
        # Judul spesifik: pakai judul EVENT (mis. "CVE-xxxx: paket versi", "Port 445
        # (SMB)", "Proses mencurigakan: mimikatz") agar bisa di-triage; nama rule
        # tetap tersimpan di field rule.name.
        "title": event.get("title") or rule.get("name", "Alert"),
        "description": rule.get("name", "") or rule.get("description", event.get("detail", "")),
        "category": event.get("category", ""),
        "event_type": event.get("event_type", ""),
        "event_ref": event.get("event_id", ""),
        "target": event.get("target", {}),
        "evidence": event.get("evidence", {}),
        "rule": {
            "id": rule.get("id", ""),
            "name": rule.get("name", ""),
            "mitre": rule.get("mitre", []),
            "recommendation": rule.get("recommendation", ""),
            "response": rule.get("response", []),
        },
        "status": "open",            # open | ack | resolved
        "origin": clamp_origin(event.get("origin", "real")),
    }


# --------------------------------------------------------------------------- REPORT
def build_report(scope, alerts, events, agents=None):
    by_sev = {s: 0 for s in SEVERITIES}
    for a in alerts:
        by_sev[clamp_severity(a.get("severity"))] += 1
    mitre = sorted({m for a in alerts
                    for m in (a.get("mitre") or a.get("rule", {}).get("mitre") or [])})
    return {
        "schema": "nexus.report/v1",
        "generated_at": now(),
        "generated_iso": iso(now()),
        "scope": scope,
        "summary": {
            "alerts_total": len(alerts),
            "events_total": len(events),
            "agents_total": len(agents or []),
            "by_severity": by_sev,
            "risk_score": sum(a.get("level", 0) for a in alerts),
            "top_level": max([a.get("level", 0) for a in alerts], default=0),
            "mitre_techniques": mitre,
        },
        "alerts": alerts,
        "events": events,
        "agents": agents or [],
    }

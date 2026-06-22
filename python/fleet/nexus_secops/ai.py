# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_secops/ai.py
"""
Nexus AI — mesin triase keamanan LOKAL (tanpa API eksternal / tanpa token).

Berbeda dari LLM awan (Security Copilot/Charlotte/Purple AI), ini AI MILIK Nexus
yang:
  • murni Python stdlib — ikut terinstall otomatis bersama Nexus, tak ada paket
    tambahan, tak ada kunci API, tak ada biaya token;
  • jalan lokal saat manager dijalankan (autostart) — melatih dirinya dari data
    yang ada lalu mentriase insiden baru secara real-time;
  • DAPAT DIJELASKAN — bukan kotak hitam.

Komponennya (semua nyata, dihitung dari data asli):
  1. Naive Bayes classifier — BELAJAR dari keputusan analis (alert yang ditutup
     'resolved' = cenderung benign vs yang dieskalasi = ancaman) untuk menaksir
     kemungkinan false-positive → mengurangi alert fatigue dari waktu ke waktu.
  2. Penilai prioritas (P1/P2/P3) — heuristik transparan dari severity, panjang
     kill-chain, sinyal kompromi aktif (proses jahat/IOC/anomali), teknik MITRE
     berdampak tinggi; diredam oleh taksiran false-positive.
  3. Peringkas kill-chain (NLG template) — narasi bahasa manusia dari timeline.
  4. Perekomendasi respons — basis pengetahuan MITRE + sinyal.
  5. Penerjemah bahasa→kueri (NL→NQL) — intent/keyword, dwibahasa ID/EN.

Model & hasil triase disimpan di tabel ai_model / ai_triage (DB manager).
"""
import json
import math
import re
import sqlite3
import time

from nexus_common import protocol as fc

# Persona AI lokal Nexus. Diberi nama agar mudah dikenali/dipasarkan ("tanya AI-nya"),
# bukan sekadar "fitur AI". Tetap 100% lokal — tanpa API/token.
ASSISTANT_NAME = "Ask Nexus"
ASSISTANT_TAGLINE = "asisten keamanan lokal Nexus — tanpa token, data tak keluar jaringan"

_MODEL = None            # cache model NB per-proses (dimuat dari DB / hasil train)


# --------------------------------------------------------------------------- DB
def _conn():
    c = sqlite3.connect(fc.manager_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    return c


def ensure_tables(c):
    """Buat tabel AI pada koneksi `c` (tanpa commit)."""
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_model (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS ai_triage (
            id TEXT PRIMARY KEY, ts INTEGER, incident_id TEXT, entity TEXT,
            priority TEXT, score INTEGER, confidence INTEGER, fp_likelihood INTEGER,
            summary TEXT, recommendations TEXT, reasons TEXT, tenant_id TEXT DEFAULT 'default'
        );
        CREATE INDEX IF NOT EXISTS idx_ai_triage_ts ON ai_triage(ts DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_triage_inc ON ai_triage(incident_id);
        """
    )


def init_db():
    c = _conn()
    ensure_tables(c)
    c.commit(); c.close()


# --------------------------------------------------------------------------- Naive Bayes
def _featurize(a):
    """Ubah alert -> token fitur kategorikal untuk classifier."""
    toks = []
    if a.get("rule_id"):
        toks.append("rule:" + str(a["rule_id"]))
    if a.get("category"):
        toks.append("cat:" + str(a["category"]))
    if a.get("event_type"):
        toks.append("etype:" + str(a["event_type"]))
    if a.get("severity"):
        toks.append("sev:" + str(a["severity"]))
    lvl = int(a.get("level", 0) or 0)
    toks.append("lvl:" + ("hi" if lvl >= 12 else "md" if lvl >= 8 else "lo"))
    for m in (a.get("mitre") or []):
        toks.append("mitre:" + str(m))
    return toks


def _label(a):
    """Label belajar dari disposisi analis: 'benign' (ditutup & level rendah) vs
    'threat' (tereskalasi / level tinggi). Sisanya tak dilabeli (None)."""
    status = a.get("status", "open")
    lvl = int(a.get("level", 0) or 0)
    if lvl >= 12:
        return "threat"
    if status == "resolved" and lvl < 12:
        return "benign"
    if status == "ack":
        return "threat"
    return None            # open & level rendah -> menunggu, tak dipakai latih


def train(tenant="default", min_per_class=8):
    """Latih classifier dari riwayat alert berlabel. Idempoten; aman dipanggil saat
    autostart. Bila data tiap kelas < min_per_class, model ditandai 'untrained'
    (predict mengembalikan netral) — jujur, tak menebak dari data tak cukup."""
    global _MODEL
    init_db()
    c = _conn()
    rows = c.execute("SELECT rule_id, category, event_type, severity, level, mitre, status "
                     "FROM alerts WHERE COALESCE(tenant_id,'default')=?", (tenant,)).fetchall()
    class_counts = {"benign": 0, "threat": 0}
    tok_counts = {"benign": {}, "threat": {}}
    vocab = set()
    for r in rows:
        a = dict(r)
        try:
            a["mitre"] = json.loads(r["mitre"]) if r["mitre"] else []
        except Exception:
            a["mitre"] = []
        lab = _label(a)
        if not lab:
            continue
        class_counts[lab] += 1
        for t in _featurize(a):
            tok_counts[lab][t] = tok_counts[lab].get(t, 0) + 1
            vocab.add(t)
    trained = class_counts["benign"] >= min_per_class and class_counts["threat"] >= min_per_class
    model = {"class_counts": class_counts, "tok_counts": tok_counts,
             "vocab_size": len(vocab), "tok_totals": {k: sum(v.values()) for k, v in tok_counts.items()},
             "samples": sum(class_counts.values()), "trained": trained, "trained_ts": fc.now()}
    c.execute("INSERT INTO ai_model(key,value) VALUES('nb',?) "
              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(model),))
    c.commit(); c.close()
    _MODEL = model
    return {"ok": True, "module": "nexus_secops", "trained": trained,
            "samples": model["samples"], "by_class": class_counts}


def _load_model():
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    init_db()
    c = _conn()
    r = c.execute("SELECT value FROM ai_model WHERE key='nb'").fetchone()
    c.close()
    _MODEL = json.loads(r["value"]) if r else None
    return _MODEL


def predict_benign(alert):
    """P(benign) untuk sebuah alert via Naive Bayes (Laplace-smoothed). Netral 0.5
    bila model belum terlatih cukup."""
    m = _load_model()
    if not m or not m.get("trained"):
        return 0.5
    V = max(1, m["vocab_size"])
    logp = {}
    total = m["samples"] or 1
    for cls in ("benign", "threat"):
        lp = math.log((m["class_counts"][cls] + 1) / (total + 2))
        denom = m["tok_totals"].get(cls, 0) + V
        counts = m["tok_counts"].get(cls, {})
        for t in _featurize(alert):
            lp += math.log((counts.get(t, 0) + 1) / denom)
        logp[cls] = lp
    # softmax 2 kelas -> probabilitas benign
    mx = max(logp.values())
    ex = {k: math.exp(v - mx) for k, v in logp.items()}
    s = sum(ex.values()) or 1
    return ex["benign"] / s


# --------------------------------------------------------------------------- knowledge base
_MITRE_ADVICE = {
    "T1110": "Reset kredensial akun terdampak; terapkan rate-limit/fail2ban + MFA.",
    "T1059": "Hentikan proses berbahaya; audit script/command; isolasi host.",
    "T1071": "Blokir domain/IP C2; periksa beacon berkala; isolasi host yang menghubungi.",
    "T1486": "DUGAAN RANSOMWARE — isolasi SEGERA, putus file-share, pulihkan dari backup bersih.",
    "T1005": "Audit akses data; rotasi secret; periksa indikasi eksfiltrasi.",
    "T1078": "Tinjau akun yang dipakai; cabut sesi aktif; audit hak akses berlebih.",
    "T1190": "Tambal aplikasi rentan; periksa webshell/backdoor; perketat WAF.",
    "T1505.003": "Cari & hapus webshell; tinjau integritas file webroot.",
    "T1552": "Rotasi semua secret yang mungkin bocor; pindahkan ke vault server-side.",
    "T1562.004": "Aktifkan kembali firewall; audit perubahan aturan yang menonaktifkannya.",
    "T1046": "Tutup/filter layanan terekspos ke VPN/allowlist; pantau pemindaian.",
    "T1595": "Blokir IP pemindai; pastikan tak ada endpoint sensitif terekspos.",
}
# Saran berbasis sinyal langsung (lebih spesifik dari MITRE umum).
_SIGNAL_ADVICE = {
    "ioc_match": ("Blokir IP/domain IOC (playbook PB-TI-BLOCK) & cari indikator terkait.", "PB-TI-BLOCK"),
    "suspicious_process": ("Hentikan proses & isolasi host (playbook PB-SUSPROC-KILL).", "PB-SUSPROC-KILL"),
    "behavior_anomaly": ("Verifikasi aktivitas entitas dengan pemiliknya; cabut sesi bila mencurigakan.", "PB-UEBA-NOTIFY"),
    "suspicious_lineage": ("Hentikan rantai proses & isolasi host; periksa webshell/eksploitasi pada induk (PB-SUSPROC-KILL).", "PB-SUSPROC-KILL"),
    "cloud_finding": ("Perbaiki konfigurasi cloud sesuai CIS (tutup akses publik/port admin, aktifkan MFA/enkripsi).", "PB-CLOUD-NOTIFY"),
    "network_threat": ("Blokir IP tujuan C2/beaconing & isolasi host; telusuri proses pengirim (PB-NDR-BLOCK).", "PB-NDR-BLOCK"),
    "web_attack": ("Blokir IP sumber (PB-WEBATTACK-BLOCK); validasi input; tinjau log akses.", "PB-WEBATTACK-BLOCK"),
    "failed_login": ("Blokir IP brute-force; terapkan MFA & lockout.", None),
}
_HIGH_IMPACT_MITRE = {"T1486", "T1490", "T1005", "T1041", "T1567", "T1071"}


# --------------------------------------------------------------------------- triage
def _fetch_alerts_by_ids(c, ids):
    if not ids:
        return []
    ph = ",".join("?" * len(ids))
    rows = c.execute(f"SELECT id, rule_id, category, event_type, severity, level, mitre, "
                     f"status, target, evidence, title, ts FROM alerts WHERE id IN ({ph})",
                     ids).fetchall()
    out = []
    for r in rows:
        a = dict(r)
        for col in ("mitre", "target", "evidence"):
            try:
                a[col] = json.loads(r[col]) if r[col] else ([] if col == "mitre" else {})
            except Exception:
                a[col] = [] if col == "mitre" else {}
        out.append(a)
    return out


def _priority_band(score):
    return "P1" if score >= 70 else "P2" if score >= 45 else "P3"


def triage_incident(incident_id, tenant="default", record=True):
    """Triase satu insiden XDR: prioritas, skor, taksiran false-positive, ringkasan
    kill-chain, & rekomendasi respons. Semua dari data NYATA insiden."""
    from nexus_secops import correlate as xdr
    g = xdr.get_incident(incident_id, tenant)
    if not g.get("ok"):
        return {"ok": False, "error": "insiden tak ditemukan"}
    inc = g["incident"]
    c = _conn()
    contributors = _fetch_alerts_by_ids(c, inc.get("alert_ids", []))
    c.close()

    signals = set()
    for a in contributors:
        if a.get("event_type"):
            signals.add(a["event_type"])
        if a.get("rule_id"):
            signals.add(a["rule_id"])
    mitre = inc.get("mitre", [])

    reasons = []
    score = round(int(inc.get("level", 0)) / 15 * 60)        # 0-60 dari severity
    reasons.append(f"severity insiden level {inc.get('level', 0)} → dasar {score}")
    active = signals & {"ioc_match", "suspicious_process", "NEXUS-TI-001", "NEXUS-PROC-001"}
    if active:
        score += 20; reasons.append("sinyal kompromi aktif (+20): " + ", ".join(sorted(active)))
    if "behavior_anomaly" in signals or "NEXUS-UEBA-001" in signals:
        score += 10; reasons.append("anomali perilaku UEBA (+10)")
    if int(inc.get("count", 0)) >= 3:
        score += 10; reasons.append(f"kill-chain panjang {inc.get('count')} tahap (+10)")
    hi = set(mitre) & _HIGH_IMPACT_MITRE
    if hi:
        score += 15; reasons.append("teknik MITRE berdampak tinggi (+15): " + ", ".join(sorted(hi)))
    score = max(0, min(100, score))

    # Redam oleh taksiran false-positive (NB belajar dari analis).
    p_benign = (sum(predict_benign(a) for a in contributors) / len(contributors)
                if contributors else 0.5)
    effective = round(score * (1 - 0.4 * p_benign))
    priority = _priority_band(effective)
    if p_benign >= 0.6:
        reasons.append(f"model menaksir kemungkinan benign {round(p_benign*100)}% "
                       f"→ prioritas diredam ke {effective}")

    m = _load_model()
    conf = 0.4 + 0.1 * min(len(signals), 3) + (0.2 if (m and m.get("trained")) else 0.0)
    conf = round(min(1.0, conf) * 100)

    summary = summarize(inc, priority, effective, p_benign)
    recs = recommend(inc, signals)

    result = {"ok": True, "module": "nexus_secops", "incident_id": incident_id,
              "entity": inc.get("entity", ""), "priority": priority, "score": effective,
              "raw_score": score, "confidence": conf, "fp_likelihood": round(p_benign * 100),
              "summary": summary, "recommendations": recs, "reasons": reasons}
    if record:
        c = _conn()
        c.execute(
            "INSERT INTO ai_triage(id,ts,incident_id,entity,priority,score,confidence,"
            "fp_likelihood,summary,recommendations,reasons,tenant_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET "
            "ts=excluded.ts, priority=excluded.priority, score=excluded.score, "
            "confidence=excluded.confidence, fp_likelihood=excluded.fp_likelihood, "
            "summary=excluded.summary, recommendations=excluded.recommendations, "
            "reasons=excluded.reasons",
            ("ait_" + incident_id, fc.now(), incident_id, inc.get("entity", ""), priority,
             effective, conf, round(p_benign * 100), summary, json.dumps(recs),
             json.dumps(reasons), tenant))
        c.commit(); c.close()
    return result


def summarize(inc, priority, score, p_benign):
    """NLG template: ubah timeline insiden jadi narasi bahasa manusia (ID)."""
    tl = inc.get("timeline", [])
    chain = " → ".join(f"[{step.get('ts_iso','')[11:16]}] {step.get('title','')}" for step in tl) \
        or "(tanpa rincian timeline)"
    mitre = ", ".join(inc.get("mitre", [])) or "—"
    fp_note = ("kemungkinan besar BENIGN/false-positive — verifikasi singkat disarankan"
               if p_benign >= 0.6 else
               "konsisten dengan ancaman nyata" if p_benign <= 0.35 else
               "perlu konfirmasi analis")
    return (f"Prioritas {priority} (skor {score}/100). Insiden \"{inc.get('name','')}\" pada "
            f"entitas {inc.get('entity','')} menggabungkan {inc.get('count',0)} sinyal. "
            f"Rangkaian: {chain}. Teknik MITRE: {mitre}. "
            f"Penilaian AI: {fp_note}.")


def recommend(inc, signals):
    """Rekomendasi respons dari sinyal + teknik MITRE (+ saran playbook SOAR)."""
    recs, playbooks = [], []
    for sig, (advice, pb) in _SIGNAL_ADVICE.items():
        if sig in signals or any(sig in str(s) for s in signals):
            recs.append(advice)
            if pb:
                playbooks.append(pb)
    for tech in inc.get("mitre", []):
        if tech in _MITRE_ADVICE:
            recs.append(_MITRE_ADVICE[tech])
    if not recs:
        recs.append(inc.get("recommendation", "") or "Tinjau insiden secara manual; "
                    "kumpulkan konteks tambahan sebelum mengambil tindakan.")
    # dedup jaga urutan
    seen, uniq = set(), []
    for r in recs:
        if r not in seen:
            seen.add(r); uniq.append(r)
    return {"actions": uniq, "suggested_playbooks": sorted(set(playbooks))}


def triage_incidents(incident_ids, tenant="default"):
    out = []
    for iid in incident_ids or []:
        r = triage_incident(iid, tenant)
        if r.get("ok"):
            out.append({"incident_id": iid, "priority": r["priority"], "score": r["score"]})
    return {"ok": True, "module": "nexus_secops", "triaged": len(out), "results": out}


def triage_all(status="open", limit=200, tenant="default"):
    from nexus_secops import correlate as xdr
    incs = xdr.list_incidents(status, int(limit), tenant)["incidents"]
    return triage_incidents([i["id"] for i in incs], tenant)


def list_triage(limit=200, priority="", tenant="default"):
    init_db()
    c = _conn()
    q = "SELECT * FROM ai_triage WHERE COALESCE(tenant_id,'default')=?"
    params = [tenant]
    if priority:
        q += " AND priority=?"; params.append(priority)
    q += " ORDER BY score DESC, ts DESC LIMIT ?"; params.append(int(limit))
    rows = c.execute(q, params).fetchall()
    c.close()
    return {"ok": True, "module": "nexus_secops", "triage": [{
        "incident_id": r["incident_id"], "entity": r["entity"], "priority": r["priority"],
        "score": r["score"], "confidence": r["confidence"], "fp_likelihood": r["fp_likelihood"],
        "summary": r["summary"], "recommendations": _j(r["recommendations"], {}),
        "ts_iso": fc.iso(r["ts"]),
    } for r in rows]}


# --------------------------------------------------------------------------- NL -> NQL
_NL_RULES = [
    (r"gagal login|failed login|brute.?force|brute|login gagal", "event_type:failed_login"),
    (r"proses (mencurigakan|jahat)|suspicious process|malware proc", "event_type:suspicious_process"),
    (r"\bioc\b|threat intel|indikator|c2|command.and.control", "event_type:ioc_match"),
    (r"anomali|behavior|perilaku|ueba", "event_type:behavior_anomaly"),
    (r"serangan web|web attack|sqli|xss", "event_type:web_attack"),
    (r"firewall (mati|nonaktif|off)", "rule_id:NEXUS-FW-001"),
    (r"kritis|critical", "severity>=critical"),
    (r"high|tinggi|berisiko tinggi", "severity>=high"),
    (r"hari ini|today|24 jam|last day", "last:24h"),
    (r"minggu ini|this week|7 hari|seminggu", "last:7d"),
    (r"jam terakhir|last hour|1 jam", "last:1h"),
    (r"bulan ini|this month|30 hari", "last:30d"),
]
_ENTITY_RE = re.compile(r"\b(agt_[a-z0-9]+)\b", re.I)


def nl_query(text):
    """Terjemahkan kalimat (ID/EN) → kueri NQL (intent/keyword). Best-effort &
    transparan: mengembalikan NQL + bagian yang dikenali. Jika tak ada yang cocok,
    fallback ke pencarian teks bebas."""
    t = (text or "").lower()
    parts, matched = [], []
    for pat, frag in _NL_RULES:
        if re.search(pat, t):
            if frag not in parts:
                parts.append(frag); matched.append(pat.split("|")[0])
    em = _ENTITY_RE.search(text or "")
    if em:
        parts.append("agent_id:" + em.group(1))
    index = "alerts" if ("alert" in t or "insiden" in t or "incident" in t) else "events"
    if not parts:
        # tak ada intent dikenal → cari kata kunci bermakna sebagai teks bebas
        words = [w for w in re.findall(r"[a-z0-9_.:-]{3,}", t)
                 if w not in ("cari", "tampilkan", "show", "find", "semua", "all", "dari", "the")]
        nql = " ".join(words[:6])
        return {"ok": True, "module": "nexus_secops", "assistant": ASSISTANT_NAME,
                "index": index, "nql": nql, "matched": [],
                "note": "tak ada intent dikenal — memakai pencarian teks bebas"}
    return {"ok": True, "module": "nexus_secops", "assistant": ASSISTANT_NAME,
            "index": index, "nql": " ".join(parts), "matched": matched}


# --------------------------------------------------------------------------- lifecycle
def autostart(tenant="default"):
    """Dipanggil saat manager start: latih model dari data yang ada lalu triase
    insiden terbuka. Membuat AI 'hidup begitu aplikasi dijalankan' tanpa intervensi."""
    try:
        tr = train(tenant)
        ta = triage_all("open", 200, tenant)
        return {"ok": True, "trained": tr.get("trained"), "samples": tr.get("samples"),
                "triaged": ta.get("triaged", 0)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def model_status(tenant="default"):
    m = _load_model()
    return {"ok": True, "module": "nexus_secops",
            "trained": bool(m and m.get("trained")),
            "samples": (m or {}).get("samples", 0),
            "by_class": (m or {}).get("class_counts", {}),
            "trained_iso": fc.iso((m or {}).get("trained_ts", 0)) if m else "—"}


def _j(s, default=None):
    try:
        return json.loads(s) if s else (default if default is not None else {})
    except Exception:
        return default if default is not None else {}

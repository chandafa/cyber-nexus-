# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus/python/modules/sbom.py
"""
Modul SBOM + Dependency-Risk Scanner — supply-chain shift-left.

Developer-first: dijalankan di CI / pre-commit. HANYA stdlib Python — tanpa tool
eksternal, tanpa jaringan secara default (offline-first). Setiap "AI"/heuristik
adalah aturan lokal deterministik (TANPA API/token eksternal).

Alur:
  1. Temukan & urai manifest dependensi di bawah `path` (atau `manifest` eksplisit):
     requirements.txt, pyproject.toml, package.json, package-lock.json, go.mod,
     Cargo.lock, pom.xml. Hasilkan daftar komponen ternormalisasi (SBOM):
     [{ecosystem, name, version}].
  2. Silang-rujuk komponen dgn basis advisory CVE LOKAL. Bila DB fleet manager
     tersedia (nexus_manager/vulndb.py) ia dipakai; jika tidak, seed advisory
     kecil bawaan dipakai. Struktur memungkinkan DB yang lebih lengkap di-drop-in
     (kwargs `vulndb` = path JSON, atau env NEXUS_SBOM_VULNDB).
  3. Deteksi risiko nyata: pin ke versi known-bad, dan (bonus) secret plaintext di
     manifest.
  4. Kembalikan dict berbentuk baik + sanggup memancarkan SBOM CycloneDX-lite JSON.

Return shape:
  {
    module: 'sbom', ok, components:[{ecosystem,name,version}],
    findings:[{component,version,severity,advisory,cve?,ecosystem,kind}],
    counts:{critical,high,medium,low}, sbom_format:'cyclonedx-lite', ...
  }
"""
import json
import os
import re

try:
    from core.stream_handler import emit_line
except Exception:  # pragma: no cover — agar modul tetap dipakai mandiri (tes/CI)
    def emit_line(line: str) -> None:
        pass

# Nama manifest yang dipindai. Ekosistem -> daftar nama berkas.
MANIFEST_NAMES = {
    'pypi': ['requirements.txt', 'pyproject.toml'],
    'npm': ['package.json', 'package-lock.json'],
    'go': ['go.mod'],
    'cargo': ['Cargo.lock'],
    'maven': ['pom.xml'],
}
_ALL_MANIFESTS = {n for names in MANIFEST_NAMES.values() for n in names}

# Direktori yang dilewati saat penelusuran (vendored / build artefak).
_SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', 'venv', '.venv', 'env', '__pycache__',
    'dist', 'build', 'target', '.tox', '.mypy_cache', 'site-packages',
}

MAX_DEPTH = 6
MAX_FILES = 400

# --------------------------------------------------------------------------- seed advisory DB
# Seed advisory list — SENGAJA kecil & jelas ditandai "seed". DB lebih lengkap bisa
# di-drop-in (lihat _load_vulndb). `product` dicocokkan sbg KATA UTUH (lowercase);
# `fixed` = versi pertama yang aman; opsional `introduced` = batas bawah terdampak;
# opsional `ecosystem` mempersempit pencocokan ke satu ekosistem.
SEED_VULN_DB = [
    # --- Python (PyPI) ---
    {"product": "django", "ecosystem": "pypi", "introduced": "0", "fixed": "3.2.18",
     "cve": "CVE-2023-24580", "severity": "high",
     "title": "Django multipart parser DoS (file upload)"},
    {"product": "flask", "ecosystem": "pypi", "introduced": "0", "fixed": "2.2.5",
     "cve": "CVE-2023-30861", "severity": "high",
     "title": "Flask session cookie leak via caching proxies"},
    {"product": "requests", "ecosystem": "pypi", "introduced": "0", "fixed": "2.31.0",
     "cve": "CVE-2023-32681", "severity": "medium",
     "title": "requests leaks Proxy-Authorization header on redirect"},
    {"product": "pyyaml", "ecosystem": "pypi", "introduced": "0", "fixed": "5.4",
     "cve": "CVE-2020-14343", "severity": "critical",
     "title": "PyYAML arbitrary code execution via full_load"},
    {"product": "urllib3", "ecosystem": "pypi", "introduced": "0", "fixed": "1.26.18",
     "cve": "CVE-2023-45803", "severity": "medium",
     "title": "urllib3 request body leak on redirect"},
    {"product": "jinja2", "ecosystem": "pypi", "introduced": "0", "fixed": "2.11.3",
     "cve": "CVE-2020-28493", "severity": "medium",
     "title": "Jinja2 ReDoS in urlize filter"},
    {"product": "cryptography", "ecosystem": "pypi", "introduced": "0", "fixed": "41.0.0",
     "cve": "CVE-2023-23931", "severity": "medium",
     "title": "pyca/cryptography Cipher.update_into out-of-bounds write"},
    # --- npm ---
    {"product": "lodash", "ecosystem": "npm", "introduced": "0", "fixed": "4.17.21",
     "cve": "CVE-2021-23337", "severity": "high",
     "title": "lodash command injection via template"},
    {"product": "minimist", "ecosystem": "npm", "introduced": "0", "fixed": "1.2.6",
     "cve": "CVE-2021-44906", "severity": "critical",
     "title": "minimist prototype pollution"},
    {"product": "axios", "ecosystem": "npm", "introduced": "0", "fixed": "0.21.2",
     "cve": "CVE-2021-3749", "severity": "high",
     "title": "axios ReDoS via trim regex"},
    {"product": "ejs", "ecosystem": "npm", "introduced": "0", "fixed": "3.1.7",
     "cve": "CVE-2022-29078", "severity": "critical",
     "title": "ejs server-side template injection (RCE)"},
    # --- Go ---
    {"product": "github.com/gin-gonic/gin", "ecosystem": "go", "introduced": "0", "fixed": "1.9.1",
     "cve": "CVE-2023-29401", "severity": "medium",
     "title": "gin filename header injection in Content-Disposition"},
    # --- Rust (crates) ---
    {"product": "openssl", "ecosystem": "cargo", "introduced": "0", "fixed": "0.10.55",
     "cve": "RUSTSEC-2023-0044", "severity": "medium",
     "title": "rust openssl X509 name constraints bypass"},
    # --- Maven ---
    {"product": "log4j-core", "ecosystem": "maven", "introduced": "2.0", "fixed": "2.17.1",
     "cve": "CVE-2021-44228", "severity": "critical",
     "title": "Log4Shell — Log4j JNDI RCE"},
]
SEED_MARKER = "seed"  # menandai temuan berasal dari DB seed bawaan

# Versi yang TER-PIN ke rilis "known-bad" terkenal (independen dari DB CVE).
KNOWN_BAD_PINS = {
    ('pypi', 'pyyaml'): {'3.13', '5.1', '5.2', '5.3'},
    ('npm', 'event-stream'): {'3.3.6'},   # supply-chain incident terkenal
    ('npm', 'left-pad'): {'0.0.3'},
}

# Heuristik secret plaintext dalam manifest (deteksi kasar; meminimalkan FP).
_SECRET_PATTERNS = [
    ('aws_access_key', re.compile(r'AKIA[0-9A-Z]{16}')),
    ('github_token', re.compile(r'ghp_[A-Za-z0-9]{36}')),
    ('slack_token', re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}')),
    ('private_key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('generic_secret', re.compile(
        r'(?i)["\']?(?:password|passwd|secret|api[_-]?key|token)["\']?\s*[=:]\s*'
        r'["\']([^"\']{8,})["\']')),
]

_SEV_ORDER = ['low', 'medium', 'high', 'critical']


# --------------------------------------------------------------------------- versi util
def _parse_ver(v):
    out = []
    for part in re.split(r'[.\-+~_]', str(v or '')):
        num = ''.join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return out


def _vless(a, b):
    """True bila versi a < b (perbandingan numerik per komponen)."""
    pa, pb = _parse_ver(a), _parse_ver(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa < pb


def _clean_ver(raw):
    """Buang penanda rentang (^ ~ >= == * dsb.) → versi konkret bila ada."""
    if not raw:
        return ''
    s = str(raw).strip().strip('"\'')
    s = s.lstrip('^~=<>! ').strip()
    m = re.search(r'\d+(?:\.\d+){0,3}(?:[.\-+][A-Za-z0-9]+)*', s)
    return m.group(0) if m else s


# --------------------------------------------------------------------------- parser manifest
def _parse_requirements(text):
    comps = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line or line.startswith('-'):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*([=<>!~]=?.*)?$', line)
        if not m:
            continue
        name = m.group(1).lower()
        ver = _clean_ver(m.group(2) or '')
        comps.append({'ecosystem': 'pypi', 'name': name, 'version': ver})
    return comps


def _parse_pyproject(text):
    comps = []
    # [project] dependencies = ["x>=1", ...]  ATAU  [tool.poetry.dependencies] x = "^1"
    dep_block = re.search(r'dependencies\s*=\s*\[(.*?)\]', text, re.DOTALL)
    if dep_block:
        for item in re.findall(r'["\']([^"\']+)["\']', dep_block.group(1)):
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*([=<>!~].*)?$', item.strip())
            if m:
                comps.append({'ecosystem': 'pypi', 'name': m.group(1).lower(),
                              'version': _clean_ver(m.group(2) or '')})
    poetry = re.search(r'\[tool\.poetry\.dependencies\](.*?)(?:\n\[|\Z)', text, re.DOTALL)
    if poetry:
        for line in poetry.group(1).splitlines():
            line = line.split('#', 1)[0].strip()
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*["\']?([^"\'{}]+)?', line)
            if m and m.group(1).lower() != 'python':
                comps.append({'ecosystem': 'pypi', 'name': m.group(1).lower(),
                              'version': _clean_ver(m.group(2) or '')})
    return comps


def _parse_package_json(text):
    comps = []
    try:
        data = json.loads(text)
    except Exception:
        return comps
    for key in ('dependencies', 'devDependencies', 'optionalDependencies'):
        for name, ver in (data.get(key) or {}).items():
            comps.append({'ecosystem': 'npm', 'name': str(name).lower(),
                          'version': _clean_ver(ver)})
    return comps


def _parse_package_lock(text):
    comps = []
    try:
        data = json.loads(text)
    except Exception:
        return comps
    # lockfile v2/v3: "packages": {"node_modules/x": {version}} ; v1: "dependencies"
    for path, meta in (data.get('packages') or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = path.split('node_modules/')[-1]
        if name:
            comps.append({'ecosystem': 'npm', 'name': name.lower(),
                          'version': _clean_ver(meta.get('version', ''))})

    def _walk(deps):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                comps.append({'ecosystem': 'npm', 'name': str(name).lower(),
                              'version': _clean_ver(meta.get('version', ''))})
                _walk(meta.get('dependencies'))
    _walk(data.get('dependencies'))
    return comps


def _parse_go_mod(text):
    comps = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('require ('):
            in_block = True
            continue
        if in_block and s == ')':
            in_block = False
            continue
        s = re.sub(r'//.*$', '', s).strip()
        if s.startswith('require '):
            s = s[len('require '):].strip()
        elif not in_block:
            continue
        m = re.match(r'^(\S+)\s+v([0-9][\w.\-+]*)', s)
        if m:
            comps.append({'ecosystem': 'go', 'name': m.group(1).lower(),
                          'version': _clean_ver(m.group(2))})
    return comps


def _parse_cargo_lock(text):
    comps = []
    name = ver = None
    for line in text.splitlines():
        s = line.strip()
        if s == '[[package]]':
            name = ver = None
            continue
        mn = re.match(r'^name\s*=\s*"([^"]+)"', s)
        mv = re.match(r'^version\s*=\s*"([^"]+)"', s)
        if mn:
            name = mn.group(1).lower()
        elif mv:
            ver = mv.group(1)
        if name and ver:
            comps.append({'ecosystem': 'cargo', 'name': name, 'version': _clean_ver(ver)})
            name = ver = None
    return comps


def _parse_pom_xml(text):
    comps = []
    for dep in re.findall(r'<dependency>(.*?)</dependency>', text, re.DOTALL):
        gid = re.search(r'<groupId>\s*([^<]+?)\s*</groupId>', dep)
        aid = re.search(r'<artifactId>\s*([^<]+?)\s*</artifactId>', dep)
        ver = re.search(r'<version>\s*([^<]+?)\s*</version>', dep)
        if aid:
            name = aid.group(1).strip().lower()
            comps.append({'ecosystem': 'maven', 'name': name,
                          'group': gid.group(1).strip().lower() if gid else '',
                          'version': _clean_ver(ver.group(1)) if ver else ''})
    return comps


_PARSERS = {
    'requirements.txt': _parse_requirements,
    'pyproject.toml': _parse_pyproject,
    'package.json': _parse_package_json,
    'package-lock.json': _parse_package_lock,
    'go.mod': _parse_go_mod,
    'Cargo.lock': _parse_cargo_lock,
    'pom.xml': _parse_pom_xml,
}


def _read(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return f.read()
    except OSError:
        return ''


def _parse_manifest_file(path):
    """Urai satu berkas manifest → (components, basename) atau ([], basename)."""
    base = os.path.basename(path)
    parser = _PARSERS.get(base)
    if not parser:
        return [], base
    return parser(_read(path)), base


def _find_manifests(root):
    """Telusuri root → daftar path manifest (lewati dir vendored, batasi kedalaman)."""
    found = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == '.' else rel.count(os.sep) + 1
        if depth > MAX_DEPTH:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith('.')]
        for fn in filenames:
            if fn in _ALL_MANIFESTS:
                found.append(os.path.join(dirpath, fn))
                if len(found) >= MAX_FILES:
                    return found
    return found


# --------------------------------------------------------------------------- vuln DB
def _load_vulndb(explicit_path=None):
    """
    Muat basis advisory. Prioritas:
      1. path JSON eksplisit (kwarg `vulndb` / env NEXUS_SBOM_VULNDB) — drop-in.
      2. DB fleet manager (nexus_manager/vulndb.py) bila importable.
      3. seed bawaan.
    Kembalikan (db_list, source_label).
    """
    path = explicit_path or os.environ.get('NEXUS_SBOM_VULNDB', '')
    if path and os.path.isfile(path):
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                return data, f'file:{os.path.basename(path)}'
        except Exception:
            pass
    # DB fleet (read-only) — dipakai bila ada, tanpa memodifikasi tree fleet.
    try:
        from fleet.nexus_manager import vulndb as _fleet_vulndb
        fleet_db = list(getattr(_fleet_vulndb, 'DEFAULT_VULN_DB', []) or [])
        if fleet_db:
            # Gabungkan dgn seed agar cakupan ekosistem dev (npm/go/cargo) tetap ada.
            return SEED_VULN_DB + fleet_db, 'fleet+seed'
    except Exception:
        pass
    return SEED_VULN_DB, SEED_MARKER


def _product_in(product, name):
    """Cocok produk sbg KATA UTUH (anti FP: 'git' tak cocok 'github')."""
    product = product.lower()
    name = name.lower()
    if product == name:
        return True
    try:
        return re.search(r'(?<![a-z0-9])' + re.escape(product) + r'(?![a-z0-9])',
                         name) is not None
    except Exception:
        return product in name


def _match_advisories(components, db):
    """Cocokkan komponen dgn DB advisory → list temuan."""
    findings = []
    seen = set()
    for comp in components:
        eco = comp.get('ecosystem', '')
        name = str(comp.get('name', '')).lower()
        ver = comp.get('version', '')
        if not name or not ver:
            continue
        for entry in db:
            entry_eco = entry.get('ecosystem')
            if entry_eco and entry_eco != eco:
                continue
            if not _product_in(str(entry.get('product', '')), name):
                continue
            fixed = entry.get('fixed', '')
            if fixed and not _vless(ver, fixed):
                continue
            intro = entry.get('introduced')
            if intro and intro not in ('0', 0) and _vless(ver, intro):
                continue
            cve = entry.get('cve', '')
            key = (eco, name, cve)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                'component': comp.get('name'), 'version': ver,
                'ecosystem': eco, 'kind': 'vulnerable_dependency',
                'severity': str(entry.get('severity', 'medium')).lower(),
                'advisory': entry.get('title', ''),
                'cve': cve, 'fixed': fixed,
            })
    return findings


def _detect_known_bad_pins(components):
    findings = []
    for comp in components:
        eco = comp.get('ecosystem', '')
        name = str(comp.get('name', '')).lower()
        ver = comp.get('version', '')
        bad = KNOWN_BAD_PINS.get((eco, name))
        if bad and ver in bad:
            findings.append({
                'component': comp.get('name'), 'version': ver, 'ecosystem': eco,
                'kind': 'known_bad_pin', 'severity': 'high',
                'advisory': f'Pinned to known-bad release {name}=={ver}',
                'cve': None,
            })
    return findings


def _detect_secrets(manifest_files):
    """Pindai isi manifest untuk secret plaintext (bonus)."""
    findings = []
    for path in manifest_files:
        text = _read(path)
        base = os.path.basename(path)
        for kind, pat in _SECRET_PATTERNS:
            if pat.search(text):
                findings.append({
                    'component': base, 'version': '', 'ecosystem': '',
                    'kind': 'plaintext_secret', 'severity': 'critical',
                    'advisory': f'Potential plaintext secret ({kind}) in {base}',
                    'cve': None,
                })
                break  # satu temuan per berkas cukup untuk gate
    return findings


# --------------------------------------------------------------------------- CycloneDX
def emit_cyclonedx(components, findings=None):
    """Pancarkan SBOM bergaya CycloneDX (lite) sebagai dict JSON-serializable."""
    findings = findings or []
    by_comp = {}
    for f in findings:
        if f.get('cve'):
            by_comp.setdefault((f.get('ecosystem'), f.get('component')), []).append(f)

    bom_components = []
    for c in components:
        eco = c.get('ecosystem', '')
        name = c.get('name', '')
        ver = c.get('version', '')
        purl = f'pkg:{eco}/{name}@{ver}' if ver else f'pkg:{eco}/{name}'
        entry = {
            'type': 'library',
            'name': name,
            'version': ver,
            'purl': purl,
        }
        vulns = by_comp.get((eco, name))
        if vulns:
            entry['vulnerabilities'] = [
                {'id': v.get('cve'), 'severity': v.get('severity'),
                 'description': v.get('advisory')} for v in vulns
            ]
        bom_components.append(entry)

    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'version': 1,
        'metadata': {'tools': [{'vendor': 'Nexus Security', 'name': 'nexus-sbom'}]},
        'components': bom_components,
    }


# --------------------------------------------------------------------------- entry
def _dedupe(components):
    out, seen = [], set()
    for c in components:
        key = (c.get('ecosystem'), c.get('name'), c.get('version'))
        if key in seen:
            continue
        seen.add(key)
        out.append({'ecosystem': c.get('ecosystem', ''), 'name': c.get('name', ''),
                    'version': c.get('version', '')})
    return out


def run(path: str = '.', manifest: str = '', vulndb: str = '',
        online: str = 'false', emit_sbom: str = 'false', **kwargs) -> dict:
    """
    Entry point dipanggil runner.py / CLI. SBOM scan offline-first.

    kwargs:
      path     : direktori target (default '.').
      manifest : berkas manifest eksplisit (override penelusuran).
      vulndb   : path JSON DB advisory drop-in (opsional).
      online   : 'true' untuk opt-in lookup online (BELUM aktif — placeholder, offline default).
      emit_sbom: 'true' untuk sertakan dokumen CycloneDX di hasil.
    """
    cb = emit_line
    online_on = str(online).lower() in ('1', 'true', 'yes', 'on')

    # 1) Kumpulkan berkas manifest.
    if manifest:
        if not os.path.isfile(manifest):
            return {'module': 'sbom', 'ok': False,
                    'error': f'manifest tidak ditemukan: {manifest}',
                    'components': [], 'findings': [],
                    'counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'sbom_format': 'cyclonedx-lite'}
        manifest_files = [manifest]
    else:
        target = path or '.'
        if not os.path.isdir(target):
            return {'module': 'sbom', 'ok': False,
                    'error': f'path bukan direktori: {target}',
                    'components': [], 'findings': [],
                    'counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'sbom_format': 'cyclonedx-lite'}
        manifest_files = _find_manifests(target)

    cb(f'[*] SBOM scan — {len(manifest_files)} manifest ditemukan di {path or manifest}')

    # 2) Urai komponen.
    components = []
    parsed_manifests = []
    for mf in manifest_files:
        comps, base = _parse_manifest_file(mf)
        if comps:
            parsed_manifests.append(base)
            cb(f'    [+] {base}: {len(comps)} komponen')
        components.extend(comps)
    components = _dedupe(components)

    # 3) Cocokkan advisory + deteksi risiko.
    db, db_source = _load_vulndb(vulndb)
    findings = _match_advisories(components, db)
    findings += _detect_known_bad_pins(components)
    findings += _detect_secrets(manifest_files)

    if online_on:
        # Opt-in online lookup adalah extension point — TETAP offline secara default.
        cb('[!] online lookup diminta tetapi dinonaktifkan (offline-first; belum diimplementasi)')

    # 4) Hitung severity & tentukan gate.
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        sev = f.get('severity', 'low')
        counts[sev] = counts.get(sev, 0) + 1

    gate_fail = (counts['critical'] + counts['high']) > 0

    for f in findings:
        cb(f'    [{f["severity"].upper()}] {f["component"]} {f.get("version","")} '
           f'— {f.get("advisory","")}' + (f' ({f["cve"]})' if f.get('cve') else ''))
    cb(f'[*] selesai — {len(components)} komponen, {len(findings)} temuan '
       f'(crit={counts["critical"]} high={counts["high"]} '
       f'med={counts["medium"]} low={counts["low"]})')
    if gate_fail:
        cb('[GATE] temuan high/critical → gate GAGAL (ok=false)')

    result = {
        'module': 'sbom',
        'ok': not gate_fail,            # FALSE bila ada high/critical → CI gate gagal
        'path': path,
        'manifests': parsed_manifests,
        'components': components,
        'findings': findings,
        'counts': counts,
        'total_components': len(components),
        'total_findings': len(findings),
        'gate_failed': gate_fail,
        'vulndb_source': db_source,
        'online': online_on,
        'sbom_format': 'cyclonedx-lite',
    }
    if str(emit_sbom).lower() in ('1', 'true', 'yes', 'on'):
        result['cyclonedx'] = emit_cyclonedx(components, findings)
    return result

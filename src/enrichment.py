"""
enrichment.py — CVE/EPSS/KEV enrichment for normalized pipeline findings.

Pipeline: extract_fingerprints → fingerprint_to_cpe → query_nvd →
          query_epss (batched) → load_kev_catalog → EnrichmentFinding records
"""

import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Optional
from urllib.parse import quote as url_quote, urlparse

import requests

from parsers import AppVersionProbeFinding

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(_SRC_DIR, '..', 'output')
CACHE_DIR = os.path.join(OUTPUT_DIR, 'cache')
_NVD_CACHE = os.path.join(CACHE_DIR, 'nvd')
_EPSS_CACHE = os.path.join(CACHE_DIR, 'epss')
_KEV_CACHE = os.path.join(CACHE_DIR, 'kev')

for _d in (_NVD_CACHE, _EPSS_CACHE, _KEV_CACHE):
    os.makedirs(_d, exist_ok=True)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Fingerprint:
    product: str          # normalised lowercase, underscores (e.g. "juice_shop")
    version: str          # raw version string; '' if unknown
    source_tool: str      # "httpx" | "nmap" | "nuclei" | "wpscan" | "app_version_probe"
    source_id: str        # tool-specific identifier (URL, template_id, …)
    matched_version: str  # the raw string that was parsed to get version


@dataclass
class EnrichmentErrorFinding:
    tool: str = "enrichment_error"
    message: str = ''


@dataclass
class EnrichmentFinding:
    tool: str = "enrichment"
    source_finding: str = ''       # "{source_tool}:{source_id}"
    product: str = ''
    version: str = ''
    matched_version: str = ''
    cpe: str = ''
    cve_id: str = ''
    cvss_score: Optional[float] = None
    cvss_severity: str = 'none'    # critical|high|medium|low|none
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False
    published: str = ''            # ISO date string
    description: str = ''
    references: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
_EPSS_API = 'https://api.first.org/data/v1/epss'
_KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

_CACHE_TTL_SECS = 86_400  # 24 hours

# NVD rate limits: 5 req/30 s (no key), 50 req/30 s (with key)
_NVD_API_KEY = os.getenv('NVD_API_KEY', '')
_NVD_DELAY   = 6.5 if not _NVD_API_KEY else 0.7   # conservative inter-request gap

# Hardcoded CPE prefix map for known apps: product → (vendor, cpe_product)
# Version is appended at call time. Avoids fuzzy NVD CPE-match API calls.
_CPE_MAP: dict[str, tuple[str, str]] = {
    'juice_shop':  ('owasp',     'juice_shop'),
    'wordpress':   ('wordpress', 'wordpress'),
    'hugo':        ('gohugo',    'hugo'),
    'express':     ('expressjs', 'express'),
    'node.js':     ('nodejs',    'node.js'),
    'apache':      ('apache',    'http_server'),
    'nginx':       ('nginx',     'nginx'),
    'php':         ('php',       'php'),
    'jquery':      ('jquery',    'jquery'),
    'bootstrap':   ('twitter',   'bootstrap'),
    'drupal':      ('drupal',    'drupal'),
    'joomla':      ('joomla',    'joomla\\!'),
    'mysql':       ('oracle',    'mysql'),
    'mariadb':     ('mariadb',   'mariadb'),
    'openssl':     ('openssl',   'openssl'),
    'tomcat':      ('apache',    'tomcat'),
    'iis':         ('microsoft', 'internet_information_services'),
}

# Nuclei template-id patterns that carry version information
_NUCLEI_VERSION_PATTERNS = (
    '-detect', '-version', '-disclosure', '-fingerprint',
)

# Reference source priority for truncation (lower index = higher priority)
_REF_PRIORITY = ('nvd.nist.gov', 'cisa.gov', 'mitre.org', 'exploit-db.com')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str):
    print(f'[ENRICHMENT] {msg}')


def _cache_path(cache_dir: str, key: str, suffix: str = '.json') -> str:
    safe = hashlib.sha256(key.encode()).hexdigest()
    return os.path.join(cache_dir, safe + suffix)


def _cache_valid(path: str, ttl: int = _CACHE_TTL_SECS) -> bool:
    if not os.path.exists(path):
        return False
    age = time.time() - os.path.getmtime(path)
    return age < ttl


def _read_cache(path: str):
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def _write_cache(path: str, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(data, fh)


def _cvss_severity(score: Optional[float]) -> str:
    if score is None:
        return 'none'
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    if score > 0.0:
        return 'low'
    return 'none'


def _prioritise_refs(refs: list[str], limit: int = 3) -> list[str]:
    """Sort references by source priority, return top `limit`."""
    def _rank(url: str) -> int:
        for i, domain in enumerate(_REF_PRIORITY):
            if domain in url:
                return i
        return len(_REF_PRIORITY)
    return sorted(refs, key=_rank)[:limit]


def _normalise_product(raw: str) -> str:
    """Lowercase, strip common version suffixes, replace spaces with underscores."""
    name = raw.lower().split(':')[0].strip()
    name = re.sub(r'\s+', '_', name)
    return name


def _parse_tech_version(tech: str) -> tuple[str, str]:
    """Split 'Product:1.2.3' → ('product', '1.2.3'). Returns ('product', '') if no version."""
    parts = tech.split(':', 1)
    product = _normalise_product(parts[0])
    version = parts[1].strip() if len(parts) == 2 else ''
    return product, version


# ---------------------------------------------------------------------------
# 3a. Fingerprint extraction
# ---------------------------------------------------------------------------

def extract_fingerprints(findings: list[dict]) -> list[Fingerprint]:
    """
    Walk normalised findings dicts and extract (product, version) fingerprints.
    Returns a deduplicated list ordered by confidence (versioned first).
    """
    seen: set[tuple[str, str]] = set()
    fps: list[Fingerprint] = []

    def _add(fp: Fingerprint):
        key = (fp.product, fp.version)
        if key not in seen and fp.product:
            seen.add(key)
            fps.append(fp)

    for f in findings:
        tool = f.get('tool', '')

        # --- httpx: parse technologies list ---
        if tool == 'httpx':
            for tech in f.get('technologies', []):
                product, version = _parse_tech_version(tech)
                if not product or product in ('hsts', 'cdn', 'waf'):
                    continue
                _add(Fingerprint(
                    product=product,
                    version=version,
                    source_tool='httpx',
                    source_id=f.get('url', ''),
                    matched_version=tech,
                ))
            # webserver field (may carry "Apache/2.4.51" style)
            ws = f.get('webserver', '')
            if ws:
                product, version = _parse_tech_version(ws.replace('/', ':'))
                if product:
                    _add(Fingerprint(
                        product=product,
                        version=version,
                        source_tool='httpx',
                        source_id=f.get('url', ''),
                        matched_version=ws,
                    ))

        # --- nmap: product + version fields ---
        elif tool == 'nmap':
            product = _normalise_product(f.get('product', ''))
            version = (f.get('version') or '').strip()
            if product:
                _add(Fingerprint(
                    product=product,
                    version=version,
                    source_tool='nmap',
                    source_id=f'{f.get("host", "")}:{f.get("port", "")}',
                    matched_version=f'{f.get("product", "")} {version}'.strip(),
                ))

        # --- nuclei: detect/version templates with extracted_results ---
        elif tool == 'nuclei':
            tid = f.get('template_id', '')
            if not any(pat in tid for pat in _NUCLEI_VERSION_PATTERNS):
                continue
            extracted = f.get('extracted_results', [])
            version = extracted[0].strip() if extracted else ''
            # Derive product from template_id: strip suffix patterns
            product_raw = tid
            for pat in _NUCLEI_VERSION_PATTERNS:
                product_raw = product_raw.replace(pat, '')
            product = _normalise_product(product_raw.replace('-', '_'))
            if product:
                _add(Fingerprint(
                    product=product,
                    version=version,
                    source_tool='nuclei',
                    source_id=tid,
                    matched_version=version or tid,
                ))

        # --- wpscan: use the version field added to WpscanFinding ---
        elif tool == 'wpscan':
            version = (f.get('version') or '').strip()
            if version:
                _add(Fingerprint(
                    product='wordpress',
                    version=version,
                    source_tool='wpscan',
                    source_id=f.get('host', ''),
                    matched_version=version,
                ))

        # --- app_version_probe: already structured ---
        elif tool == 'app_version_probe':
            product = _normalise_product(f.get('product', ''))
            version = (f.get('version') or '').strip()
            if product:
                _add(Fingerprint(
                    product=product,
                    version=version,
                    source_tool='app_version_probe',
                    source_id=f.get('host', ''),
                    matched_version=version,
                ))

    # Versioned fingerprints first — they produce more precise CPEs
    fps.sort(key=lambda fp: (fp.version == '', fp.product))
    _log(f'Extracted {len(fps)} unique fingerprint(s): '
         + ', '.join(f'{fp.product}:{fp.version or "?"}' for fp in fps))
    return fps


# ---------------------------------------------------------------------------
# 3b. App-version probe
# ---------------------------------------------------------------------------

_APP_VERSION_PROBES = [
    # (path, product, version_extractor_fn, parse_mode)
    # parse_mode: 'json' — extractor receives parsed dict
    #             'text' — extractor receives raw response string
    ('/rest/admin/application-version',
     'juice_shop',
     lambda data: data.get('version', ''),
     'json'),
    # /wp-json/wp/v2 returns 404 without pretty permalinks.
    # /?feed=rss2 always works and contains the generator tag with the WP version.
    ('/?feed=rss2',
     'wordpress',
     lambda raw: next((m.group(1) for m in [re.search(r'wordpress\.org/\?v=([0-9.]+)', raw)] if m), ''),
     'text'),
]


def _docker_get_json(endpoint: str, network: str, timeout: int) -> tuple[str, dict] | tuple[None, None]:
    """
    Fetch `endpoint` via `docker run --network {network} curlimages/curl`.
    Returns (raw_text, parsed_dict) on success, (None, None) on any failure.
    """
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '--network', network,
             'curlimages/curl', '-s', '--max-time', str(timeout),
             '-H', 'Accept: application/json', endpoint],
            capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=timeout + 5,
        )
        raw = result.stdout.strip()
        if not raw:
            _log(f'docker probe empty stdout for {endpoint} '
                 f'(exit={result.returncode} stderr={result.stderr[:120]!r})')
            return None, None
        return raw, json.loads(raw)
    except subprocess.TimeoutExpired:
        _log(f'docker probe timed out for {endpoint}')
        return None, None
    except json.JSONDecodeError as exc:
        _log(f'docker probe non-JSON response for {endpoint}: {exc}')
        return None, None
    except Exception as exc:
        _log(f'docker probe error for {endpoint}: {type(exc).__name__}: {exc}')
        return None, None


def _docker_get_text(endpoint: str, network: str, timeout: int) -> str | None:
    """
    Fetch `endpoint` via docker/curl and return the raw response text.
    Returns None on failure or empty response.
    """
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '--network', network,
             'curlimages/curl', '-s', '--max-time', str(timeout), endpoint],
            capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=timeout + 5,
        )
        raw = result.stdout.strip()
        if not raw:
            _log(f'docker text-probe empty stdout for {endpoint} '
                 f'(exit={result.returncode} stderr={result.stderr[:120]!r})')
            return None
        return raw
    except subprocess.TimeoutExpired:
        _log(f'docker text-probe timed out for {endpoint}')
        return None
    except Exception as exc:
        _log(f'docker text-probe error for {endpoint}: {type(exc).__name__}: {exc}')
        return None


def probe_app_versions(base_urls: list[str],
                       existing_fps: list[Fingerprint] | None = None,
                       network: str = 'scan-net',
                       timeout: int = 10) -> list[AppVersionProbeFinding]:
    """
    Hit known app-version endpoints on each live URL.
    Normalises each URL to scheme://host:port before appending probe paths,
    so path components from live_urls are never duplicated.
    Requests are made via `docker run --network {network}` so Docker-internal
    hostnames (e.g. juice-shop) resolve correctly.
    Skips probes whose product is already in existing_fps.
    Returns AppVersionProbeFinding dataclass instances.
    """
    already = {fp.product for fp in (existing_fps or [])}
    results: list[AppVersionProbeFinding] = []
    seen_bases: set[str] = set()

    for raw_url in base_urls:
        parsed = urlparse(raw_url)
        base = f'{parsed.scheme}://{parsed.netloc}'  # strip any path component
        if base in seen_bases:
            continue
        seen_bases.add(base)

        for path, product, extractor, parse_mode in _APP_VERSION_PROBES:
            if product in already:
                _log(f'Skipping {product} probe on {base} — already fingerprinted')
                continue
            endpoint = base + path
            try:
                if parse_mode == 'text':
                    raw = _docker_get_text(endpoint, network, timeout) if network else None
                    if not raw:
                        if not network:
                            resp = requests.get(endpoint, timeout=timeout)
                            raw = resp.text if resp.status_code == 200 else None
                        if not raw:
                            continue
                    version = extractor(raw) or ''
                    data_for_log = raw
                else:
                    if network:
                        raw, data = _docker_get_json(endpoint, network, timeout)
                    else:
                        resp = requests.get(endpoint, timeout=timeout,
                                            headers={'Accept': 'application/json'})
                        raw = resp.text if resp.status_code == 200 else None
                        data = resp.json() if raw else None
                    if not data:
                        continue
                    version = extractor(data) or ''
                    data_for_log = raw

                if not version:
                    _log(f'App-version probe: no version extracted from {endpoint}')
                    continue
                snippet = (data_for_log or '')[:200]
                _log(f'App-version probe: {product} {version} at {endpoint}')
                results.append(AppVersionProbeFinding(
                    url=base,
                    endpoint=endpoint,
                    product=product,
                    version=version,
                    raw_response_snippet=snippet,
                ))
                already.add(product)
            except Exception as exc:
                _log(f'Probe {endpoint} failed: {exc}')

    return results


# ---------------------------------------------------------------------------
# 3c. CPE mapping
# ---------------------------------------------------------------------------

def fingerprint_to_cpe(fp: Fingerprint) -> Optional[str]:
    """
    Return a CPE 2.3 string for the fingerprint, or None if no confident mapping.
    Uses the hardcoded _CPE_MAP; does not call the NVD CPE-match API to avoid
    extra rate-limit pressure during development.
    """
    key = fp.product.lower()
    if key not in _CPE_MAP:
        _log(f'No CPE mapping for "{fp.product}" — skipping')
        return None
    vendor, cpe_product = _CPE_MAP[key]
    version = fp.version if fp.version else '*'
    return f'cpe:2.3:a:{vendor}:{cpe_product}:{version}:*:*:*:*:*:*:*'


# ---------------------------------------------------------------------------
# 3d. NVD lookup
# ---------------------------------------------------------------------------

def query_nvd(cpe: str) -> list[dict]:
    """
    Query NVD CVEs v2 API for `cpe`. Returns list of raw CVE dicts with
    keys: cve_id, cvss_score, cvss_severity, published, description, references.
    Caches results for 24 h. Implements exponential backoff on 429/403.
    """
    cache_file = _cache_path(_NVD_CACHE, cpe)
    if _cache_valid(cache_file):
        _log(f'NVD cache hit: {cpe}')
        return _read_cache(cache_file)

    headers = {}
    if _NVD_API_KEY:
        headers['apiKey'] = _NVD_API_KEY

    params = {'cpeName': cpe, 'resultsPerPage': 50}
    backoff = 10

    for attempt in range(4):
        try:
            resp = requests.get(_NVD_API, params=params, headers=headers, timeout=30)
        except requests.RequestException as exc:
            _log(f'NVD request error ({cpe}): {exc}')
            return []

        if resp.status_code == 200:
            break
        if resp.status_code in (403, 429):
            _log(f'NVD rate-limited (attempt {attempt+1}), backing off {backoff}s …')
            time.sleep(backoff)
            backoff *= 2
            continue
        _log(f'NVD returned HTTP {resp.status_code} for {cpe}')
        return []
    else:
        _log(f'NVD: all retry attempts exhausted for {cpe}')
        return []

    try:
        raw = resp.json()
    except ValueError:
        _log('NVD response is not valid JSON')
        return []

    cves = []
    for item in raw.get('vulnerabilities', []):
        cve_block = item.get('cve', {})
        cve_id = cve_block.get('id', '')

        # CVSS v3 preferred, fall back to v2
        metrics = cve_block.get('metrics', {})
        cvss_score = None
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            entries = metrics.get(key)
            if entries:
                cvss_data = entries[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')
                break

        # Description (English preferred)
        desc = ''
        for d in cve_block.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break
        desc = desc[:300]

        # References with priority sort
        all_refs = [r.get('url', '') for r in cve_block.get('references', []) if r.get('url')]
        refs = _prioritise_refs(all_refs, limit=3)

        published = cve_block.get('published', '')[:10]  # ISO date only

        cves.append({
            'cve_id':        cve_id,
            'cvss_score':    cvss_score,
            'cvss_severity': _cvss_severity(cvss_score),
            'published':     published,
            'description':   desc,
            'references':    refs,
        })

    _log(f'NVD: {len(cves)} CVE(s) for {cpe}')
    _write_cache(cache_file, cves)
    time.sleep(_NVD_DELAY)   # respect rate limit between calls
    return cves


# ---------------------------------------------------------------------------
# 3e. EPSS lookup
# ---------------------------------------------------------------------------

def query_epss(cve_ids: list[str]) -> dict[str, dict]:
    """
    Batch-query FIRST.org EPSS API (up to 100 CVEs per request).
    Returns {cve_id: {'score': float, 'percentile': float}}.
    Caches per calendar date (EPSS updates daily).
    """
    today = date.today().isoformat()
    cache_file = os.path.join(_EPSS_CACHE, f'{today}.json')

    cached: dict[str, dict] = {}
    if _cache_valid(cache_file, ttl=_CACHE_TTL_SECS):
        cached = _read_cache(cache_file)

    missing = [c for c in cve_ids if c not in cached]
    if not missing:
        _log(f'EPSS cache hit for all {len(cve_ids)} CVE(s)')
        return {c: cached[c] for c in cve_ids if c in cached}

    # Batch in chunks of 100
    results = dict(cached)
    for i in range(0, len(missing), 100):
        chunk = missing[i:i + 100]
        try:
            resp = requests.get(
                _EPSS_API,
                params={'cve': ','.join(chunk)},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json().get('data', [])
            for entry in data:
                cid = entry.get('cve', '')
                results[cid] = {
                    'score':      float(entry.get('epss', 0)),
                    'percentile': float(entry.get('percentile', 0)),
                }
        except Exception as exc:
            _log(f'EPSS request error: {exc}')

    _write_cache(cache_file, results)
    _log(f'EPSS: scored {len(results)} CVE(s)')
    return {c: results[c] for c in cve_ids if c in results}


# ---------------------------------------------------------------------------
# 3f. CISA KEV catalog
# ---------------------------------------------------------------------------

def load_kev_catalog() -> set[str]:
    """
    Download CISA KEV catalog (cached 24 h).
    Returns set of CVE IDs in the catalog.
    """
    cache_file = os.path.join(_KEV_CACHE, 'kev.json')
    if _cache_valid(cache_file):
        _log('KEV cache hit')
        data = _read_cache(cache_file)
        return set(v['cveID'] for v in data.get('vulnerabilities', []))

    _log('Downloading CISA KEV catalog …')
    try:
        resp = requests.get(_KEV_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        _write_cache(cache_file, data)
        kev_ids = set(v['cveID'] for v in data.get('vulnerabilities', []))
        _log(f'KEV: {len(kev_ids)} entries loaded')
        return kev_ids
    except Exception as exc:
        _log(f'KEV download failed: {exc}')
        return set()


# ---------------------------------------------------------------------------
# 3g. Orchestrator
# ---------------------------------------------------------------------------

def enrich(findings: list[dict]) -> list[EnrichmentFinding]:
    """
    Full enrichment pipeline over a list of normalised finding dicts.
    Returns EnrichmentFinding records (one per CVE per fingerprint).
    API failures for any single fingerprint are logged and skipped — the
    pipeline does not crash.
    """
    fingerprints = extract_fingerprints(findings)
    if not fingerprints:
        _log('No fingerprints extracted — nothing to enrich')
        return []

    # Load KEV once for the whole run
    try:
        kev = load_kev_catalog()
    except Exception as exc:
        _log(f'KEV load failed, continuing without KEV data: {exc}')
        kev = set()

    all_cve_records: list[tuple[Fingerprint, str, dict]] = []  # (fp, cpe, cve_dict)

    for fp in fingerprints:
        cpe = fingerprint_to_cpe(fp)
        if not cpe:
            continue

        _log(f'Querying NVD: {cpe}')
        try:
            cves = query_nvd(cpe)
        except Exception as exc:
            _log(f'NVD query failed for {cpe}: {exc} — skipping')
            continue

        for cve in cves:
            all_cve_records.append((fp, cpe, cve))

    if not all_cve_records:
        _log('NVD returned no CVEs for any fingerprint')
        return []

    # Batch EPSS for all CVE IDs at once
    all_cve_ids = list({rec[2]['cve_id'] for rec in all_cve_records})
    try:
        epss_map = query_epss(all_cve_ids)
    except Exception as exc:
        _log(f'EPSS batch failed: {exc} — continuing without EPSS scores')
        epss_map = {}

    enriched: list[EnrichmentFinding] = []
    for fp, cpe, cve in all_cve_records:
        cve_id = cve['cve_id']
        epss = epss_map.get(cve_id, {})
        enriched.append(EnrichmentFinding(
            source_finding=f'{fp.source_tool}:{fp.source_id}',
            product=fp.product,
            version=fp.version,
            matched_version=fp.matched_version,
            cpe=cpe,
            cve_id=cve_id,
            cvss_score=cve['cvss_score'],
            cvss_severity=cve['cvss_severity'],
            epss_score=epss.get('score'),
            epss_percentile=epss.get('percentile'),
            in_kev=cve_id in kev,
            published=cve['published'],
            description=cve['description'],
            references=cve['references'],
        ))

    enriched.sort(key=lambda e: (
        -(e.epss_score or 0),
        -(e.cvss_score or 0),
    ))

    _log(f'Enrichment complete: {len(enriched)} finding(s) from '
         f'{len(fingerprints)} fingerprint(s)')
    return enriched

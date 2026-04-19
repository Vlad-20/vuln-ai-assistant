import json
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple

# Dataclasses

@dataclass
class SubfinderResult:
    tool: str  # "subfinder"
    subdomain: str
    parent_domain: str
    sources: List[str]

@dataclass
class HttpxResult:
    tool: str  # "httpx"
    url: str
    status_code: int
    title: str
    technologies: List[str]
    webserver: str
    ip: str
    cdn: str

@dataclass
class NmapResult:
    tool: str  # "nmap"
    host: str
    port: int
    protocol: str
    service: str
    product: str
    version: str

@dataclass
class FeroxbusterResult:
    tool: str  # "feroxbuster"
    url: str
    status: int
    content_length: int

@dataclass
class KatanaResult:
    tool: str  # "katana"
    url: str
    method: str
    source: str

@dataclass
class NucleiFinding:
    tool: str  # "nuclei"
    host: str
    finding_name: str
    severity: str
    description: str
    template_id: str
    matcher_name: str
    matched_at: str
    extracted_results: List[str]
    curl_command: str
    references: List[str]

@dataclass
class WpscanFinding:
    tool: str  # "wpscan"
    host: str
    finding_name: str
    severity: str
    description: str
    finding_type: str  # "vulnerability", "user_enumerated", "interesting_finding"
    references: Dict[str, Any]
    version: str = ''


@dataclass
class AppVersionProbeFinding:
    tool: str = "app_version_probe"
    url: str = ''                    # base URL that was probed (scheme://host:port)
    endpoint: str = ''               # full URL of the version endpoint
    product: str = ''
    version: str = ''
    raw_response_snippet: str = ''   # truncated to ~200 chars


# Utility

def extract_live_hosts(httpx_jsonl: str) -> Tuple[List[str], List[str]]:
    """
    Parse httpx JSONL and return (all_live_urls, wordpress_urls).
    Used by main.py to drive subsequent per-host scans.
    """
    live_urls: List[str] = []
    wordpress_urls: List[str] = []

    try:
        with open(httpx_jsonl, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get('url') or data.get('input')
                    if not url:
                        continue
                    live_urls.append(url)

                    # tech field can be a list of strings (["WordPress 6.4", "PHP"])
                    tech = data.get('tech') or data.get('technologies') or []
                    if any('wordpress' in t.lower() for t in tech):
                        wordpress_urls.append(url)
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        print(f"httpx output file not found: {httpx_jsonl}")

    return live_urls, wordpress_urls


# Deduplication / filtering

def dedup_subfinder(results: List[SubfinderResult]) -> List[SubfinderResult]:
    seen = set()
    out = []
    for r in results:
        if r.subdomain not in seen:
            seen.add(r.subdomain)
            out.append(r)
    return out

def dedup_httpx(results: List[HttpxResult]) -> List[HttpxResult]:
    seen = set()
    out = []
    for r in results:
        if r.url not in seen:
            seen.add(r.url)
            out.append(r)
    return out

def dedup_nmap(results: List[NmapResult]) -> List[NmapResult]:
    seen = set()
    out = []
    for r in results:
        key = (r.host, r.port, r.protocol)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out

_FEROX_DROP_STATUSES = {404, 403, 400}
_FEROX_MIN_CONTENT_LENGTH = 100

def dedup_feroxbuster(results: List[FeroxbusterResult]) -> List[FeroxbusterResult]:
    seen = set()
    out = []
    for r in results:
        if r.status in _FEROX_DROP_STATUSES:
            continue
        if r.content_length < _FEROX_MIN_CONTENT_LENGTH:
            continue
        if r.url not in seen:
            seen.add(r.url)
            out.append(r)
    return out

_KATANA_DROP_EXTENSIONS = {
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.woff', '.woff2', '.ttf', '.eot', '.ico', '.map',
}

def dedup_katana(results: List[KatanaResult]) -> List[KatanaResult]:
    seen = set()
    out = []
    for r in results:
        # Strip query string for extension check
        path = r.url.split('?')[0].lower()
        if any(path.endswith(ext) for ext in _KATANA_DROP_EXTENSIONS):
            continue
        if r.url not in seen:
            seen.add(r.url)
            out.append(r)
    return out

def dedup_nuclei(results: List[NucleiFinding]) -> List[NucleiFinding]:
    seen = set()
    out = []
    for r in results:
        key = (r.host, r.template_id)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out

def dedup_wpscan(results: List[WpscanFinding]) -> List[WpscanFinding]:
    seen = set()
    out = []
    for r in results:
        key = (r.host, r.finding_name)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


# 1. Subfinder

def parse_subfinder_jsonl(jsonl_file: str) -> List[SubfinderResult]:
    print(f"Parsing Subfinder file: {jsonl_file}...")
    results = []
    try:
        with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    sources = data.get('source', [])
                    if isinstance(sources, str):
                        sources = [sources]
                    results.append(SubfinderResult(
                        tool="subfinder",
                        subdomain=data.get('host', 'unknown'),
                        parent_domain=data.get('input', 'unknown'),
                        sources=sources,
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        results = dedup_subfinder(results)
        print(f"Found {len(results)} Subfinder results (after dedup).")
        return results
    except FileNotFoundError:
        print(f"Subfinder output file not found: {jsonl_file}")
        return []


# 2. httpx

def parse_httpx_jsonl(jsonl_file: str) -> List[HttpxResult]:
    print(f"Parsing httpx file: {jsonl_file}...")
    results = []
    try:
        with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get('url') or data.get('input', 'unknown')
                    tech = data.get('tech') or data.get('technologies') or []
                    results.append(HttpxResult(
                        tool="httpx",
                        url=url,
                        status_code=data.get('status_code', 0),
                        title=data.get('title', ''),
                        technologies=tech if isinstance(tech, list) else [tech],
                        webserver=data.get('webserver') or data.get('server', ''),
                        ip=data.get('ip', ''),
                        cdn=data.get('cdn', ''),
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        results = dedup_httpx(results)
        print(f"Found {len(results)} httpx results (after dedup).")
        return results
    except FileNotFoundError:
        print(f"httpx output file not found: {jsonl_file}")
        return []


# 3. Nmap

def parse_nmap_json(json_file: str) -> List[NmapResult]:
    print(f"Parsing Nmap file: {json_file}...")
    results = []
    try:
        with open(json_file, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)

        for host in data.get('hosts', []):
            host_address = host.get('address', 'unknown')
            for port in host.get('ports', []):
                if port.get('state') != 'open':
                    continue
                service = port.get('service', {})
                results.append(NmapResult(
                    tool="nmap",
                    host=host_address,
                    port=port.get('portid'),
                    protocol=port.get('protocol', ''),
                    service=service.get('name', 'unknown'),
                    product=service.get('product', ''),
                    version=service.get('version', ''),
                ))

        results = dedup_nmap(results)
        print(f"Found {len(results)} Nmap results (after dedup).")
        return results

    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing Nmap JSON: {e}")
        return []
    except FileNotFoundError:
        print(f"Nmap output file not found: {json_file}")
        return []


# 4. Feroxbuster


def parse_feroxbuster_json(json_file: str) -> List[FeroxbusterResult]:
    print(f"Parsing Feroxbuster file: {json_file}...")
    results = []
    try:
        with open(json_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get('type') != 'response':
                        continue
                    results.append(FeroxbusterResult(
                        tool="feroxbuster",
                        url=data.get('url', 'unknown'),
                        status=data.get('status', 0),
                        content_length=data.get('content_length', 0),
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        results = dedup_feroxbuster(results)
        print(f"Found {len(results)} Feroxbuster results (after dedup + filter).")
        return results
    except FileNotFoundError:
        print(f"Feroxbuster output file not found: {json_file}")
        return []


# 5. Katana

def parse_katana_jsonl(jsonl_file: str) -> List[KatanaResult]:
    print(f"Parsing Katana file: {jsonl_file}...")
    results = []
    try:
        with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    request = data.get('request', {})
                    endpoint = request.get('endpoint') or data.get('endpoint', 'unknown')
                    results.append(KatanaResult(
                        tool="katana",
                        url=endpoint,
                        method=request.get('method', 'GET'),
                        source=data.get('source', ''),
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        results = dedup_katana(results)
        print(f"Found {len(results)} Katana results (after dedup + filter).")
        return results
    except FileNotFoundError:
        print(f"Katana output file not found: {jsonl_file}")
        return []


# 6. WPScan

def _cvss_to_severity(raw) -> str:
    try:
        score = float(raw)
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'
    except (ValueError, TypeError):
        return str(raw).lower() if raw else 'medium'

def parse_wpscan_json(json_file: str) -> List[WpscanFinding]:
    print(f"Parsing WPScan file: {json_file}...")
    results = []
    try:
        with open(json_file, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)

        target_url = data.get('target_url', 'unknown')
        wp_version = (data.get('version') or {}).get('number', '')

        for item in data.get('interesting_findings', []):
            results.append(WpscanFinding(
                tool="wpscan",
                host=target_url,
                finding_name=item.get('type', 'interesting_finding'),
                severity='info',
                description=item.get('to_s', ''),
                finding_type='interesting_finding',
                references=item.get('references', {}),
                version=wp_version,
            ))

        wp_version_block = data.get('version') or {}
        for vuln in wp_version_block.get('vulnerabilities', []):
            results.append(WpscanFinding(
                tool="wpscan",
                host=target_url,
                finding_name=vuln.get('title', 'WordPress Vulnerability'),
                severity=_cvss_to_severity(vuln.get('cvss', {}).get('score')),
                description=vuln.get('title', ''),
                finding_type='vulnerability',
                references=vuln.get('references', {}),
                version=wp_version,
            ))

        for plugin_name, plugin_data in data.get('plugins', {}).items():
            for vuln in plugin_data.get('vulnerabilities', []):
                results.append(WpscanFinding(
                    tool="wpscan",
                    host=target_url,
                    finding_name=vuln.get('title', plugin_name),
                    severity=_cvss_to_severity(vuln.get('cvss', {}).get('score')),
                    description=f"Plugin '{plugin_name}': {vuln.get('title', '')}",
                    finding_type='vulnerability',
                    references=vuln.get('references', {}),
                    version=wp_version,
                ))

        for theme_name, theme_data in data.get('themes', {}).items():
            for vuln in theme_data.get('vulnerabilities', []):
                results.append(WpscanFinding(
                    tool="wpscan",
                    host=target_url,
                    finding_name=vuln.get('title', theme_name),
                    severity=_cvss_to_severity(vuln.get('cvss', {}).get('score')),
                    description=f"Theme '{theme_name}': {vuln.get('title', '')}",
                    finding_type='vulnerability',
                    references=vuln.get('references', {}),
                    version=wp_version,
                ))

        for username in data.get('users', {}):
            results.append(WpscanFinding(
                tool="wpscan",
                host=target_url,
                finding_name=f"User: {username}",
                severity='low',
                description=f"WordPress user '{username}' enumerated at {target_url}.",
                finding_type='user_enumerated',
                references={},
                version=wp_version,
            ))

        results = dedup_wpscan(results)
        print(f"Found {len(results)} WPScan findings (after dedup).")
        return results
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing WPScan file {json_file}: {e}")
        return []


# 7. Nuclei

def parse_nuclei_jsonl(jsonl_file: str) -> List[NucleiFinding]:
    print(f"Parsing Nuclei file: {jsonl_file}...")
    results = []
    try:
        with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get('info', {})
                    refs = info.get('reference') or info.get('references') or []
                    if isinstance(refs, str):
                        refs = [refs]
                    extracted = data.get('extracted-results') or data.get('extracted_results') or []
                    results.append(NucleiFinding(
                        tool="nuclei",
                        host=data.get('host', 'unknown'),
                        finding_name=info.get('name', 'N/A'),
                        severity=info.get('severity', 'info'),
                        description=info.get('description', ''),
                        template_id=data.get('template-id') or data.get('template_id', ''),
                        matcher_name=data.get('matcher-name') or data.get('matcher_name', ''),
                        matched_at=data.get('matched-at') or data.get('matched_at', ''),
                        extracted_results=extracted,
                        curl_command=data.get('curl-command') or data.get('curl_command', ''),
                        references=refs,
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        results = dedup_nuclei(results)
        print(f"Found {len(results)} Nuclei findings (after dedup).")
        return results
    except FileNotFoundError:
        print(f"Nuclei output file not found: {jsonl_file}")
        return []

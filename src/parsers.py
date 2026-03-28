import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple

@dataclass
class NormalizedFinding:
    # standardized, unified format for any vuln
    host: str
    port: Optional[int]
    protocol: Optional[str]
    finding_name: str
    severity: str
    source_tool: str
    description: str
    raw_evidence: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

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

                    # tech field can be a list of strings (e.g. ["WordPress 6.4", "PHP"])
                    tech = data.get('tech') or data.get('technologies') or []
                    if any('wordpress' in t.lower() for t in tech):
                        wordpress_urls.append(url)
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        print(f"httpx output file not found: {httpx_jsonl}")

    return live_urls, wordpress_urls


# ---------------------------------------------------------------------------
# Step 1 — Subfinder
# ---------------------------------------------------------------------------

def parse_subfinder_jsonl(jsonl_file: str) -> List[NormalizedFinding]:
    # parses a Subfinder JSON-Lines output file into a list of NormalizedFinding
    # each line: {"host": "sub.example.com", "source": [...], "input": "example.com"}
    print(f"Parsing Subfinder file: {jsonl_file}...")
    findings = []
    try:
        with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = data.get('host', 'unknown')
                    source = data.get('source', '')
                    sources_str = ', '.join(source) if isinstance(source, list) else source
                    input_domain = data.get('input', 'unknown')

                    finding = NormalizedFinding(
                        host=host,
                        port=None,
                        protocol=None,
                        finding_name=f"Subdomain Discovered: {host}",
                        severity="info",
                        source_tool="subfinder",
                        description=f"Subdomain '{host}' discovered for '{input_domain}' via sources: {sources_str}",
                        raw_evidence=data
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        print(f"Found {len(findings)} Subfinder findings.")
        return findings
    except FileNotFoundError:
        print(f"Subfinder output file not found: {jsonl_file}")
        return []


# ---------------------------------------------------------------------------
# Step 2 — httpx
# ---------------------------------------------------------------------------

def parse_httpx_jsonl(jsonl_file: str) -> List[NormalizedFinding]:
    # each line: {"url": "...", "status_code": 200, "title": "...", "tech": [...], ...}
    print(f"Parsing httpx file: {jsonl_file}...")
    findings = []
    try:
        with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get('url') or data.get('input', 'unknown')
                    status = data.get('status_code', 0)
                    title = data.get('title', '')
                    tech = data.get('tech') or data.get('technologies') or []
                    server = data.get('webserver') or data.get('server', '')
                    cdn = data.get('cdn', '')
                    ip = data.get('ip', '')

                    tech_str = ', '.join(tech) if tech else 'N/A'
                    desc = (
                        f"Live host {url} responded with HTTP {status}. "
                        f"Title: '{title}'. Tech: {tech_str}. Server: {server}."
                    )
                    if cdn:
                        desc += f" CDN: {cdn}."
                    if ip:
                        desc += f" IP: {ip}."

                    findings.append(NormalizedFinding(
                        host=url,
                        port=None,
                        protocol=data.get('scheme'),
                        finding_name=f"Live Host: {url}",
                        severity="info",
                        source_tool="httpx",
                        description=desc,
                        raw_evidence=data
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        print(f"Found {len(findings)} httpx findings.")
        return findings
    except FileNotFoundError:
        print(f"httpx output file not found: {jsonl_file}")
        return []


# ---------------------------------------------------------------------------
# Step 3 — Nmap
# ---------------------------------------------------------------------------

def parse_nmap_json(json_file: str) -> List[NormalizedFinding]:
    # Parses the JSON file produced by run_scans._nmap_xml_to_json().
    # Structure: {"hosts": [{"address": "...", "ports": [{"portid": 80, "protocol": "tcp", "state": "open", "service": {...}}]}]}
    print(f"Parsing Nmap file: {json_file}...")
    findings = []
    try:
        with open(json_file, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)

        for host in data.get('hosts', []):
            host_address = host.get('address', 'unknown')
            for port in host.get('ports', []):
                if port.get('state') != 'open':
                    continue
                port_num = port.get('portid')
                port_proto = port.get('protocol')
                service = port.get('service', {})
                service_name = service.get('name', 'unknown')
                product = service.get('product', '')
                version = service.get('version', '')

                findings.append(NormalizedFinding(
                    host=host_address,
                    port=port_num,
                    protocol=port_proto,
                    finding_name=f"Open Port: {service_name}",
                    severity="info",
                    source_tool="nmap",
                    description=f"Service {service_name} detected on port {port_num}/{port_proto}. Product: {product}, Version: {version}",
                    raw_evidence={
                        'port': port_num,
                        'protocol': port_proto,
                        'service': service_name,
                        'product': product,
                        'version': version
                    }
                ))

        print(f"Found {len(findings)} Nmap findings.")
        return findings

    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing Nmap JSON: {e}")
        return []
    except FileNotFoundError:
        print(f"Nmap output file not found: {json_file}")
        return []


# ---------------------------------------------------------------------------
# Step 4 — Feroxbuster
# ---------------------------------------------------------------------------

def parse_feroxbuster_json(json_file: str) -> List[NormalizedFinding]:
    # Feroxbuster --json outputs one JSON object per line (JSONL-style).
    # Relevant entries have "type": "response".
    print(f"Parsing Feroxbuster file: {json_file}...")
    findings = []
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

                    url = data.get('url', 'unknown')
                    status = data.get('status', 0)
                    content_length = data.get('content_length', 0)
                    method = data.get('method', 'GET')

                    findings.append(NormalizedFinding(
                        host=url,
                        port=None,
                        protocol=None,
                        finding_name=f"Directory/File Found: {url}",
                        severity="info",
                        source_tool="feroxbuster",
                        description=f"{method} {url} → HTTP {status}, {content_length} bytes",
                        raw_evidence=data
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        print(f"Found {len(findings)} Feroxbuster findings.")
        return findings
    except FileNotFoundError:
        print(f"Feroxbuster output file not found: {json_file}")
        return []


# ---------------------------------------------------------------------------
# Step 5 — Katana
# ---------------------------------------------------------------------------

def parse_katana_jsonl(jsonl_file: str) -> List[NormalizedFinding]:
    # each line: {"timestamp": "...", "request": {"endpoint": "...", "method": "..."}, ...}
    print(f"Parsing Katana file: {jsonl_file}...")
    findings = []
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
                    method = request.get('method', 'GET')
                    source = data.get('source', '')

                    findings.append(NormalizedFinding(
                        host=endpoint,
                        port=None,
                        protocol=None,
                        finding_name=f"Crawled Endpoint: {endpoint}",
                        severity="info",
                        source_tool="katana",
                        description=f"Endpoint {endpoint} discovered via {method} crawl. Source: {source}",
                        raw_evidence=data
                    ))
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        print(f"Found {len(findings)} Katana findings.")
        return findings
    except FileNotFoundError:
        print(f"Katana output file not found: {jsonl_file}")
        return []


# ---------------------------------------------------------------------------
# Step 6 — WPScan
# ---------------------------------------------------------------------------

def parse_wpscan_json(json_file: str) -> List[NormalizedFinding]:
    # WPScan outputs a single JSON object with keys like:
    # interesting_findings, plugins, themes, users, version, vulnerabilities
    print(f"Parsing WPScan file: {json_file}...")
    findings = []
    try:
        with open(json_file, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)

        target_url = data.get('target_url', 'unknown')

        # Interesting findings (headers, exposed files, etc.)
        for item in data.get('interesting_findings', []):
            url = item.get('url', target_url)
            finding_type = item.get('type', 'interesting_finding')
            references = item.get('references', {})
            findings.append(NormalizedFinding(
                host=target_url,
                port=None,
                protocol=None,
                finding_name=f"WPScan: {finding_type}",
                severity="info",
                source_tool="wpscan",
                description=item.get('to_s', f"{finding_type} at {url}"),
                raw_evidence={'item': item, 'references': references}
            ))

        # WordPress version vulnerabilities
        wp_version = data.get('version') or {}
        for vuln in wp_version.get('vulnerabilities', []):
            severity = vuln.get('cvss', {}).get('score', 'medium')
            # Normalize numeric CVSS score to a label
            try:
                score = float(severity)
                if score >= 9.0:
                    severity = 'critical'
                elif score >= 7.0:
                    severity = 'high'
                elif score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
            except (ValueError, TypeError):
                severity = str(severity).lower() if severity else 'medium'

            findings.append(NormalizedFinding(
                host=target_url,
                port=None,
                protocol=None,
                finding_name=f"WordPress Vulnerability: {vuln.get('title', 'N/A')}",
                severity=severity,
                source_tool="wpscan",
                description=vuln.get('title', 'No description.'),
                raw_evidence=vuln
            ))

        # Plugin vulnerabilities
        for plugin_name, plugin_data in data.get('plugins', {}).items():
            for vuln in plugin_data.get('vulnerabilities', []):
                findings.append(NormalizedFinding(
                    host=target_url,
                    port=None,
                    protocol=None,
                    finding_name=f"WP Plugin Vulnerability: {vuln.get('title', plugin_name)}",
                    severity='medium',
                    source_tool="wpscan",
                    description=f"Plugin '{plugin_name}': {vuln.get('title', 'N/A')}",
                    raw_evidence=vuln
                ))

        # Theme vulnerabilities
        for theme_name, theme_data in data.get('themes', {}).items():
            for vuln in theme_data.get('vulnerabilities', []):
                findings.append(NormalizedFinding(
                    host=target_url,
                    port=None,
                    protocol=None,
                    finding_name=f"WP Theme Vulnerability: {vuln.get('title', theme_name)}",
                    severity='medium',
                    source_tool="wpscan",
                    description=f"Theme '{theme_name}': {vuln.get('title', 'N/A')}",
                    raw_evidence=vuln
                ))

        # Enumerated users
        for username, user_data in data.get('users', {}).items():
            findings.append(NormalizedFinding(
                host=target_url,
                port=None,
                protocol=None,
                finding_name=f"WordPress User Enumerated: {username}",
                severity='low',
                source_tool="wpscan",
                description=f"WordPress user '{username}' was enumerated at {target_url}.",
                raw_evidence=user_data
            ))

        print(f"Found {len(findings)} WPScan findings.")
        return findings
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print(f"Error parsing WPScan file {json_file}: {e}")
        return []


# ---------------------------------------------------------------------------
# Step 7 — Nuclei
# ---------------------------------------------------------------------------

def parse_nuclei_jsonl(jsonl_file: str) -> List[NormalizedFinding]:
    # parses a Nuclei JSON-Lines output file into a list of NormalizedFinding
    print(f"Parsing Nuclei file: {jsonl_file}...")
    findings = []
    try:
        with open(jsonl_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                try:
                    data = json.loads(line)

                    finding = NormalizedFinding(
                        host=data.get('host', 'unknown'),
                        port=None,
                        protocol=data.get('scheme'),
                        finding_name=data.get('info', {}).get('name', 'N/A'),
                        severity=data.get('info', {}).get('severity', 'info'),
                        source_tool="nuclei",
                        description=data.get('info', {}).get('description', 'No description provided.'),
                        raw_evidence=data
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        print(f"Found {len(findings)} Nuclei findings.")
        return findings
    except FileNotFoundError:
        print(f"Nuclei output file not found: {jsonl_file}")
        return []

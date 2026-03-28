import subprocess
import os
import shutil
import json
import re
import time
import xml.etree.ElementTree as ET

# Define output directory
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'output')

# Output file paths
SUBFINDER_OUT = os.path.join(OUTPUT_DIR, 'subfinder_results.jsonl')
HTTPX_OUT = os.path.join(OUTPUT_DIR, 'httpx_results.jsonl')
NMAP_XML  = os.path.join(OUTPUT_DIR, 'nmap_results.xml')
NMAP_OUT  = os.path.join(OUTPUT_DIR, 'nmap_results.json')
NUCLEI_OUT = os.path.join(OUTPUT_DIR, 'nuclei_results.jsonl')
HOSTS_FILE = os.path.join(OUTPUT_DIR, 'hosts.txt')
NUCLEI_TARGETS_FILE = os.path.join(OUTPUT_DIR, 'nuclei_targets.txt')

# Scan timeouts in seconds
SUBFINDER_TIMEOUT = 300
HTTPX_TIMEOUT     = 300
NMAP_TIMEOUT      = 300
FEROXBUSTER_TIMEOUT = 300
KATANA_TIMEOUT    = 180
WPSCAN_TIMEOUT    = 300
NUCLEI_TIMEOUT    = 600

# Wordlist mounted from ./wordlists on the host into the feroxbuster container
FEROXBUSTER_WORDLIST = '/wordlists/common.txt'

# WPScan API token — set the WPSCAN_API_TOKEN env var for vulnerability data
WPSCAN_API_TOKEN = os.environ.get('WPSCAN_API_TOKEN', 'YVGUAfJ3rKShteQfINOPras9y4Yo0gmNaso8SWxmsng')


def setup_environment():
    print("Setting up environment...")
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    print(f"Created new output directory: {OUTPUT_DIR}")


def _is_nonempty(filepath: str) -> bool:
    return os.path.exists(filepath) and os.path.getsize(filepath) > 0


def _sanitize_filename(url: str) -> str:
    """Convert a URL/hostname to a safe filename component."""
    name = re.sub(r'^https?://', '', url)
    name = re.sub(r'[^\w\-.]', '_', name)
    return name.strip('_')


def _run(command: list, timeout: int):
    """Run a subprocess and return CompletedProcess, or raise on error/timeout."""
    return subprocess.run(
        command, check=True, capture_output=True,
        encoding='utf-8', errors='replace', timeout=timeout
    )


# ---------------------------------------------------------------------------
# Step 1 — Subfinder
# ---------------------------------------------------------------------------

def run_subfinder(domain: str):
    print(f"[SUBFINDER] Starting subdomain enumeration on {domain}...")
    command = [
        'docker-compose', 'run', '--rm', 'subfinder',
        '-d', domain,
        '-json', '-all', '-recursive', '-silent',
        '-o', '/output/subfinder_results.jsonl'
    ]
    try:
        _run(command, SUBFINDER_TIMEOUT)
        print(f"[SUBFINDER] Complete. Results: {SUBFINDER_OUT}")
        return SUBFINDER_OUT
    except subprocess.TimeoutExpired:
        print(f"[SUBFINDER] Timed out after {SUBFINDER_TIMEOUT}s. Using partial results if available.")
        return SUBFINDER_OUT if _is_nonempty(SUBFINDER_OUT) else None
    except subprocess.CalledProcessError as e:
        if _is_nonempty(SUBFINDER_OUT):
            print(f"[SUBFINDER] Finished with non-zero exit. Results: {SUBFINDER_OUT}")
            return SUBFINDER_OUT
        print(f"[SUBFINDER] ERROR: {e.stderr}")
        return None


# ---------------------------------------------------------------------------
# Step 2 — httpx
# ---------------------------------------------------------------------------

def _build_hosts_file(subfinder_jsonl: str, original_domain: str) -> str:
    """Extract hosts from subfinder JSONL and write a plain-text list for httpx."""
    hosts = {original_domain}  # always include the root domain

    if subfinder_jsonl and _is_nonempty(subfinder_jsonl):
        try:
            with open(subfinder_jsonl, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        host = data.get('host')
                        if host:
                            hosts.add(host)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[HTTPX] Warning: could not read subfinder output: {e}")

    with open(HOSTS_FILE, 'w') as f:
        f.write('\n'.join(sorted(hosts)))

    print(f"[HTTPX] Built hosts file with {len(hosts)} entries.")
    return HOSTS_FILE


def run_httpx(subfinder_file: str, original_domain: str):
    print(f"[HTTPX] Starting HTTP probing and tech fingerprinting...")
    _build_hosts_file(subfinder_file, original_domain)

    command = [
        'docker-compose', 'run', '--rm', 'httpx',
        '-l', '/output/hosts.txt',
        '-json', '-sc', '-title', '-td', '-server', '-cdn', '-ip',
        '-o', '/output/httpx_results.jsonl',
        '-timeout', '5',    # max 5s per HTTP request
        '-retries', '0',    # no retries on failure
        '-no-color'
    ]
    try:
        _run(command, HTTPX_TIMEOUT)
        print(f"[HTTPX] Complete. Results: {HTTPX_OUT}")
        return HTTPX_OUT
    except subprocess.TimeoutExpired:
        print(f"[HTTPX] Timed out after {HTTPX_TIMEOUT}s. Waiting for container to flush output...")
        time.sleep(8)
        return HTTPX_OUT if _is_nonempty(HTTPX_OUT) else None
    except subprocess.CalledProcessError as e:
        if _is_nonempty(HTTPX_OUT):
            print(f"[HTTPX] Finished with non-zero exit. Results: {HTTPX_OUT}")
            return HTTPX_OUT
        print(f"[HTTPX] ERROR: {e.stderr}")
        return None


# ---------------------------------------------------------------------------
# Step 3 — Nmap
# ---------------------------------------------------------------------------

def _nmap_xml_to_json(xml_path: str, json_path: str):
    """Convert nmap XML output to a structured JSON file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []
    for host in root.findall('host'):
        addr_el = host.find('address')
        address = addr_el.get('addr', 'unknown') if addr_el is not None else 'unknown'
        hostnames = [hn.get('name') for hn in host.findall('.//hostname') if hn.get('name')]
        ports = []
        for port in host.findall('.//port'):
            state_el = port.find('state')
            service_el = port.find('service')
            ports.append({
                'portid': int(port.get('portid', 0)),
                'protocol': port.get('protocol'),
                'state': state_el.get('state') if state_el is not None else 'unknown',
                'service': {
                    'name':    service_el.get('name', '')    if service_el is not None else '',
                    'product': service_el.get('product', '') if service_el is not None else '',
                    'version': service_el.get('version', '') if service_el is not None else '',
                } if service_el is not None else {}
            })
        hosts.append({'address': address, 'hostnames': hostnames, 'ports': ports})

    with open(json_path, 'w') as f:
        json.dump({'hosts': hosts}, f, indent=2)


def run_nmap(target: str):
    print(f"[NMAP] Starting port scan on {target}...")
    command = [
        'docker-compose', 'run', '--rm', 'nmap',
        '-sV', '--top-ports', '100', '-n', '-Pn',
        '-oX', '/output/nmap_results.xml',
        target
    ]
    try:
        _run(command, NMAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"[NMAP] Timed out after {NMAP_TIMEOUT}s. Using partial results if available.")
        if not _is_nonempty(NMAP_XML):
            return None
    except subprocess.CalledProcessError as e:
        if not _is_nonempty(NMAP_XML):
            print(f"[NMAP] ERROR: {e.stderr}")
            return None
        print(f"[NMAP] Finished with non-zero exit. Converting available XML...")

    try:
        _nmap_xml_to_json(NMAP_XML, NMAP_OUT)
        print(f"[NMAP] Complete. Results: {NMAP_OUT}")
        return NMAP_OUT
    except ET.ParseError as e:
        print(f"[NMAP] Failed to convert XML to JSON: {e}")
        return None


# ---------------------------------------------------------------------------
# Step 4 — Feroxbuster
# ---------------------------------------------------------------------------

def run_feroxbuster(url: str):
    print(f"[FEROXBUSTER] Starting directory discovery on {url}...")
    safe_name = _sanitize_filename(url)
    out_container = f'/output/feroxbuster_{safe_name}.json'
    out_local = os.path.join(OUTPUT_DIR, f'feroxbuster_{safe_name}.json')

    command = [
        'docker-compose', 'run', '--rm', 'feroxbuster',
        '--json',
        '-u', url,
        '-w', FEROXBUSTER_WORDLIST,
        '-o', out_container,
        '-q'
    ]
    try:
        _run(command, FEROXBUSTER_TIMEOUT)
        print(f"[FEROXBUSTER] Complete for {url}. Results: {out_local}")
        return out_local
    except subprocess.TimeoutExpired:
        print(f"[FEROXBUSTER] Timed out after {FEROXBUSTER_TIMEOUT}s for {url}. Using partial results if available.")
        return out_local if _is_nonempty(out_local) else None
    except subprocess.CalledProcessError as e:
        if _is_nonempty(out_local):
            print(f"[FEROXBUSTER] Finished with non-zero exit for {url}. Results: {out_local}")
            return out_local
        print(f"[FEROXBUSTER] ERROR for {url}: {e.stderr}")
        return None


# ---------------------------------------------------------------------------
# Step 5 — Katana
# ---------------------------------------------------------------------------

def run_katana(url: str):
    print(f"[KATANA] Starting URL crawling on {url}...")
    safe_name = _sanitize_filename(url)
    out_container = f'/output/katana_{safe_name}.jsonl'
    out_local = os.path.join(OUTPUT_DIR, f'katana_{safe_name}.jsonl')

    command = [
        'docker-compose', 'run', '--rm', 'katana',
        '-json', '-d', '3',
        '-u', url,
        '-o', out_container,
        '-silent'
    ]
    try:
        _run(command, KATANA_TIMEOUT)
        print(f"[KATANA] Complete for {url}. Results: {out_local}")
        return out_local
    except subprocess.TimeoutExpired:
        print(f"[KATANA] Timed out after {KATANA_TIMEOUT}s for {url}. Using partial results if available.")
        return out_local if _is_nonempty(out_local) else None
    except subprocess.CalledProcessError as e:
        if _is_nonempty(out_local):
            print(f"[KATANA] Finished with non-zero exit for {url}. Results: {out_local}")
            return out_local
        print(f"[KATANA] ERROR for {url}: {e.stderr}")
        return None


# ---------------------------------------------------------------------------
# Step 6 — WPScan (conditional — only for WordPress hosts)
# ---------------------------------------------------------------------------

def run_wpscan(url: str):
    print(f"[WPSCAN] Starting WordPress scan on {url}...")
    safe_name = _sanitize_filename(url)
    out_container = f'/output/wpscan_{safe_name}.json'
    out_local = os.path.join(OUTPUT_DIR, f'wpscan_{safe_name}.json')

    command = [
        'docker-compose', 'run', '--rm', 'wpscan',
        '--url', url,
        '--format', 'json',
        '-o', out_container,
        '--no-banner'
    ]
    if WPSCAN_API_TOKEN:
        command += ['--api-token', WPSCAN_API_TOKEN]

    try:
        _run(command, WPSCAN_TIMEOUT)
        print(f"[WPSCAN] Complete for {url}. Results: {out_local}")
        return out_local
    except subprocess.TimeoutExpired:
        print(f"[WPSCAN] Timed out after {WPSCAN_TIMEOUT}s for {url}. Using partial results if available.")
        return out_local if _is_nonempty(out_local) else None
    except subprocess.CalledProcessError as e:
        if _is_nonempty(out_local):
            print(f"[WPSCAN] Finished with non-zero exit for {url}. Results: {out_local}")
            return out_local
        print(f"[WPSCAN] ERROR for {url}: {e.stderr}")
        return None


# ---------------------------------------------------------------------------
# Step 7 — Nuclei
# ---------------------------------------------------------------------------

def run_nuclei(live_urls: list):
    if not live_urls:
        print("[NUCLEI] No targets provided. Skipping.")
        return None

    print(f"[NUCLEI] Starting vulnerability scan on {len(live_urls)} target(s)...")

    with open(NUCLEI_TARGETS_FILE, 'w') as f:
        f.write('\n'.join(live_urls))

    command = [
        'docker-compose', 'run', '--rm', 'nuclei',
        '-l', '/output/nuclei_targets.txt',
        '-as',
        '-jsonl',
        '-o', '/output/nuclei_results.jsonl',
        '-silent'
    ]
    try:
        _run(command, NUCLEI_TIMEOUT)
        print(f"[NUCLEI] Complete. Results: {NUCLEI_OUT}")
        return NUCLEI_OUT
    except subprocess.TimeoutExpired:
        print(f"[NUCLEI] Timed out after {NUCLEI_TIMEOUT}s. Using partial results if available.")
        return NUCLEI_OUT if _is_nonempty(NUCLEI_OUT) else None
    except subprocess.CalledProcessError as e:
        if _is_nonempty(NUCLEI_OUT):
            print(f"[NUCLEI] Finished with non-zero exit. Results: {NUCLEI_OUT}")
            return NUCLEI_OUT
        print(f"[NUCLEI] ERROR: {e.stderr}")
        return None


if __name__ == "__main__":
    TEST_TARGET = "scanme.nmap.org"
    setup_environment()
    run_nmap(TEST_TARGET)
    run_nuclei([f"http://{TEST_TARGET}"])

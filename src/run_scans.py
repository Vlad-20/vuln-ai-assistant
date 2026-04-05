import subprocess
import os
import shutil
import json
import re
import time
import threading
import xml.etree.ElementTree as ET

# Holds the currently running subprocess so it can be killed on demand.
_current_proc: subprocess.Popen = None
_proc_lock = threading.Lock()
_stop_requested = threading.Event()


def request_stop():
    """Signal the pipeline to stop and kill the current subprocess."""
    _stop_requested.set()
    with _proc_lock:
        if _current_proc is not None:
            try:
                _current_proc.kill()
            except Exception:
                pass


def is_stop_requested() -> bool:
    return _stop_requested.is_set()


def reset_stop():
    _stop_requested.clear()


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
KATANA_TIMEOUT    = 300
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


def _stop_service_containers(service_name: str):
    """Kill any Docker containers still running for the given compose service."""
    try:
        result = subprocess.run(
            ['docker', 'ps', '-q', '--filter', f'label=com.docker.compose.service={service_name}'],
            capture_output=True, text=True, encoding='utf-8', timeout=15
        )
        for cid in result.stdout.strip().splitlines():
            if cid:
                subprocess.run(['docker', 'stop', cid], capture_output=True, timeout=15)
                print(f"[{service_name.upper()}] Stopped orphaned container {cid[:12]}.")
    except Exception as e:
        print(f"[{service_name.upper()}] Warning: could not stop orphaned container: {e}")


def _run(command: list, timeout: int, service_name: str = None, stdin_data: str = None):
    """Run a subprocess, raise CalledProcessError or TimeoutExpired on failure.
    On timeout, also stops any orphaned Docker containers for the service.
    Pass stdin_data to pipe text into the process's stdin."""
    global _current_proc
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if stdin_data is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8',
        errors='replace'
    )
    with _proc_lock:
        _current_proc = proc
    try:
        stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, command, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        if service_name:
            _stop_service_containers(service_name)
        raise
    finally:
        with _proc_lock:
            _current_proc = None


# ---------------------------------------------------------------------------
# Step 1 — Subfinder
# ---------------------------------------------------------------------------

def run_subfinder(domain: str):
    print(f"[SUBFINDER] Starting subdomain enumeration on {domain}...")
    command = [
        'docker-compose', 'run', '--rm', 'subfinder',
        '-d', domain,
        '-json', '-all', '-silent',
        '-o', '/output/subfinder_results.jsonl'
    ]
    try:
        _run(command, SUBFINDER_TIMEOUT, 'subfinder')
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

def _collect_hosts(subfinder_jsonl: str, original_domain: str) -> set:
    """Return the set of hosts to probe: root domain + all subfinder results."""
    hosts = {original_domain}
    if subfinder_jsonl and _is_nonempty(subfinder_jsonl):
        try:
            with open(subfinder_jsonl, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        host = json.loads(line).get('host')
                        if host:
                            hosts.add(host)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[HTTPX] Warning: could not read subfinder output: {e}")
    return hosts


def run_httpx(subfinder_file: str, original_domain: str):
    print(f"[HTTPX] Starting HTTP probing and tech fingerprinting...")
    hosts = _collect_hosts(subfinder_file, original_domain)
    print(f"[HTTPX] Probing {len(hosts)} host(s).")

    # Pipe hosts via stdin to avoid Windows/WSL2 volume-read issues with -l flag
    hosts_input = '\n'.join(sorted(hosts)) + '\n'

    command = [
        'docker-compose', 'run', '--rm', '-T',  # -T disables TTY so stdin can be piped
        'httpx',
        '-json', '-sc', '-title', '-td', '-server', '-cdn', '-ip',
        '-o', '/output/httpx_results.jsonl',
        '-silent',
    ]
    try:
        _run(command, HTTPX_TIMEOUT, 'httpx', stdin_data=hosts_input)
        if _is_nonempty(HTTPX_OUT):
            print(f"[HTTPX] Complete. Results: {HTTPX_OUT}")
        else:
            print("[HTTPX] Complete — no live hosts responded.")
        return HTTPX_OUT
    except subprocess.TimeoutExpired:
        print(f"[HTTPX] Timed out after {HTTPX_TIMEOUT}s. Using partial results if available.")
        time.sleep(8)
        return HTTPX_OUT if os.path.exists(HTTPX_OUT) else None
    except subprocess.CalledProcessError as e:
        print(f"[HTTPX] ERROR (exit {e.returncode}): {e.stderr.strip()}")
        return HTTPX_OUT if os.path.exists(HTTPX_OUT) else None


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
        _run(command, NMAP_TIMEOUT, 'nmap')
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
        _run(command, FEROXBUSTER_TIMEOUT, 'feroxbuster')
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
    # Ensure the URL has a scheme — katana requires http:// or https://
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    safe_name = _sanitize_filename(url)
    out_local = os.path.join(OUTPUT_DIR, f'katana_{safe_name}.jsonl')

    # -T disables TTY so pipes work cleanly.
    # -d 2 caps crawl depth so katana finishes before the timeout kills it.
    # No -o flag: we stream stdout to the host file directly so partial results
    # are preserved even when the container is killed at timeout.
    command = [
        'docker', 'run', '--rm', '--network', 'host',
        'projectdiscovery/katana:latest',
        '-u', url,
        '-jsonl',
        '-d', '2',
    ]
    print(f"[KATANA] Command: {' '.join(command)}")

    global _current_proc
    timed_out = False
    stdout_lines = []
    stderr_lines = []

    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8',
        errors='replace',
    )
    with _proc_lock:
        _current_proc = proc

    def _kill_on_timeout():
        nonlocal timed_out
        timed_out = True
        print(f"[KATANA] Timeout ({KATANA_TIMEOUT}s) reached for {url}. Stopping container...")
        proc.kill()
        _stop_service_containers('katana')

    # Drain stderr in a background thread to prevent pipe buffer deadlock.
    # Some katana versions also write JSONL to stderr rather than stdout.
    def _drain_stderr():
        for line in proc.stderr:
            stderr_lines.append(line.rstrip('\n'))

    stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
    stderr_thread.start()

    timer = threading.Timer(KATANA_TIMEOUT, _kill_on_timeout)
    timer.start()
    try:
        for line in proc.stdout:
            stdout_lines.append(line.rstrip('\n'))
        proc.stdout.close()
        proc.wait()
        stderr_thread.join(timeout=5)
        proc.stderr.close()
    finally:
        timer.cancel()
        with _proc_lock:
            _current_proc = None

    print(f"[KATANA] stdout lines: {len(stdout_lines)}, stderr lines: {len(stderr_lines)}")
    for l in stderr_lines[:10]:
        print(f"[KATANA] stderr: {l}")

    # Some katana builds write JSONL to stderr instead of stdout when piped.
    # Use whichever stream has content; prefer stdout.
    result_lines = stdout_lines if stdout_lines else stderr_lines

    with open(out_local, 'w', encoding='utf-8') as f:
        for line in result_lines:
            f.write(line + '\n')

    if timed_out:
        print(f"[KATANA] Timed out after {KATANA_TIMEOUT}s for {url}. Partial results: {len(result_lines)} lines.")
    else:
        print(f"[KATANA] Complete for {url}. Exit code: {proc.returncode}. Results: {len(result_lines)} lines.")

    return out_local if _is_nonempty(out_local) else None


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
        '--random-user-agent'
    ]
    if WPSCAN_API_TOKEN:
        command += ['--api-token', WPSCAN_API_TOKEN]

    try:
        _run(command, WPSCAN_TIMEOUT, 'wpscan')
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

    # Pipe targets via stdin to avoid Windows/WSL2 volume-read issues with -l flag
    targets_input = '\n'.join(live_urls) + '\n'

    command = [
        'docker-compose', 'run', '--rm', '-T',  # -T disables TTY so stdin can be piped
        'nuclei',
        '-as',
        '-jsonl',
        '-o', '/output/nuclei_results.jsonl',
        '-silent'
    ]
    try:
        _run(command, NUCLEI_TIMEOUT, 'nuclei', stdin_data=targets_input)
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

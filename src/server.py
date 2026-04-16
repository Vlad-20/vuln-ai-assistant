import os
import sys
import json
import queue
import threading
from dataclasses import asdict

from flask import Flask, Response, request, jsonify, send_file, send_from_directory
from flask import stream_with_context

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_scans
import parsers
from target_utils import normalize_target, is_public_domain

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
os.makedirs(STATIC_DIR, exist_ok=True)

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='/static')

# Single-user global state

_event_queue: queue.Queue = queue.Queue()
_scan_running = threading.Event()
_state: dict = {'output_file': None}

# Routes

@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')


@app.route('/scan', methods=['POST'])
def start_scan():
    if _scan_running.is_set():
        return jsonify({'error': 'A scan is already running.'}), 409

    data = request.get_json(force=True, silent=True) or {}
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'Target domain is required.'}), 400

    # Drain stale events from a previous run
    while not _event_queue.empty():
        try:
            _event_queue.get_nowait()
        except queue.Empty:
            break

    run_scans.reset_stop()
    _state['output_file'] = None
    _scan_running.set()
    threading.Thread(target=_run_pipeline, args=(target,), daemon=True).start()
    return jsonify({'status': 'started'})


@app.route('/stop', methods=['POST'])
def stop_scan():
    if not _scan_running.is_set():
        return jsonify({'error': 'No scan is running.'}), 409
    run_scans.request_stop()
    return jsonify({'status': 'stopping'})


@app.route('/events')
def events():
    @stream_with_context
    def generate():
        while True:
            try:
                event = _event_queue.get(timeout=0.4)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get('type') in ('scan_complete', 'scan_error'):
                    return
            except queue.Empty:
                if not _scan_running.is_set():
                    return
                yield ': ping\n\n'   # SSE keepalive comment

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive',
    })


@app.route('/download')
def download():
    path = _state.get('output_file')
    if path and os.path.exists(path):
        return send_file(path, as_attachment=True,
                         download_name='scan_results.json',
                         mimetype='application/json')
    return jsonify({'error': 'No results available yet.'}), 404

# Pipeline helpers

def _emit(event: dict):
    _event_queue.put(event)

def _step_start(step_id: str, label: str):
    _emit({'type': 'step_start', 'step_id': step_id, 'label': label})

def _step_end(step_id: str, status: str, message: str = ''):
    _emit({'type': 'step_end', 'step_id': step_id, 'status': status, 'message': message})

def _log(msg: str):
    _emit({'type': 'log', 'message': msg})

# Scan pipeline (background thread)

def _is_stopped() -> bool:
    return run_scans.is_stop_requested()


def _run_pipeline(target: str):
    # Track all collected file paths so the normalize step can always run
    collected: dict = {
        'subfinder_file': None,
        'httpx_file': None,
        'nmap_file': None,
        'feroxbuster_files': [],
        'katana_files': [],
        'wpscan_files': [],
        'nuclei_file': None,
    }
    stopped = False

    try:
        run_scans.setup_environment()

        hostname, target_url = normalize_target(target)
        _log(f"Normalized target: hostname='{hostname}'")

        # 1. Subfinder - skip for non-public domains (IPs, internal hostnames)
        _step_start('subfinder', 'Subdomain Enumeration')
        if is_public_domain(hostname):
            collected['subfinder_file'] = run_scans.run_subfinder(hostname)
            _step_end('subfinder', 'success' if collected['subfinder_file'] else 'error')
        else:
            _log(f"Skipping subfinder — '{hostname}' is not a public domain.")
            _step_end('subfinder', 'skipped', 'Internal/IP target')
        if _is_stopped(): stopped = True; return

        # 2. httpx
        # For public domains, pass the hostname so httpx discovers both http and https.
        # For non-public targets (IPs, internal Docker hostnames), pass the full URL
        # so httpx gets an explicit scheme.
        httpx_seed = hostname if is_public_domain(hostname) else target_url
        _step_start('httpx', 'HTTP Probing & Tech Detection')
        collected['httpx_file'] = run_scans.run_httpx(collected['subfinder_file'], httpx_seed)
        _step_end('httpx', 'success' if collected['httpx_file'] else 'error')
        if _is_stopped(): stopped = True; return

        live_urls, wordpress_urls = [], []
        if collected['httpx_file']:
            live_urls, wordpress_urls = parsers.extract_live_hosts(collected['httpx_file'])
            _log(f"Found {len(live_urls)} live host(s), {len(wordpress_urls)} WordPress host(s).")
        else:
            _log("httpx produced no output - downstream steps will be skipped.")

        # 3. Nmap - needs a bare hostname, NOT a URL
        _step_start('nmap', 'Port & Service Discovery')
        collected['nmap_file'] = run_scans.run_nmap(hostname)
        _step_end('nmap', 'success' if collected['nmap_file'] else 'error')
        if _is_stopped(): stopped = True; return

        # 4. Feroxbuster
        _step_start('feroxbuster',
                    f'Directory Discovery ({len(live_urls)} host(s))' if live_urls else 'Directory Discovery')
        if live_urls:
            for url in live_urls:
                if _is_stopped(): stopped = True; return
                _log(f'Feroxbuster → {url}')
                f = run_scans.run_feroxbuster(url)
                if f:
                    collected['feroxbuster_files'].append(f)
            _step_end('feroxbuster', 'success' if collected['feroxbuster_files'] else 'error',
                      f"{len(collected['feroxbuster_files'])}/{len(live_urls)} host(s) scanned")
        else:
            _step_end('feroxbuster', 'skipped', 'No live hosts from httpx')
        if _is_stopped(): stopped = True; return

        # 5. Katana
        _step_start('katana',
                    f'URL Crawling ({len(live_urls)} host(s))' if live_urls else 'URL Crawling')
        if live_urls:
            for url in live_urls:
                if _is_stopped(): stopped = True; return
                _log(f'Katana → {url}')
                k = run_scans.run_katana(url)
                if k:
                    collected['katana_files'].append(k)
            _step_end('katana', 'success' if collected['katana_files'] else 'error',
                      f"{len(collected['katana_files'])}/{len(live_urls)} host(s) crawled")
        else:
            _step_end('katana', 'skipped', 'No live hosts from httpx')
        if _is_stopped(): stopped = True; return

        # 6. WPScan
        _step_start('wpscan',
                    f'WordPress Scanning ({len(wordpress_urls)} host(s))' if wordpress_urls else 'WordPress Scanning')
        if wordpress_urls:
            for url in wordpress_urls:
                if _is_stopped(): stopped = True; return
                _log(f'WPScan → {url}')
                w = run_scans.run_wpscan(url)
                if w:
                    collected['wpscan_files'].append(w)
            _step_end('wpscan', 'success' if collected['wpscan_files'] else 'error')
        else:
            _step_end('wpscan', 'skipped', 'No WordPress hosts detected')
        if _is_stopped(): stopped = True; return

        # 7. Nuclei
        _step_start('nuclei', 'Vulnerability Scanning')
        if live_urls:
            collected['nuclei_file'] = run_scans.run_nuclei(live_urls)
            _step_end('nuclei', 'success' if collected['nuclei_file'] else 'error')
        else:
            _step_end('nuclei', 'skipped', 'No live hosts to scan')

    except Exception as e:
        _log(f'Pipeline error: {e}')
        stopped = True

    finally:
        # Always normalize and write whatever was collected, even if stopped early
        _normalize_and_finish(collected, stopped)
        _scan_running.clear()


def _normalize_and_finish(collected: dict, stopped: bool):
    _step_start('normalize', 'Normalizing Findings')
    all_findings = []
    try:
        if collected['subfinder_file']:
            all_findings.extend(parsers.parse_subfinder_jsonl(collected['subfinder_file']))
        if collected['httpx_file']:
            all_findings.extend(parsers.parse_httpx_jsonl(collected['httpx_file']))
        if collected['nmap_file']:
            all_findings.extend(parsers.parse_nmap_json(collected['nmap_file']))
        for f in collected['feroxbuster_files']:
            all_findings.extend(parsers.parse_feroxbuster_json(f))
        for f in collected['katana_files']:
            all_findings.extend(parsers.parse_katana_jsonl(f))
        for f in collected['wpscan_files']:
            all_findings.extend(parsers.parse_wpscan_json(f))
        if collected['nuclei_file']:
            all_findings.extend(parsers.parse_nuclei_jsonl(collected['nuclei_file']))

        if all_findings:
            out_path = os.path.join(run_scans.OUTPUT_DIR, 'normalized_findings.json')
            with open(out_path, 'w', encoding='utf-8') as fh:
                json.dump([asdict(x) for x in all_findings], fh, indent=4)
            _state['output_file'] = out_path

        partial_note = ' (partial — scan stopped early)' if stopped else ''
        _step_end('normalize', 'success', f"{len(all_findings)} total findings{partial_note}")

        if stopped:
            _emit({'type': 'scan_error',
                   'message': f'Scan stopped early. {len(all_findings)} findings saved.',
                   'findings': len(all_findings)})
        else:
            _emit({'type': 'scan_complete', 'total_findings': len(all_findings)})

    except Exception as e:
        _step_end('normalize', 'error', str(e))
        _emit({'type': 'scan_error', 'message': f'Normalize failed: {e}'})


if __name__ == '__main__':
    print("VulnAI Scanner UI  →  http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)

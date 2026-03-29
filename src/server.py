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

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
os.makedirs(STATIC_DIR, exist_ok=True)

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='/static')

# ---------------------------------------------------------------------------
# Single-user global state
# ---------------------------------------------------------------------------
_event_queue: queue.Queue = queue.Queue()
_scan_running = threading.Event()
_state: dict = {'output_file': None}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

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

    _state['output_file'] = None
    _scan_running.set()
    threading.Thread(target=_run_pipeline, args=(target,), daemon=True).start()
    return jsonify({'status': 'started'})


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


# ---------------------------------------------------------------------------
# Pipeline helpers
# ---------------------------------------------------------------------------

def _emit(event: dict):
    _event_queue.put(event)

def _step_start(step_id: str, label: str):
    _emit({'type': 'step_start', 'step_id': step_id, 'label': label})

def _step_end(step_id: str, status: str, message: str = ''):
    _emit({'type': 'step_end', 'step_id': step_id, 'status': status, 'message': message})

def _log(msg: str):
    _emit({'type': 'log', 'message': msg})


# ---------------------------------------------------------------------------
# Scan pipeline (background thread)
# ---------------------------------------------------------------------------

def _run_pipeline(target: str):
    try:
        run_scans.setup_environment()

        # 1 — Subfinder
        _step_start('subfinder', 'Subdomain Enumeration')
        subfinder_file = run_scans.run_subfinder(target)
        _step_end('subfinder', 'success' if subfinder_file else 'error')

        # 2 — httpx
        _step_start('httpx', 'HTTP Probing & Tech Detection')
        httpx_file = run_scans.run_httpx(subfinder_file, target)
        _step_end('httpx', 'success' if httpx_file else 'error')

        live_urls, wordpress_urls = [], []
        if httpx_file:
            live_urls, wordpress_urls = parsers.extract_live_hosts(httpx_file)
            _log(f"Found {len(live_urls)} live host(s), {len(wordpress_urls)} WordPress host(s).")
        else:
            _log("httpx produced no output — downstream steps will be skipped.")

        # 3 — Nmap
        _step_start('nmap', 'Port & Service Discovery')
        nmap_file = run_scans.run_nmap(target)
        _step_end('nmap', 'success' if nmap_file else 'error')

        # 4 — Feroxbuster
        feroxbuster_files = []
        _step_start('feroxbuster',
                    f'Directory Discovery ({len(live_urls)} host(s))' if live_urls else 'Directory Discovery')
        if live_urls:
            for url in live_urls:
                _log(f'Feroxbuster → {url}')
                f = run_scans.run_feroxbuster(url)
                if f:
                    feroxbuster_files.append(f)
            _step_end('feroxbuster', 'success' if feroxbuster_files else 'error',
                      f"{len(feroxbuster_files)}/{len(live_urls)} host(s) scanned")
        else:
            _step_end('feroxbuster', 'skipped', 'No live hosts from httpx')

        # 5 — Katana
        katana_files = []
        _step_start('katana',
                    f'URL Crawling ({len(live_urls)} host(s))' if live_urls else 'URL Crawling')
        if live_urls:
            for url in live_urls:
                _log(f'Katana → {url}')
                k = run_scans.run_katana(url)
                if k:
                    katana_files.append(k)
            _step_end('katana', 'success' if katana_files else 'error',
                      f"{len(katana_files)}/{len(live_urls)} host(s) crawled")
        else:
            _step_end('katana', 'skipped', 'No live hosts from httpx')

        # 6 — WPScan
        wpscan_files = []
        _step_start('wpscan',
                    f'WordPress Scanning ({len(wordpress_urls)} host(s))' if wordpress_urls else 'WordPress Scanning')
        if wordpress_urls:
            for url in wordpress_urls:
                _log(f'WPScan → {url}')
                w = run_scans.run_wpscan(url)
                if w:
                    wpscan_files.append(w)
            _step_end('wpscan', 'success' if wpscan_files else 'error')
        else:
            _step_end('wpscan', 'skipped', 'No WordPress hosts detected')

        # 7 — Nuclei
        nuclei_file = None
        _step_start('nuclei', 'Vulnerability Scanning')
        if live_urls:
            nuclei_file = run_scans.run_nuclei(live_urls)
            _step_end('nuclei', 'success' if nuclei_file else 'error')
        else:
            _step_end('nuclei', 'skipped', 'No live hosts to scan')

        # 8 — Normalize
        _step_start('normalize', 'Normalizing Findings')
        all_findings = []
        if subfinder_file:
            all_findings.extend(parsers.parse_subfinder_jsonl(subfinder_file))
        if httpx_file:
            all_findings.extend(parsers.parse_httpx_jsonl(httpx_file))
        if nmap_file:
            all_findings.extend(parsers.parse_nmap_json(nmap_file))
        for f in feroxbuster_files:
            all_findings.extend(parsers.parse_feroxbuster_json(f))
        for f in katana_files:
            all_findings.extend(parsers.parse_katana_jsonl(f))
        for f in wpscan_files:
            all_findings.extend(parsers.parse_wpscan_json(f))
        if nuclei_file:
            all_findings.extend(parsers.parse_nuclei_jsonl(nuclei_file))

        out_path = os.path.join(run_scans.OUTPUT_DIR, 'normalized_findings.json')
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump([asdict(x) for x in all_findings], fh, indent=4)
        _state['output_file'] = out_path

        _step_end('normalize', 'success', f"{len(all_findings)} total findings")
        _emit({'type': 'scan_complete', 'total_findings': len(all_findings)})

    except Exception as e:
        _emit({'type': 'scan_error', 'message': str(e)})

    finally:
        _scan_running.clear()


if __name__ == '__main__':
    print("VulnAI Scanner UI  →  http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)

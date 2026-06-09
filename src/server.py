import json
import os
import queue
import sys
import threading
from dataclasses import asdict
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file, send_from_directory
from flask import stream_with_context

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enrichment
import parsers
import prioritizer
import run_scans
from target_utils import is_public_domain, normalize_target

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
os.makedirs(STATIC_DIR, exist_ok=True)

OUTPUT_DIR = Path(run_scans.OUTPUT_DIR)

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='/static')

# Single-user global state
_event_queue: queue.Queue = queue.Queue()
_scan_running = threading.Event()
_state: dict = {
    'normalized':  None,
    'enriched':    None,
    'annotated':   None,
    'prioritized': None,
}

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

    run_scans.reset_stop()
    for key in _state:
        _state[key] = None
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
                yield ': ping\n\n'

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive',
    })


@app.route('/download')
def download():
    """
    Serve one of the four output files.
    Query param: file=normalized|enriched|annotated|prioritized  (default: prioritized)
    """
    FILE_MAP = {
        'normalized':  ('normalized_findings.jsonl',           'application/x-ndjson'),
        'enriched':    ('enriched_findings.jsonl',             'application/x-ndjson'),
        'annotated':   ('enriched_findings.annotated.jsonl',   'application/x-ndjson'),
        'prioritized': ('enriched_findings.prioritized.json',  'application/json'),
    }
    file_key = request.args.get('file', 'prioritized')
    if file_key not in FILE_MAP:
        return jsonify({'error': f'Unknown file key "{file_key}". '
                                 f'Valid values: {list(FILE_MAP)}'}), 400

    filename, mimetype = FILE_MAP[file_key]
    path = OUTPUT_DIR / filename
    if path.exists() and path.stat().st_size > 0:
        return send_file(str(path), as_attachment=True,
                         download_name=filename, mimetype=mimetype)
    return jsonify({'error': f'{filename} not available yet.'}), 404


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


def _is_stopped() -> bool:
    return run_scans.is_stop_requested()


# ---------------------------------------------------------------------------
# Scan pipeline (background thread)
# ---------------------------------------------------------------------------

def _run_pipeline(target: str):
    collected: dict = {
        'subfinder_file':            None,
        'httpx_file':                None,
        'nmap_file':                 None,
        'feroxbuster_files':         [],
        'katana_files':              [],
        'wpscan_files':              [],
        'nuclei_file':               None,
        'app_version_probe_findings': [],
    }
    stopped = False

    try:
        run_scans.setup_environment()

        hostname, target_url = normalize_target(target)
        _log(f"Normalized target: hostname='{hostname}'")

        # 1. Subfinder
        _step_start('subfinder', 'Subdomain Enumeration')
        if is_public_domain(hostname):
            collected['subfinder_file'] = run_scans.run_subfinder(hostname)
            _step_end('subfinder', 'success' if collected['subfinder_file'] else 'error')
        else:
            _log(f"Skipping subfinder — '{hostname}' is not a public domain.")
            _step_end('subfinder', 'skipped', 'Internal/IP target')
        if _is_stopped(): stopped = True; return

        # 2. httpx
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

        # 2.5 App-version probe
        _step_start('app_version_probe', 'App Version Detection')
        if live_urls:
            probe_results = enrichment.probe_app_versions(live_urls)
            collected['app_version_probe_findings'] = probe_results
            _step_end('app_version_probe', 'success',
                      f'{len(probe_results)} version(s) detected')
        else:
            _step_end('app_version_probe', 'skipped', 'No live hosts from httpx')
        if _is_stopped(): stopped = True; return

        # 3. Nmap
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
        _normalize_and_finish(collected, stopped)
        _scan_running.clear()


# ---------------------------------------------------------------------------
# Normalize → Enrich → Prioritize
# ---------------------------------------------------------------------------

def _normalize_and_finish(collected: dict, stopped: bool):
    # ------------------------------------------------------------------
    # Step: normalize
    # ------------------------------------------------------------------
    _step_start('normalize', 'Normalizing Findings')
    all_findings_objs = []
    try:
        if collected['subfinder_file']:
            all_findings_objs.extend(parsers.parse_subfinder_jsonl(collected['subfinder_file']))
        if collected['httpx_file']:
            all_findings_objs.extend(parsers.parse_httpx_jsonl(collected['httpx_file']))
        if collected['nmap_file']:
            all_findings_objs.extend(parsers.parse_nmap_json(collected['nmap_file']))
        for f in collected['feroxbuster_files']:
            all_findings_objs.extend(parsers.parse_feroxbuster_json(f))
        for f in collected['katana_files']:
            all_findings_objs.extend(parsers.parse_katana_jsonl(f))
        for f in collected['wpscan_files']:
            all_findings_objs.extend(parsers.parse_wpscan_json(f))
        if collected['nuclei_file']:
            all_findings_objs.extend(parsers.parse_nuclei_jsonl(collected['nuclei_file']))
        all_findings_objs.extend(collected['app_version_probe_findings'])

        normalized_path = OUTPUT_DIR / 'normalized_findings.jsonl'
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(normalized_path, 'w', encoding='utf-8') as fh:
            for finding in all_findings_objs:
                fh.write(json.dumps(asdict(finding), ensure_ascii=False) + '\n')
        _state['normalized'] = str(normalized_path)

        partial_note = ' (partial — scan stopped early)' if stopped else ''
        _step_end('normalize', 'success', f"{len(all_findings_objs)} total findings{partial_note}")

    except Exception as e:
        _step_end('normalize', 'error', str(e))
        _emit({'type': 'scan_error', 'message': f'Normalize failed: {e}'})
        return

    # ------------------------------------------------------------------
    # Step: enrichment
    # ------------------------------------------------------------------
    enriched_path   = OUTPUT_DIR / 'enriched_findings.jsonl'
    prioritizer_input = normalized_path

    _step_start('enrichment', 'CVE / EPSS Enrichment')
    try:
        cve_count = enrichment.enrich_to_jsonl(normalized_path, enriched_path)
        _state['enriched'] = str(enriched_path)
        _step_end('enrichment', 'success', f'{cve_count} CVE record(s) added')
        _emit({'type': 'enrichment_complete', 'cve_count': cve_count})
        prioritizer_input = enriched_path
    except Exception as e:
        _log(f'Enrichment failed: {e} — falling back to normalized findings')
        _step_end('enrichment', 'error', str(e))

    # ------------------------------------------------------------------
    # Step: prioritization
    # ------------------------------------------------------------------
    _step_start('prioritization', 'Prioritization & Scoring')
    try:
        annotated_path, prioritized_path = prioritizer.prioritize(prioritizer_input)
        _state['annotated']   = str(annotated_path)
        _state['prioritized'] = str(prioritized_path)

        with open(prioritized_path, 'r', encoding='utf-8') as fh:
            pdata = json.load(fh)
        meta           = pdata.get('metadata', {})
        priority_counts = meta.get('priority_counts', {})
        total_enriched = meta.get('total_findings_raw', 0)
        total_deduped  = meta.get('total_findings_deduplicated', 0)
        anchor_count   = len(pdata.get('anchors', []))

        pc = priority_counts
        _step_end('prioritization', 'success',
                  f"C:{pc.get('critical',0)} H:{pc.get('high',0)} "
                  f"M:{pc.get('medium',0)} L:{pc.get('low',0)} I:{pc.get('info',0)}")

        if stopped:
            _emit({
                'type':    'scan_error',
                'message': f'Scan stopped early. {len(all_findings_objs)} findings saved.',
                'findings': len(all_findings_objs),
                'priority_counts':    priority_counts,
                'total_enriched':     total_enriched,
                'total_deduplicated': total_deduped,
                'anchor_count':       anchor_count,
            })
        else:
            _emit({
                'type':               'scan_complete',
                'total_findings':     len(all_findings_objs),
                'priority_counts':    priority_counts,
                'total_enriched':     total_enriched,
                'total_deduplicated': total_deduped,
                'anchor_count':       anchor_count,
            })

    except Exception as e:
        _step_end('prioritization', 'error', str(e))
        _log(f'Prioritization failed: {e}')
        if stopped:
            _emit({
                'type':    'scan_error',
                'message': f'Scan stopped early. {len(all_findings_objs)} findings saved.',
                'findings': len(all_findings_objs),
            })
        else:
            _emit({'type': 'scan_complete', 'total_findings': len(all_findings_objs)})


if __name__ == '__main__':
    print("Vuln Scanner UI  ->  http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)

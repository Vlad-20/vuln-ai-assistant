import json
import sys
from dataclasses import asdict
from pathlib import Path

import run_scans
import parsers
import enrichment
import prioritizer
from target_utils import normalize_target, is_public_domain


TEST_TARGET = "vladvlaicu.com"
OUTPUT_DIR   = Path(run_scans.OUTPUT_DIR)
NORMALIZED   = OUTPUT_DIR / 'normalized_findings.jsonl'
ENRICHED     = OUTPUT_DIR / 'enriched_findings.jsonl'


def main():
    print("*** Starting FULL Scan and Parse pipeline ***")
    run_scans.setup_environment()

    hostname, url = normalize_target(TEST_TARGET)
    print(f"[PIPELINE] Normalized target: hostname='{hostname}', url='{url}'")

    # 1. Subdomain Enumeration (subfinder)
    if is_public_domain(hostname):
        subfinder_file = run_scans.run_subfinder(hostname)
    else:
        print(f"[PIPELINE] Skipping subfinder - '{hostname}' is not a public domain.")
        subfinder_file = None

    # 2. HTTP Probing & Web Tech Fingerprinting (httpx)
    httpx_seed = hostname if is_public_domain(hostname) else url
    httpx_file = run_scans.run_httpx(subfinder_file, httpx_seed)

    live_urls: list = []
    wordpress_urls: list = []
    print(f"[DEBUG] httpx_file = {httpx_file!r}")
    if httpx_file:
        live_urls, wordpress_urls = parsers.extract_live_hosts(httpx_file)
        print(f"[PIPELINE] {len(live_urls)} live host(s) found, "
              f"{len(wordpress_urls)} WordPress host(s) detected.")
    else:
        print("[DEBUG] httpx_file is None - httpx produced no usable output.")

    # 2.5 App-version probe
    app_version_findings = []
    if live_urls:
        print("[PIPELINE] Running app-version probes …")
        app_version_findings = enrichment.probe_app_versions(live_urls)
        print(f"[PIPELINE] {len(app_version_findings)} version(s) detected.")

    # 3. Port & Service Discovery (nmap)
    nmap_file = run_scans.run_nmap(hostname)

    # 4. Directory Discovery (feroxbuster), per live host
    feroxbuster_files = []
    for u in live_urls:
        result = run_scans.run_feroxbuster(u)
        if result:
            feroxbuster_files.append(result)

    # 5. URL Collection & Crawling (katana), per live host
    katana_files = []
    for u in live_urls:
        result = run_scans.run_katana(u)
        if result:
            katana_files.append(result)

    # 6. CMS-Specific Scanning (WPScan), WordPress hosts only
    wpscan_files = []
    if wordpress_urls:
        print(f"[PIPELINE] WordPress detected - running WPScan on {len(wordpress_urls)} host(s).")
        for u in wordpress_urls:
            result = run_scans.run_wpscan(u)
            if result:
                wpscan_files.append(result)
    else:
        print("[PIPELINE] No WordPress hosts detected - skipping WPScan.")

    # 7. Vulnerability Scanning (nuclei), all live hosts
    nuclei_file = run_scans.run_nuclei(live_urls)

    # Normalize all findings into normalized_findings.jsonl
    print("\n*** Normalizing findings ***")
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
    all_findings.extend(app_version_findings)

    print(f"\n*** Total normalized findings: {len(all_findings)} ***")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(NORMALIZED, 'w', encoding='utf-8') as fh:
            for finding in all_findings:
                fh.write(json.dumps(asdict(finding), ensure_ascii=False) + '\n')
        print(f"Saved {len(all_findings)} findings → {NORMALIZED}")
    except Exception as e:
        print(f"ERROR saving normalized findings: {e}")
        sys.exit(1)

    # Enrichment into enriched_findings.jsonl
    print("\n*** Running CVE / EPSS / KEV enrichment ***")
    prioritizer_input = NORMALIZED
    try:
        cve_count = enrichment.enrich_to_jsonl(NORMALIZED, ENRICHED)
        print(f"[ENRICHMENT] Added {cve_count} CVE record(s) → {ENRICHED}")
        prioritizer_input = ENRICHED
    except Exception as e:
        print(f"[ENRICHMENT] Failed: {e} — prioritizer will run on normalized findings")

    # Prioritization into annotated JSONL and prioritized JSON
    print("\n*** Running prioritization ***")
    try:
        annotated, prioritized = prioritizer.prioritize(prioritizer_input)
        print(f"[PRIORITIZER] Annotated  : {annotated}")
        print(f"[PRIORITIZER] Prioritized: {prioritized}")

        # Quick summary
        with open(prioritized, 'r', encoding='utf-8') as fh:
            meta = json.load(fh).get('metadata', {})
        pc = meta.get('priority_counts', {})
        print(f"\n*** Priority summary ***")
        for lvl in ('critical', 'high', 'medium', 'low', 'info'):
            n = pc.get(lvl, 0)
            if n:
                print(f"  {lvl.upper():8s}: {n}")
    except Exception as e:
        print(f"[PRIORITIZER] Failed: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[PIPELINE] Interrupted by user. Exiting.")

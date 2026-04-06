import run_scans
import parsers
import json
from dataclasses import asdict
import os

TEST_TARGET = "vladvlaicu.com"
OUTPUT_FILE = os.path.join(run_scans.OUTPUT_DIR, 'normalized_findings.jsonl')


def main():
    print("*** Starting FULL Scan and Parse pipeline ***")
    run_scans.setup_environment()

    # 1. Subdomain Enumeration (subfinder)

    subfinder_file = run_scans.run_subfinder(TEST_TARGET)

    # 2. HTTP Probing & Web Tech Fingerprinting (httpx)

    httpx_file = run_scans.run_httpx(subfinder_file, TEST_TARGET)

    # Derive live hosts and WordPress targets for downstream steps
    live_urls: list = []
    wordpress_urls: list = []
    print(f"[DEBUG] httpx_file = {httpx_file!r}")
    if httpx_file:
        live_urls, wordpress_urls = parsers.extract_live_hosts(httpx_file)
        print(f"[PIPELINE] {len(live_urls)} live host(s) found, "
              f"{len(wordpress_urls)} WordPress host(s) detected.")
        print(f"[DEBUG] live_urls = {live_urls}")
    else:
        print("[DEBUG] httpx_file is None - httpx produced no usable output.")

    # 3.  Port & Service Discovery (nmap) -> against root domain

    nmap_file = run_scans.run_nmap(TEST_TARGET)

    # 4. Directory Discovery (feroxbuster) - per live host

    feroxbuster_files = []
    for url in live_urls:
        result = run_scans.run_feroxbuster(url)
        if result:
            feroxbuster_files.append(result)

    # 5. URL Collection & Crawling (katana) - per live host

    katana_files = []
    for url in live_urls:
        result = run_scans.run_katana(url)
        if result:
            katana_files.append(result)

    # 6. CMS-Specific Scanning (WPScan) - WordPress hosts only

    wpscan_files = []
    if wordpress_urls:
        print(f"[PIPELINE] WordPress detected - running WPScan on {len(wordpress_urls)} host(s).")
        for url in wordpress_urls:
            result = run_scans.run_wpscan(url)
            if result:
                wpscan_files.append(result)
    else:
        print("[PIPELINE] No WordPress hosts detected - skipping WPScan.")

    # 7. Vulnerability Scanning (nuclei) - all live hosts

    nuclei_file = run_scans.run_nuclei(live_urls)

    # Normalize all findings

    print("\n*** Starting normalization ***")
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

    print(f"\n*** Total normalized findings: {len(all_findings)} ***")

    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for finding in all_findings:
                f.write(json.dumps(asdict(finding)) + '\n')
        print(f"\nSuccessfully saved {len(all_findings)} entries to: {OUTPUT_FILE}")
    except Exception as e:
        print(f"\nERROR saving findings to JSONL: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[PIPELINE] Interrupted by user. Exiting.")

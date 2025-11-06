import run_scans
import parsers
import json
from dataclasses import asdict
from pprint import pprint
import os

TEST_TARGET = "scanme.nmap.org"
OUTPUT_FILE = os.path.join(run_scans.OUTPUT_DIR, 'normalized_findings.json')

def main():
    print("*** Starting FULL Scan and Parse pipeline ***")

    # run scans
    run_scans.setup_environment()
    nmap_file = run_scans.run_nmap(TEST_TARGET)
    nuclei_file = run_scans.run_nuclei(TEST_TARGET)

    print("\n*** Starting normalization ***")
    all_findings = []

    # normalize nmap & nuclei
    if nmap_file:
        nmap_findings = parsers.parse_nmap_xml(nmap_file)
        all_findings.extend(nmap_findings)

    if nuclei_file:
        nuclei_findings = parsers.parse_nuclei_jsonl(nuclei_file)
        all_findings.extend(nuclei_findings)

    print(f"\n*** Total normalized findings: {len(all_findings)} ***")

    # use asdict(f) to make the custom dataclass serializable
    findings_as_dict = [asdict(f) for f in all_findings]

    # save the list to a JSON file
    try:
        with open(OUTPUT_FILE, 'w') as f:
            # use indent=4 for nice, human-readable formatting
            json.dump(findings_as_dict, f, indent=4)
        print(f"\nSuccessfully saved all findings to: {OUTPUT_FILE}")
    except Exception as e:
        print(f"\nERROR saving findings to JSON: {e}")

if __name__ == "__main__":
    main()
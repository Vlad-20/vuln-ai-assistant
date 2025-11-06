import subprocess
import os
import shutil

# Define output directory
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'output')
NMAP_OUT = os.path.join(OUTPUT_DIR, 'nmap_results.xml')
NUCLEI_OUT = os.path.join(OUTPUT_DIR, 'nuclei_results.jsonl')

def setup_environment():
    # Ensure the output directory is clean before a run
    print("Setting up environment...")
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    print(f"Created new output directory: {OUTPUT_DIR}")

def run_nmap(target: str):
    # Run Nmap via docker-compose
    # -sV: Service version detection
    # -Pn: pingless scan
    # -oX: Output to XML format
    print(f"[NMAP] Starting scan on {target}...")
    # Save the report to /output/nmap_results.xml inside the container
    command = [
        'docker-compose', 'run', '--rm',
        'nmap',
        '-sV',
        '--top-ports', '100',
        '-n',
        '-Pn',
        '-oX', '/output/nmap_results.xml',
        target
    ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[NMAP] Scan complete. Results saved to {NMAP_OUT}")
        return NMAP_OUT
    except subprocess.CalledProcessError as e:
        print(f"[NMAP] ERROR running Nmap:")
        print(e.stderr)
        return None
    
def run_nuclei(target: str):
    # Run Nuclei via docker-compose
    # -jsonl: output to JSON-Lines format
    # -o: output to file
    # -as: automatic scan to select relevant templates
    print(f"[NUCLEI] Starting scan on {target}...")
    # Nuclei needs the full URL, including protocol
    if not target.startswith(('http://', 'https://')):
        # Default to http if no protocol is specified
        target = f"http://{target}"

    # Save the report to /output/nuclei_results.jsonl inside the container
    command = [
        'docker-compose', 'run', '--rm',
        'nuclei',
        '-u', target,
        '-as',
        '-jsonl',
        '-o', '/output/nuclei_results.jsonl',
        '-silent' # hide progress bar for cleaner subprocess output
    ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[NUCLEI] Scan complete. Results saved to {NUCLEI_OUT}")
        return NUCLEI_OUT
    except subprocess.CalledProcessError as e:
        if os.path.exists(NUCLEI_OUT):
            print(f"[NUCLEI] Scan finished (with non-zero exit). Results saved to {NUCLEI_OUT}")
            return NUCLEI_OUT
        print(f"[NUCLEI] ERROR running Nuclei:")
        print(e.stderr)
        return None
    
if __name__ == "__main__":
    # scanme.nmap.org is provided by Nmap for testing
    TEST_TARGET = "scanme.nmap.org"

    setup_environment()
    run_nmap(TEST_TARGET)
    run_nuclei(TEST_TARGET)
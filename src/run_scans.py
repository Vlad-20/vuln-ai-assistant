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
        target,
        '-sV',
        '-Pn',
        '-oX', '/output/nmap_results.xml'
    ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[NMAP] Scan complete. Results saved to {NMAP_OUT}")
        return NMAP_OUT
    except subprocess.CalledProcessError as e:
        print(f"[NMAP] ERROR running Nmap:")
        print(e.stderr)
        return None
import xml.etree.ElementTree as ET
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class NormalizedFinding:
    # standardized, unified format for any vuln
    host: str
    port: Optional[int]
    protocol: Optional[str]
    finding_name: str
    severity: str
    source_tool: str
    description: str
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

def parse_subfinder_jsonl(jsonl_file: str) -> List[NormalizedFinding]:
    # parses a Subfinder JSON-Lines output file into a list of NormalizedFinding
    # each line: {"host": "sub.example.com", "source": [...], "input": "example.com"}
    print(f"Parsing Subfinder file: {jsonl_file}...")
    findings = []
    try:
        with open(jsonl_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = data.get('host', 'unknown')
                    source = data.get('source', '')
                    sources_str = ', '.join(source) if isinstance(source, list) else source
                    input_domain = data.get('input', 'unknown')

                    finding = NormalizedFinding(
                        host=host,
                        port=None,
                        protocol=None,
                        finding_name=f"Subdomain Discovered: {host}",
                        severity="info",
                        source_tool="subfinder",
                        description=f"Subdomain '{host}' discovered for '{input_domain}' via sources: {sources_str}",
                        raw_evidence=data
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        print(f"Found {len(findings)} Subfinder findings.")
        return findings
    except FileNotFoundError:
        print(f"Subfinder output file not found: {jsonl_file}")
        return []

def parse_nmap_xml(xml_file: str) -> List[NormalizedFinding]:
    # parses an Nmap XML output file into a list of NormalizedFinding
    print(f"Parsing Nmap file: {xml_file}...")
    findings = []
    try: 
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall('host'):
            host_address = host.find('address').get('addr')

            for port in host.findall('.//port'):
                port_num = int(port.get('portid'))
                port_proto = port.get('protocol')

                service = port.find('service')
                if service is not None:
                    service_name = service.get('name', 'unknown')
                    product = service.get('product', '')
                    version = service.get('version', '')

                    # create a finding for an open port/service
                    finding=NormalizedFinding(
                        host=host_address,
                        port=port_num,
                        protocol=port_proto,
                        finding_name=f"Open Port: {service_name}",
                        severity="info", #nmap port scans are generally informational
                        source_tool="nmap",
                        description=f"Service {service_name} detected on port {port_num}/{port_proto}. Product: {product}, Version: {version}",
                        raw_evidence={
                            'port': port_num,
                            'protocol': port_proto,
                            'service': service_name,
                            'product': product,
                            'version': version
                        }
                    )
                    findings.append(finding)

        print(f"Found {len(findings)} Nmap findings.")
        return findings
    
    except ET.ParseError as e:
        print(f"Error parsing Nmap XML: {e}")
        return []
    except FileNotFoundError:
        print(f"Nmap output file not found: {xml_file}")
        return []
    
def parse_nuclei_jsonl(jsonl_file: str) -> List[NormalizedFinding]:
    # parses a Nuclei JSON-Lines output file into a list of NormalizedFinding
    print(f"Parsing Nuclei file: {jsonl_file}...")
    findings = []
    try:
        with open(jsonl_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)

                    finding = NormalizedFinding(
                        # 'host' in Nuclei is the full URL
                        host=data.get('host', 'unknown'),
                        port=None, #Nuclei doesn't always specify port
                        protocol=data.get('scheme'),
                        finding_name=data.get('info', {}).get('name', 'N/A'),
                        severity=data.get('info', {}).get('severity', 'info'),
                        source_tool="nuclei",
                        description=data.get('info', {}).get('description', 'No description provided.'),
                        raw_evidence=data #store the entire JSON line as evidence
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")

        print(f"Found {len(findings)} Nuclei findings.")
        return findings
    except FileNotFoundError:
        print(f"Nuclei output file not found: {jsonl_file}")
        return []

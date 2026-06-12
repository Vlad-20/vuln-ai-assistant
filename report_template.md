# {{TARGET_DOMAIN}}

## Attack Surface Discovery Report

**{{SCAN_DATE}}**

---

# Table of Contents

- Disclaimer
- Executive Summary
- Business Impact
- Scan Metadata
- Abbreviations
- Scope of Work
- Methodology
- Finding Severity Ratings
- Attack Surface Summary
- Detailed Findings
- General Conclusions & Recommendations

---

# Disclaimer

This document is private and intended only for the commissioning party. Please do not share, publish, or use it without written permission.

While this report was prepared carefully and in good faith, it does not guarantee that all information, findings, or assessments are entirely accurate or complete. The findings reflect the state of the target at the time of scanning and may not capture changes made before or after the assessment window.

This report is not responsible for any consequences or issues arising from the use of, or reliance on, the information provided herein.

---

# Executive Summary

[Write 2–3 sentences describing: what was scanned, the overall risk posture, and the single most urgent action the reader should take. Use plain language — assume the reader is not a security professional.]

### Scope

The scope of this assessment included all publicly accessible domains, subdomains, IP addresses, and external services associated with **{{TARGET_DOMAIN}}**.

### Key Findings

The attack surface assessment revealed the following significant exposures:

- **[Finding name]**: [One-sentence plain-language description]
- **[Finding name]**: [One-sentence plain-language description]
- **[Finding name]**: [One-sentence plain-language description]

[List only Critical and High findings here. If none exist, state that no critical or high severity findings were identified.]

---

# Business Impact

[Write 2–3 paragraphs describing the real-world consequences of the findings for the organization. Focus on: data exposure risk, reputational damage, operational disruption, and regulatory or compliance implications. Be direct about severity — do not downplay risks — but do not fabricate or exaggerate beyond what the findings support. Avoid technical jargon; write as if explaining to a business executive.]

---

# Scan Metadata

|Field|Value|
|---|---|
|Target Domain|{{TARGET_DOMAIN}}|
|Scan Date|{{SCAN_DATE}}|
|Tools Used|{{TOOLS_USED}}|
|Subdomains Found|{{SUBDOMAIN_COUNT}}|
|Live Hosts|{{LIVE_HOST_COUNT}}|
|Total Findings|{{TOTAL_FINDINGS}}|
|Pipeline Version|{{PIPELINE_VERSION}}|

---

# Abbreviations

The following abbreviations are used throughout this document.

|Abbreviation|Definition|
|---|---|
|**CVE**|Common Vulnerabilities and Exposures — a publicly maintained list of known security flaws, each assigned a unique identifier (e.g. CVE-2021-44228).|
|**CVSS**|Common Vulnerability Scoring System — a standardized score from 0.0 to 10.0 indicating the severity of a vulnerability.|
|**EPSS**|Exploit Prediction Scoring System — a probability score (0–1) estimating the likelihood that a vulnerability will be actively exploited in the wild within 30 days.|
|**KEV**|Known Exploited Vulnerabilities — a catalog maintained by CISA listing CVEs that have been confirmed as actively exploited by threat actors.|
|**DNS**|Domain Name System — the system that translates human-readable domain names (e.g. example.com) into IP addresses.|
|**HTTP/HTTPS**|Hypertext Transfer Protocol (Secure) — the communication protocol used to transfer data between web browsers and servers. HTTPS is the encrypted version.|
|**OWASP**|Open Web Application Security Project — a non-profit foundation that publishes widely used security standards and guidelines.|
|**N/A**|Not Applicable — used when a field (e.g. CVSS score) does not apply to a finding, such as an exposed file path with no associated CVE.|

---

# Scope of Work

This assessment was conducted as an external attack surface discovery engagement targeting **{{TARGET_DOMAIN}}**. The objective was to perform a comprehensive reconnaissance of the client's external digital footprint — identifying, cataloguing, and evaluating publicly exposed assets and potential entry points that could be targeted by malicious actors.

The engagement was strictly non-intrusive. No exploitation attempts were made. All findings are based on passive enumeration, service probing, and template-based detection.

**In scope:**

- All subdomains and DNS records associated with {{TARGET_DOMAIN}}
- All live HTTP/HTTPS services reachable from the public internet
- Publicly accessible files, directories, and endpoints
- Software versions and known associated vulnerabilities

**Out of scope:**

- Social engineering
- Physical security
- Denial of service testing
- Exploitation or post-exploitation activities

---

# Methodology

The assessment was conducted using an automated pipeline following a layered discovery approach:

- **Subdomain Enumeration**: Passive DNS enumeration was used to discover all subdomains associated with the target domain.
- **Live Host Probing**: All discovered subdomains were probed to identify live HTTP/HTTPS services, response codes, and web technologies in use.
- **Port & Service Scanning**: Open ports and running services were identified on all live hosts to map the exposed network perimeter.
- **Directory & File Discovery**: Forced browsing techniques were applied to discover exposed files, directories, and sensitive paths (e.g. configuration files, backup files, administrative interfaces).
- **Web Crawling**: Live web applications were crawled to discover linked endpoints, parameters, and additional exposed resources.
- **Vulnerability Scanning**: Template-based scanning was applied to detect known vulnerabilities, misconfigurations, and version-specific security issues.
- **CVE Enrichment**: Identified software versions and vulnerabilities were cross-referenced against the NVD (National Vulnerability Database), EPSS, and CISA's Known Exploited Vulnerabilities catalog to provide risk context.
- **Prioritization**: All findings were scored and prioritized using a rule-based model that accounts for CVSS severity, EPSS exploitation likelihood, KEV status, and direct exposure risk.

---

# Finding Severity Ratings

The following table defines the severity levels used throughout this document.

|Severity|CVSS Score Range|Definition|
|---|---|---|
|**Critical**|9.0–10.0|Exploitation is straightforward and typically results in full system compromise or severe data exposure. Immediate remediation is required.|
|**High**|7.0–8.9|Exploitation is feasible and could result in elevated access, data loss, or service disruption. Remediation should be planned as soon as possible.|
|**Medium**|4.0–6.9|Vulnerabilities exist but are more difficult to exploit, often requiring additional conditions such as user interaction. Remediation should be scheduled after higher-priority issues.|
|**Low**|0.1–3.9|Vulnerabilities are present but unlikely to be exploited in isolation. Remediation should be included in the next maintenance window.|
|**Informational**|N/A|No direct vulnerability. Findings represent exposed information, technology fingerprints, or observations that increase the overall attack surface.|

> **Note on exposure findings:** Some findings in this report — such as exposed configuration files (e.g. `/.env`), version control directories (e.g. `/.git`), or sensitive endpoints — are rated based on the sensitivity of the exposed data and the directness of access, independent of a CVSS score. An exposed `/.env` file containing credentials is treated as High or Critical regardless of whether a CVE exists for it.

Risk is assessed across two dimensions:

- **Likelihood** — the probability that the vulnerability could be exploited, considering attack complexity, available tooling, and attacker skill level.
- **Impact** — the potential effect on confidentiality, integrity, and availability of systems and data, including reputational and financial consequences.

---

# Attack Surface Summary

The following tables provide an inventory of the discovered attack surface.

### Findings by Severity

|Critical|High|Medium|Low|Informational|
|:-:|:-:|:-:|:-:|:-:|
|{{COUNT_CRITICAL}}|{{COUNT_HIGH}}|{{COUNT_MEDIUM}}|{{COUNT_LOW}}|{{COUNT_INFO}}|

### Discovered Assets

|Asset Type|Count|
|---|---|
|Subdomains|{{SUBDOMAIN_COUNT}}|
|Live Hosts|{{LIVE_HOST_COUNT}}|
|Open Ports|{{OPEN_PORT_COUNT}}|
|Exposed Endpoints|{{ENDPOINT_COUNT}}|
|Technologies Detected|{{TECH_COUNT}}|

### Finding Index

|Ref|Title|Severity|
|---|---|---|
|F-01|[Finding title]|[Severity]|
|F-02|[Finding title]|[Severity]|
|F-03|[Finding title]|[Severity]|

[List all findings here in order of decreasing severity. This table is the reader's navigation guide to the detailed section below.]

---

# Detailed Findings

All findings identified during the assessment are listed below with a full description, risk rating, and remediation guidance.

---

**Finding F-01: [Title]**

|Field|Detail|
|---|---|
|**Description**|[Clear explanation of what was found and why it is a security risk. Write for a non-technical reader — avoid jargon or explain it if unavoidable. Include what an attacker could do with this finding.]|
|**Severity**|[Critical / High / Medium / Low / Informational]|
|**CVSS Score**|[Score and vector, or "N/A — exposure finding"]|
|**EPSS Score**|[Exploitation probability, e.g. "0.94 (94% likelihood of exploitation in the wild)" — or "N/A"]|
|**KEV Status**|[Yes — actively exploited / No / N/A]|
|**Target**|[Affected URL, host, or path]|
|**Discovered By**|[Tool name, e.g. Nuclei / Feroxbuster / WPScan]|
|**References**|[CVE ID if applicable, OWASP link, CWE link, or other relevant reference]|
|**Remediation**|[Concrete, actionable steps to fix the issue. Use a bulleted list. Be specific.]|

---

[Repeat the finding block above for each finding, ordered Critical → High → Medium → Low → Informational.]

---

# General Conclusions

[Write 2–3 paragraphs summarizing the overall security posture of the target. Highlight the most significant themes across findings — for example, if multiple findings relate to outdated software, or multiple sensitive paths are exposed, call that out as a systemic issue rather than individual problems. End with a forward-looking statement about what addressing these findings would mean for the organization's security posture.]

## Recommendations

[List the top recommendations in priority order. Each recommendation should be actionable and tied to specific findings. Example format below.]

1. **[Recommendation title]** — [One sentence describing the action and which finding(s) it addresses.]
2. **[Recommendation title]** — [One sentence describing the action and which finding(s) it addresses.]
3. **[Recommendation title]** — [One sentence describing the action and which finding(s) it addresses.]

[Aim for 5–8 recommendations. Start with the highest-severity items and end with general hygiene improvements.]
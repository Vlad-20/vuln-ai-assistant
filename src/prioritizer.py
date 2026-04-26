"""
prioritizer.py — Phase 1 post-processor for the vuln-ai-assistant pipeline.

Reads the unified findings JSONL produced by main.py, deduplicates findings,
scores them by priority, groups them by multiple dimensions, and writes two
output files:
  <stem>.annotated.jsonl  — every deduplicated finding with scoring fields
  <stem>.prioritized.json — grouped views for the LLM report writer

Usage:
    python prioritizer.py <normalized_findings.jsonl>
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Configuration constants — edit these to tune scoring rules
# ---------------------------------------------------------------------------

# Sensitive path patterns: (regex, base_severity, reason)
# Applied to the URL *path* component only (no scheme/host/query).
# First match wins; ordered critical → low.
SENSITIVE_PATHS: List[Tuple[str, str, str]] = [
    # Critical — credential / secret files
    (r"(^|/)\.env$",                       "critical", "environment file exposed"),
    (r"(^|/)\.git/config$",                "critical", "git config file exposed"),
    (r"(^|/)\.aws/credentials$",           "critical", "AWS credentials file exposed"),
    (r"(^|/)(wp-config\.php\.bak|wp-config\.php~)$",
                                            "critical", "WordPress config backup exposed"),
    (r"(^|/)id_rsa$",                      "critical", "SSH private key exposed"),
    (r"(^|/)\.ssh(/|$)",                   "critical", "SSH directory exposed"),
    (r"(^|/)private\.key$",               "critical", "private key file exposed"),
    (r"\.sql$",                             "critical", "SQL dump / database backup exposed"),
    # High — admin panels, VCS dirs, dangerous directories
    (r"(^|/)\.git(/|$)",                   "high", "git repository directory exposed"),
    (r"(^|/)admin(/|$)",                   "high", "admin panel discovered"),
    (r"(^|/)administrator(/|$)",           "high", "admin panel discovered"),
    (r"(^|/)phpmyadmin(/|$)",              "high", "phpMyAdmin panel discovered"),
    (r"(^|/)wp-admin(/|$)",               "high", "WordPress admin panel discovered"),
    (r"(^|/)console(/|$)",                 "high", "management console discovered"),
    (r"(^|/)manager(/|$)",                 "high", "manager interface discovered"),
    (r"(^|/)backups?(/|$)",                "high", "backup directory discovered"),
    (r"(^|/)\.svn(/|$)",                   "high", "SVN repository directory exposed"),
    (r"(^|/)\.DS_Store$",                  "high", ".DS_Store file exposed (hints at directory listing)"),
    (r"(^|/)server-status(/|$)",           "high", "Apache server-status page discovered"),
    (r"(^|/)ftp(/|$)",                     "high", "FTP directory exposed"),
    (r"(^|/)files(/|$)",                   "high", "files directory exposed"),
    # Medium — debug / API documentation pages
    (r"(^|/)phpinfo\.php$",                "medium", "phpinfo page exposed"),
    (r"(^|/)test\.php$",                   "medium", "test script exposed"),
    (r"(^|/)info\.php$",                   "medium", "PHP info page exposed"),
    (r"(^|/)(api/)?swagger(/|$)",          "medium", "Swagger/OpenAPI UI exposed"),
    (r"(^|/)api-docs(/|$)",               "medium", "API documentation exposed"),
    # Low — informational / standard disclosure files
    (r"(^|/)robots\.txt$",                 "low", "robots.txt found"),
    (r"(^|/)sitemap\.xml$",                "low", "sitemap.xml found"),
    (r"(^|/)\.well-known(/|$)",            "low", "well-known directory found"),
]

# Subdomain prefixes that indicate non-production environments.
SUSPICIOUS_SUBDOMAIN_RE = re.compile(
    r"^(staging|dev|development|internal|test|qa|admin|adm|beta|preview|stg|uat)\.",
    re.IGNORECASE,
)

# Standard infrastructure subdomains (expected public-facing, scored info).
STANDARD_INFRA_SUBDOMAIN_RE = re.compile(
    r"^(www|mail|webmail|ns\d*|mx\d*|smtp|pop|imap|ftp)\.",
    re.IGNORECASE,
)

# DNS verification / underscore-prefix records (TXT-proof delegation etc.).
_DNS_VERIFICATION_RE = re.compile(r"^_")

# Service names (as reported by nmap) mapped to priority level.
# High = should not be publicly accessible; info = expected web service.
UNUSUAL_SERVICE_PORTS: Dict[str, str] = {
    "mysql":          "high",
    "postgres":       "high",
    "postgresql":     "high",
    "redis":          "high",
    "mongodb":        "high",
    "elasticsearch":  "high",
    "memcached":      "high",
    "rdp":            "high",    # Remote Desktop Protocol
    "ms-wbt-server":  "high",    # nmap alias for RDP
    "vnc":            "high",
    "microsoft-ds":   "high",    # SMB 445
    "netbios-ssn":    "high",    # SMB 139
    "kibana":         "high",
    "jenkins":        "high",
    "docker":         "high",    # Docker daemon API
    "ftp":            "medium",
    "ftps":           "medium",
    # Expected public services
    "http":           "info",
    "https":          "info",
    "ssl/http":       "info",
    "ssl/https":      "info",
}

# Port-number fallback when nmap didn't identify the service (-sV failed/timed out).
_UNUSUAL_PORTS_BY_NUMBER: Dict[int, Tuple[str, str]] = {
    3306:  ("high",   "MySQL database port exposed"),
    5432:  ("high",   "PostgreSQL database port exposed"),
    6379:  ("high",   "Redis port exposed"),
    27017: ("high",   "MongoDB port exposed"),
    9200:  ("high",   "Elasticsearch port exposed"),
    11211: ("high",   "Memcached port exposed"),
    3389:  ("high",   "RDP port exposed"),
    5900:  ("high",   "VNC port exposed"),
    445:   ("high",   "SMB port exposed"),
    139:   ("high",   "NetBIOS/SMB port exposed"),
    5601:  ("high",   "Kibana port exposed"),
    2375:  ("high",   "Docker daemon API (unauthenticated) exposed"),
    2376:  ("high",   "Docker daemon API port exposed"),
    8080:  ("info",   "HTTP alternate port"),
    8443:  ("info",   "HTTPS alternate port"),
}

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
}

# Nuclei template IDs that indicate tech-fingerprint (not actionable vuln).
_NUCLEI_TECH_RE = re.compile(
    r"(tech-detect|waf-detect|-fingerprint|-detect|-identify)$",
    re.IGNORECASE,
)

# Nuclei template IDs for default-page findings (e.g. default-plesk-page).
_NUCLEI_DEFAULT_PAGE_RE = re.compile(r"^default-.+-page$", re.IGNORECASE)

# Nuclei template IDs for default credential findings.
_NUCLEI_DEFAULT_CREDS_RE = re.compile(
    r"(default-login|default-credentials|default-password)",
    re.IGNORECASE,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _drop_severity(severity: str) -> str:
    """Drop one severity level (floor at 'low')."""
    idx = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[max(0, idx - 1)]


def _extract_host(finding: dict) -> str:
    """Best-effort host extraction from a finding dict."""
    host = finding.get("host")
    if host:
        if "://" in host:
            return urlparse(host).hostname or host
        return host.split(":")[0]
    for key in ("url", "matched_at", "endpoint"):
        val = finding.get(key)
        if val and "://" in val:
            parsed = urlparse(val)
            return parsed.hostname or "_no_host"
    subdomain = finding.get("subdomain")
    if subdomain:
        return subdomain
    return "_no_host"


def _extract_path(url: str) -> str:
    """Return the path component of a URL (no query string, no fragment)."""
    try:
        return urlparse(url).path or "/"
    except Exception:
        return url


def _match_sensitive_path(path: str) -> Optional[Tuple[str, str]]:
    """
    Check a URL path against SENSITIVE_PATHS.
    Returns (base_severity, reason) for the first match, or None.
    """
    for pattern, severity, reason in SENSITIVE_PATHS:
        if re.search(pattern, path, re.IGNORECASE):
            return severity, reason
    return None


def _product_slug(text: str) -> str:
    """Normalize a product name / template_id to a comparable slug."""
    text = text.lower()
    for suffix in ("-detect", "-fingerprint", "-identify", "-version", "-check", "-probe"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
            break
    return re.sub(r"[^a-z0-9]", "", text)


# ---------------------------------------------------------------------------
# Pass 1: Deduplication
# ---------------------------------------------------------------------------

def _fingerprint(finding: dict) -> Optional[tuple]:
    """Compute a deduplication fingerprint. Returns None for unrecognised records."""
    tool = finding.get("tool", "")
    try:
        if tool == "subfinder":
            return ("subfinder", finding.get("subdomain", ""))
        if tool == "httpx":
            return ("httpx", finding.get("url", ""))
        if tool == "nmap":
            return ("nmap", finding.get("host", ""), finding.get("port"), finding.get("protocol", ""))
        if tool == "feroxbuster":
            return ("feroxbuster", finding.get("url", ""), finding.get("status"))
        if tool == "katana":
            return ("katana", finding.get("url", ""))
        if tool == "nuclei":
            return (
                "nuclei",
                finding.get("template_id", ""),
                finding.get("host", ""),
                finding.get("matched_at", ""),
            )
        if tool == "wpscan":
            cve_id = finding.get("cve_id")
            if cve_id:
                return ("wpscan", cve_id)
            return (
                "wpscan",
                finding.get("template_id") or finding.get("finding_name", ""),
                finding.get("host", ""),
            )
        if tool == "app_version_probe":
            return ("app_version_probe", finding.get("url", ""), finding.get("product", ""))
    except Exception as exc:
        log.warning("Could not fingerprint finding (tool=%s): %s", tool, exc)
    return None


def _merge_two(a: dict, b: dict) -> dict:
    """
    Merge record b into record a.
    - sources / raw_records: accumulated
    - list fields: union (order-preserving dedup)
    - scalar fields: prefer non-empty value from a, fall back to b
    """
    merged = dict(a)

    sources_a = a.get("sources", [a.get("tool", "")])
    sources_b = b.get("sources", [b.get("tool", "")])
    merged["sources"] = list(dict.fromkeys(sources_a + sources_b))

    rr_a = a.get("raw_records", [a])
    rr_b = b.get("raw_records", [b])
    merged["raw_records"] = rr_a + rr_b

    for key, val_b in b.items():
        if key in ("sources", "raw_records"):
            continue
        val_a = merged.get(key)
        if isinstance(val_b, list) and isinstance(val_a, list):
            merged[key] = list(dict.fromkeys(val_a + val_b))
        elif not val_a and val_b:
            merged[key] = val_b

    return merged


def _merge_group(records: List[dict]) -> dict:
    """Merge a list of records sharing the same fingerprint into one."""
    if len(records) == 1:
        r = dict(records[0])
        r.setdefault("sources", [r.get("tool", "")])
        r.setdefault("raw_records", [records[0]])
        return r
    result = records[0]
    for other in records[1:]:
        result = _merge_two(result, other)
    return result


def dedupe(findings: List[dict]) -> List[dict]:
    """
    Pass 1: deduplicate findings.

    First deduplicates within each tool using per-tool fingerprints, then
    performs a cross-tool merge between nuclei tech-fingerprint findings and
    app_version_probe findings that identify the same product on the same host.

    Each returned record gains 'sources' and 'raw_records' fields.
    """
    groups: Dict[tuple, List[dict]] = defaultdict(list)
    skipped = 0
    for finding in findings:
        fp = _fingerprint(finding)
        if fp is None:
            log.warning("Skipping unrecognised record: %s", str(finding)[:120])
            skipped += 1
            continue
        groups[fp].append(finding)

    if skipped:
        log.warning("%d record(s) skipped due to unrecognised/missing tool field", skipped)

    merged: List[dict] = [_merge_group(recs) for recs in groups.values()]
    log.debug("Per-tool dedup: %d raw → %d", len(findings) - skipped, len(merged))

    # Cross-tool dedup: nuclei tech-fingerprint + app_version_probe
    avp_index: Dict[Tuple[str, str], int] = {}
    for idx, f in enumerate(merged):
        if f.get("tool") == "app_version_probe":
            host = _extract_host(f)
            slug = _product_slug(f.get("product", ""))
            if slug:
                avp_index[(host, slug)] = idx

    if not avp_index:
        return merged

    to_remove: set = set()
    for idx, f in enumerate(merged):
        if f.get("tool") != "nuclei":
            continue
        tid = f.get("template_id", "")
        if not _NUCLEI_TECH_RE.search(tid):
            continue
        host = _extract_host(f)
        slug = _product_slug(tid)
        avp_key = (host, slug)
        if avp_key in avp_index:
            avp_idx = avp_index[avp_key]
            log.debug(
                "Cross-tool merge: nuclei '%s' ← absorbed into app_version_probe (host=%s)",
                tid, host,
            )
            merged[avp_idx] = _merge_two(merged[avp_idx], f)
            to_remove.add(idx)

    return [f for i, f in enumerate(merged) if i not in to_remove]


# ---------------------------------------------------------------------------
# Pass 2: Priority scoring
# ---------------------------------------------------------------------------

def score(finding: dict) -> Tuple[str, str, str, bool]:
    """
    Score a deduplicated finding.

    Returns (priority, priority_reason, category, is_anchor).
    Priority is one of: critical / high / medium / low / info.
    First-match rule system; dispatches on 'tool'.
    """
    tool = finding.get("tool", "")

    # CVE-bearing rules — currently inert (no CVE fields in pipeline output yet).
    # When cve_id / cvss / epss / kev fields are added by the enrichment module
    # these branches will fire automatically.
    cve_id = finding.get("cve_id")
    cvss   = finding.get("cvss")
    epss   = finding.get("epss")
    kev    = finding.get("kev")
    if cve_id or cvss or epss or kev:
        if kev:
            return "critical", f"in CISA KEV catalog (CVE {cve_id})", "vulnerability", False
        try:
            cvss_f = float(cvss) if cvss else 0.0
            epss_f = float(epss) if epss else 0.0
        except (ValueError, TypeError):
            cvss_f = epss_f = 0.0
        if epss_f >= 0.5 and cvss_f >= 7:
            return (
                "critical",
                f"high exploit probability (EPSS {epss_f:.2f}) + high severity (CVSS {cvss_f})",
                "vulnerability",
                False,
            )
        if cvss_f >= 9:
            return "critical", f"critical CVSS {cvss_f}", "vulnerability", False
        if cvss_f >= 7 or epss_f >= 0.3:
            return "high", f"CVSS {cvss_f} / EPSS {epss_f:.2f}", "vulnerability", False
        if cvss_f >= 4:
            return "medium", f"CVSS {cvss_f}", "vulnerability", False
        return "low", f"low severity CVE {cve_id}", "vulnerability", False

    if tool == "feroxbuster":
        return _score_feroxbuster(finding)
    if tool == "katana":
        return _score_katana(finding)
    if tool == "subfinder":
        return _score_subfinder(finding)
    if tool == "nmap":
        return _score_nmap(finding)
    if tool == "httpx":
        return "info", "live host fingerprint", "tech_fingerprint", False
    if tool == "nuclei":
        return _score_nuclei(finding)
    if tool == "wpscan":
        return _score_wpscan(finding)
    if tool == "app_version_probe":
        return "info", "confirmed product version", "tech_fingerprint", True

    log.warning("Unknown tool '%s' — applying default scoring", tool)
    return "info", "uncategorized finding", "other", False


def _score_feroxbuster(finding: dict) -> Tuple[str, str, str, bool]:
    url    = finding.get("url", "")
    status = finding.get("status", 0)
    path   = _extract_path(url)

    match = _match_sensitive_path(path)
    if match:
        base_sev, reason = match
        final_sev = base_sev if status not in (404, 500) else _drop_severity(base_sev)
        return final_sev, reason, "exposed_path", False

    if status in (200, 201, 204, 301, 302):
        return "info", "discovered path", "exposed_path", False
    if status == 403:
        return "low", "access-restricted path discovered", "exposed_path", False
    if status == 500:
        return "low", "server error on discovered path", "exposed_path", False
    return "info", "discovered path", "exposed_path", False


def _score_katana(finding: dict) -> Tuple[str, str, str, bool]:
    path = _extract_path(finding.get("url", ""))
    match = _match_sensitive_path(path)
    if match:
        base_sev, reason = match
        return base_sev, reason, "exposed_path", False
    return "info", "crawled URL", "other", False


def _score_subfinder(finding: dict) -> Tuple[str, str, str, bool]:
    subdomain = finding.get("subdomain", "")
    if _DNS_VERIFICATION_RE.match(subdomain):
        return "info", "DNS verification record", "subdomain", False
    if SUSPICIOUS_SUBDOMAIN_RE.match(subdomain):
        return "high", "non-production subdomain publicly resolving", "subdomain", False
    if STANDARD_INFRA_SUBDOMAIN_RE.match(subdomain):
        return "info", "standard infrastructure subdomain", "subdomain", False
    return "info", "discovered subdomain", "subdomain", False


def _score_nmap(finding: dict) -> Tuple[str, str, str, bool]:
    service = (finding.get("service") or "").lower()
    port    = finding.get("port", 0)

    if service in UNUSUAL_SERVICE_PORTS:
        sev = UNUSUAL_SERVICE_PORTS[service]
        if sev == "info":
            return "info", f"standard web service on port {port}", "service", False
        return sev, f"unusual service exposed: {service} on port {port}", "service", False

    if port in _UNUSUAL_PORTS_BY_NUMBER:
        sev, reason = _UNUSUAL_PORTS_BY_NUMBER[port]
        return sev, reason, "service", False

    if service == "ssh" or port == 22:
        return "info", f"SSH service on port {port}", "service", False

    return "info", f"open port {port} ({service or 'unknown service'})", "service", False


def _score_nuclei(finding: dict) -> Tuple[str, str, str, bool]:
    tid      = finding.get("template_id", "")
    severity = _NUCLEI_SEVERITY_MAP.get(finding.get("severity", "info"), "info")

    if _NUCLEI_DEFAULT_PAGE_RE.match(tid):
        return "low", "default/unconfigured service page exposed", "misconfiguration", False
    if _NUCLEI_DEFAULT_CREDS_RE.search(tid):
        return "critical", "default credentials detected", "vulnerability", False
    if _NUCLEI_TECH_RE.search(tid):
        return "info", "technology fingerprint", "tech_fingerprint", False
    if re.search(r"(exposure|disclosure)", tid, re.IGNORECASE) and severity == "info":
        return "low", "information exposure", "misconfiguration", False

    category = "vulnerability" if severity in ("medium", "high", "critical") else "tech_fingerprint"
    return severity, f"nuclei finding: {finding.get('finding_name', tid)}", category, False


def _score_wpscan(finding: dict) -> Tuple[str, str, str, bool]:
    cve_id = finding.get("cve_id")
    if cve_id:
        severity = _NUCLEI_SEVERITY_MAP.get(finding.get("severity", "medium"), "medium")
        return severity, f"WordPress vulnerability {cve_id}", "vulnerability", False

    finding_type = finding.get("finding_type", "")
    severity     = _NUCLEI_SEVERITY_MAP.get(finding.get("severity", "info"), "info")
    name         = finding.get("finding_name", "")

    if finding_type == "interesting_finding":
        return "info", "WordPress installation identified", "tech_fingerprint", True

    if finding_type == "vulnerability":
        refs = finding.get("references", {})
        has_cve = bool(
            refs.get("cve")
            or refs.get("cveIds")
            or any("CVE-" in str(v) for v in refs.values() if isinstance(v, (str, list)))
        )
        return severity, f"WordPress finding: {name}", "vulnerability" if has_cve else "tech_fingerprint", False

    if finding_type == "user_enumerated":
        return "low", "WordPress user enumerated", "misconfiguration", False

    return severity, f"WordPress finding: {name}", "tech_fingerprint", False


# ---------------------------------------------------------------------------
# Pass 3: Grouping
# ---------------------------------------------------------------------------

def _derive_scan_target(findings: List[dict]) -> str:
    """Best-effort: return the most common parent_domain or hostname."""
    parent_domains = [f.get("parent_domain") for f in findings if f.get("parent_domain")]
    if parent_domains:
        return Counter(parent_domains).most_common(1)[0][0]
    hosts = [_extract_host(f) for f in findings if _extract_host(f) != "_no_host"]
    if hosts:
        return Counter(hosts).most_common(1)[0][0]
    return "unknown"


def group(findings: List[dict]) -> dict:
    """
    Pass 3: build grouped views of the scored findings.

    A finding intentionally appears in multiple groups:
    by_priority, by_host, and by_category simultaneously.
    """
    by_priority: Dict[str, List[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    by_host: Dict[str, List[dict]] = defaultdict(list)
    by_category: Dict[str, List[dict]] = {
        "subdomain": [], "host": [], "service": [], "exposed_path": [],
        "tech_fingerprint": [], "vulnerability": [], "misconfiguration": [], "other": [],
    }
    anchors: List[dict] = []

    for f in findings:
        priority = f.get("priority", "info")
        category = f.get("category", "other")
        host     = _extract_host(f)

        by_priority.get(priority, by_priority["info"]).append(f)
        by_host[host].append(f)
        by_category.get(category, by_category["other"]).append(f)

        if f.get("anchor"):
            anchors.append(f)

    return {
        "by_priority": by_priority,
        "by_host":     dict(by_host),
        "by_category": by_category,
        "anchors":     anchors,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def prioritize(input_path: Path) -> Tuple[Path, Path]:
    """
    Top-level orchestration: read → dedupe → score → group → write.

    Returns (annotated_jsonl_path, prioritized_json_path).
    """
    log.info("Reading findings from %s", input_path)
    raw_findings: List[dict] = []
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw_findings.append(json.loads(line))
            except json.JSONDecodeError as exc:
                log.warning("Line %d: invalid JSON — skipping (%s)", lineno, exc)

    log.info("Loaded %d raw finding(s)", len(raw_findings))

    # Pass 1
    deduped = dedupe(raw_findings)
    log.info("After deduplication: %d finding(s)", len(deduped))

    # Pass 2
    scored: List[dict] = []
    for finding in deduped:
        try:
            priority, reason, category, is_anchor = score(finding)
        except Exception as exc:
            log.warning(
                "Scoring failed for finding (tool=%s): %s",
                finding.get("tool"), exc,
            )
            priority, reason, category, is_anchor = "info", "scoring error", "other", False

        annotated = dict(finding)
        annotated["priority"]        = priority
        annotated["priority_reason"] = reason
        annotated["category"]        = category
        if is_anchor:
            annotated["anchor"] = True
        scored.append(annotated)
        log.debug(
            "Scored %s / %s → %s",
            finding.get("tool"),
            finding.get("template_id") or finding.get("url") or finding.get("subdomain"),
            priority,
        )

    # Pass 3
    grouped = group(scored)
    priority_counts = {p: len(lst) for p, lst in grouped["by_priority"].items()}

    output = {
        "metadata": {
            "input_file":                  str(input_path),
            "scan_target":                 _derive_scan_target(scored),
            "generated_at":                datetime.now(timezone.utc).isoformat(),
            "total_findings_raw":          len(raw_findings),
            "total_findings_deduplicated": len(scored),
            "priority_counts":             priority_counts,
        },
        "by_priority": grouped["by_priority"],
        "by_host":     grouped["by_host"],
        "by_category": grouped["by_category"],
        "anchors":     grouped["anchors"],
    }

    stem             = input_path.stem
    out_dir          = input_path.parent
    annotated_path   = out_dir / f"{stem}.annotated.jsonl"
    prioritized_path = out_dir / f"{stem}.prioritized.json"

    with open(annotated_path, "w", encoding="utf-8") as fh:
        for f in scored:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    log.info("Wrote annotated findings → %s", annotated_path)

    with open(prioritized_path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)
    log.info("Wrote prioritized report → %s", prioritized_path)

    return annotated_path, prioritized_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deduplicate, score, and group pipeline findings from a JSONL file."
    )
    parser.add_argument("input", type=Path, help="Path to normalized_findings.jsonl")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        annotated, prioritized = prioritize(args.input)
        print(f"Annotated:   {annotated}")
        print(f"Prioritized: {prioritized}")
    except FileNotFoundError:
        log.error("Input file not found: %s", args.input)
        raise SystemExit(1)
    except Exception as exc:
        log.exception("Unexpected error: %s", exc)
        raise SystemExit(2)


if __name__ == "__main__":
    main()

"""
Tests for src/prioritizer.py

Run with: pytest tests/test_prioritizer.py -v
"""

import json
import shutil
from pathlib import Path

import pytest

from prioritizer import dedupe, group, prioritize, score

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def juice_shop_fixture() -> Path:
    return FIXTURES / "juice_shop_findings.jsonl"


@pytest.fixture
def hackout_ro_fixture() -> Path:
    return FIXTURES / "hackout_ro_findings.jsonl"


# ---------------------------------------------------------------------------
# Pass 1 — Deduplication
# ---------------------------------------------------------------------------

class TestDedupe:
    def test_subfinder_same_subdomain_merges_sources(self):
        """Two subfinder records for the same subdomain with different data sources
        collapse into one finding whose 'sources' contains both source names."""
        findings = [
            {
                "tool": "subfinder",
                "subdomain": "sub.example.com",
                "parent_domain": "example.com",
                "sources": ["thc"],
            },
            {
                "tool": "subfinder",
                "subdomain": "sub.example.com",
                "parent_domain": "example.com",
                "sources": ["rapiddns"],
            },
        ]
        result = dedupe(findings)
        assert len(result) == 1
        assert set(result[0]["sources"]) == {"thc", "rapiddns"}
        assert result[0]["subdomain"] == "sub.example.com"
        assert len(result[0]["raw_records"]) == 2

    def test_different_subdomains_are_not_merged(self):
        findings = [
            {"tool": "subfinder", "subdomain": "a.example.com", "parent_domain": "example.com", "sources": ["thc"]},
            {"tool": "subfinder", "subdomain": "b.example.com", "parent_domain": "example.com", "sources": ["thc"]},
        ]
        assert len(dedupe(findings)) == 2

    def test_nuclei_and_app_version_probe_same_product_same_host_merge(self):
        """A nuclei tech-detect finding and an app_version_probe finding that
        identify the same product on the same host are merged into one record."""
        findings = [
            {
                "tool": "nuclei",
                "host": "juice-shop",
                "finding_name": "Juice Shop Detect",
                "severity": "info",
                "description": "",
                "template_id": "juice-shop-detect",
                "matcher_name": "",
                "matched_at": "http://juice-shop:3000",
                "extracted_results": ["15.0.0"],
                "curl_command": "",
                "references": [],
            },
            {
                "tool": "app_version_probe",
                "url": "http://juice-shop:3000",
                "endpoint": "http://juice-shop:3000/api/Challenges",
                "product": "Juice Shop",
                "version": "15.0.0",
                "raw_response_snippet": "",
            },
        ]
        result = dedupe(findings)
        assert len(result) == 1, (
            f"Expected 1 merged finding, got {len(result)}: {[r.get('tool') for r in result]}"
        )
        assert "nuclei" in result[0]["sources"]
        assert "app_version_probe" in result[0]["sources"]

    def test_nuclei_non_tech_detect_does_not_merge_with_avp(self):
        """A nuclei finding whose template_id is NOT a tech-detect pattern should
        NOT be merged with app_version_probe even if the product slug matches."""
        findings = [
            {
                "tool": "nuclei",
                "host": "juice-shop",
                "finding_name": "Some Vuln",
                "severity": "high",
                "description": "",
                "template_id": "juice-shop-sqli",  # not a fingerprint template
                "matcher_name": "",
                "matched_at": "http://juice-shop:3000",
                "extracted_results": [],
                "curl_command": "",
                "references": [],
            },
            {
                "tool": "app_version_probe",
                "url": "http://juice-shop:3000",
                "endpoint": "http://juice-shop:3000/api/Challenges",
                "product": "Juice Shop",
                "version": "15.0.0",
                "raw_response_snippet": "",
            },
        ]
        result = dedupe(findings)
        assert len(result) == 2

    def test_raw_records_preserved(self):
        """Every merged finding must carry a raw_records list for traceability."""
        findings = [
            {"tool": "httpx", "url": "http://example.com", "status_code": 200,
             "title": "", "technologies": [], "webserver": "", "ip": "", "cdn": ""},
        ]
        result = dedupe(findings)
        assert len(result[0]["raw_records"]) == 1

    def test_unrecognised_tool_is_skipped(self):
        """Records with an unrecognised tool field are skipped without crashing."""
        findings = [
            {"tool": "unknown_tool_xyz", "data": "whatever"},
            {"tool": "httpx", "url": "http://example.com", "status_code": 200,
             "title": "", "technologies": [], "webserver": "", "ip": "", "cdn": ""},
        ]
        result = dedupe(findings)
        # Only the httpx record survives
        assert len(result) == 1
        assert result[0]["tool"] == "httpx"


# ---------------------------------------------------------------------------
# Pass 2 — Scoring
# ---------------------------------------------------------------------------

class TestScoreFeroxbuster:
    def _make(self, url: str, status: int, content_length: int = 500) -> dict:
        return {"tool": "feroxbuster", "url": url, "status": status, "content_length": content_length}

    def test_env_200_is_critical(self):
        priority, reason, category, anchor = score(self._make("http://host/.env", 200))
        assert priority == "critical"
        assert category == "exposed_path"

    def test_env_404_drops_to_high(self):
        priority, _, _, _ = score(self._make("http://host/.env", 404))
        assert priority == "high"

    def test_env_500_drops_to_high(self):
        priority, _, _, _ = score(self._make("http://host/.env", 500))
        assert priority == "high"

    def test_ftp_200_is_high(self):
        priority, reason, category, _ = score(self._make("http://host/ftp", 200))
        assert priority == "high"
        assert category == "exposed_path"

    def test_api_500_is_low(self):
        """Non-sensitive path with 500 response → low."""
        priority, reason, category, _ = score(self._make("http://host/api", 500))
        assert priority == "low"
        assert "server error" in reason.lower()

    def test_normal_200_is_info(self):
        priority, _, _, _ = score(self._make("http://host/about", 200))
        assert priority == "info"

    def test_403_non_sensitive_is_low(self):
        priority, reason, _, _ = score(self._make("http://host/about", 403))
        assert priority == "low"
        assert "access-restricted" in reason.lower()

    def test_git_config_200_is_critical(self):
        priority, _, _, _ = score(self._make("http://host/.git/config", 200))
        assert priority == "critical"

    def test_swagger_200_is_medium(self):
        priority, _, _, _ = score(self._make("http://host/api/swagger", 200))
        assert priority == "medium"

    def test_robots_txt_is_low(self):
        priority, _, _, _ = score(self._make("http://host/robots.txt", 200))
        assert priority == "low"


class TestScoreSubfinder:
    def _make(self, subdomain: str) -> dict:
        return {"tool": "subfinder", "subdomain": subdomain,
                "parent_domain": "example.com", "sources": ["thc"]}

    def test_staging_subdomain_is_high(self):
        priority, reason, category, _ = score(self._make("staging.example.com"))
        assert priority == "high"
        assert "non-production" in reason.lower()
        assert category == "subdomain"

    def test_dev_subdomain_is_high(self):
        priority, _, _, _ = score(self._make("dev.example.com"))
        assert priority == "high"

    def test_dns_verification_record_is_info(self):
        """Underscore-prefix subdomains (TXT/DNS verification) must not be flagged."""
        priority, reason, category, _ = score(self._make("_dc-mx.589dcacf336b.example.com"))
        assert priority == "info"
        assert "dns verification" in reason.lower()

    def test_www_is_info(self):
        priority, _, _, _ = score(self._make("www.example.com"))
        assert priority == "info"

    def test_unknown_subdomain_is_info(self):
        priority, reason, category, _ = score(self._make("blog.example.com"))
        assert priority == "info"
        assert category == "subdomain"


class TestScoreNmap:
    def _make(self, port: int, service: str = "", product: str = "") -> dict:
        return {"tool": "nmap", "host": "10.0.0.1", "port": port,
                "protocol": "tcp", "service": service, "product": product, "version": ""}

    def test_mysql_service_is_high(self):
        priority, reason, category, _ = score(self._make(3306, "mysql", "MySQL"))
        assert priority == "high"
        assert category == "service"

    def test_mysql_port_fallback_is_high(self):
        """When service detection returns empty string, port 3306 still triggers high."""
        priority, _, _, _ = score(self._make(3306, "", ""))
        assert priority == "high"

    def test_http_on_80_is_info(self):
        priority, reason, category, _ = score(self._make(80, "http"))
        assert priority == "info"
        assert category == "service"

    def test_redis_is_high(self):
        priority, _, _, _ = score(self._make(6379, "redis"))
        assert priority == "high"

    def test_ssh_is_info(self):
        priority, _, _, _ = score(self._make(22, "ssh"))
        assert priority == "info"


class TestScoreNuclei:
    def _make(self, template_id: str, severity: str = "info", finding_name: str = "") -> dict:
        return {
            "tool": "nuclei",
            "host": "example.com",
            "finding_name": finding_name or template_id,
            "severity": severity,
            "description": "",
            "template_id": template_id,
            "matcher_name": "",
            "matched_at": "http://example.com",
            "extracted_results": [],
            "curl_command": "",
            "references": [],
        }

    def test_default_plesk_page_overrides_info_to_low(self):
        """default-plesk-page has severity=info in nuclei but should score as low."""
        priority, reason, category, _ = score(self._make("default-plesk-page", "info"))
        assert priority == "low"
        assert "default" in reason.lower()
        assert category == "misconfiguration"

    def test_tech_detect_is_info_tech_fingerprint(self):
        priority, reason, category, _ = score(self._make("tech-detect", "info"))
        assert priority == "info"
        assert category == "tech_fingerprint"

    def test_default_login_is_critical(self):
        priority, _, category, _ = score(self._make("default-login", "medium"))
        assert priority == "critical"
        assert category == "vulnerability"

    def test_high_severity_maps_directly(self):
        priority, _, category, _ = score(self._make("sql-injection", "high"))
        assert priority == "high"
        assert category == "vulnerability"

    def test_exposure_info_becomes_low(self):
        priority, reason, category, _ = score(self._make("git-exposure", "info"))
        assert priority == "low"
        assert category == "misconfiguration"


class TestScoreAppVersionProbe:
    def test_is_info_with_anchor(self):
        finding = {
            "tool": "app_version_probe",
            "url": "http://juice-shop:3000",
            "endpoint": "http://juice-shop:3000/api/Challenges",
            "product": "Juice Shop",
            "version": "15.0.0",
            "raw_response_snippet": "",
        }
        priority, reason, category, is_anchor = score(finding)
        assert priority == "info"
        assert is_anchor is True
        assert category == "tech_fingerprint"


class TestScoreHttpx:
    def test_is_always_info(self):
        finding = {
            "tool": "httpx",
            "url": "http://example.com",
            "status_code": 200,
            "title": "Example",
            "technologies": ["nginx"],
            "webserver": "nginx",
            "ip": "1.2.3.4",
            "cdn": "",
        }
        priority, _, category, anchor = score(finding)
        assert priority == "info"
        assert category == "tech_fingerprint"
        assert anchor is False


class TestScoreCveFields:
    """CVE rules are currently inert but must fire correctly when fields appear."""

    def _base(self) -> dict:
        return {"tool": "nuclei", "host": "h", "finding_name": "x", "severity": "info",
                "description": "", "template_id": "x", "matcher_name": "",
                "matched_at": "http://h", "extracted_results": [], "curl_command": "",
                "references": []}

    def test_kev_is_critical(self):
        f = {**self._base(), "cve_id": "CVE-2021-44228", "kev": True}
        priority, reason, _, _ = score(f)
        assert priority == "critical"
        assert "kev" in reason.lower()

    def test_high_cvss_is_critical(self):
        f = {**self._base(), "cve_id": "CVE-2021-1234", "cvss": 9.8}
        priority, _, _, _ = score(f)
        assert priority == "critical"

    def test_medium_cvss_is_medium(self):
        f = {**self._base(), "cve_id": "CVE-2021-9999", "cvss": 5.5}
        priority, _, _, _ = score(f)
        assert priority == "medium"


# ---------------------------------------------------------------------------
# Pass 3 — Grouping
# ---------------------------------------------------------------------------

class TestGroup:
    def _make_scored(self, tool: str, url: str, priority: str, category: str) -> dict:
        return {
            "tool": tool,
            "url": url,
            "priority": priority,
            "priority_reason": "test",
            "category": category,
        }

    def test_finding_appears_in_priority_host_and_category(self):
        """A single finding must appear in by_priority, by_host, and by_category."""
        findings = [
            {
                "tool": "feroxbuster",
                "url": "http://example.com/.env",
                "status": 200,
                "priority": "critical",
                "priority_reason": "environment file exposed",
                "category": "exposed_path",
            }
        ]
        result = group(findings)
        assert len(result["by_priority"]["critical"]) == 1
        assert len(result["by_host"]["example.com"]) == 1
        assert len(result["by_category"]["exposed_path"]) == 1

    def test_anchors_collected(self):
        findings = [
            {
                "tool": "app_version_probe",
                "url": "http://example.com",
                "product": "WordPress",
                "version": "5.0",
                "priority": "info",
                "priority_reason": "confirmed product version",
                "category": "tech_fingerprint",
                "anchor": True,
            }
        ]
        result = group(findings)
        assert len(result["anchors"]) == 1

    def test_output_structure_has_required_keys(self):
        result = group([])
        assert set(result.keys()) == {"by_priority", "by_host", "by_category", "anchors"}
        assert set(result["by_priority"].keys()) == {"critical", "high", "medium", "low", "info"}
        assert set(result["by_category"].keys()) == {
            "subdomain", "host", "service", "exposed_path",
            "tech_fingerprint", "vulnerability", "misconfiguration", "other",
        }

    def test_no_host_fallback(self):
        """A finding with no extractable host goes into by_host['_no_host']."""
        findings = [
            {
                "tool": "subfinder",
                "subdomain": None,
                "parent_domain": None,
                "sources": [],
                "priority": "info",
                "priority_reason": "x",
                "category": "subdomain",
            }
        ]
        result = group(findings)
        assert "_no_host" in result["by_host"]


# ---------------------------------------------------------------------------
# End-to-end: Juice Shop fixture through prioritize()
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_juice_shop_output_structure(self, juice_shop_fixture: Path, tmp_path: Path):
        """Feed the Juice Shop fixture through prioritize() and verify structure."""
        input_path = tmp_path / "juice_shop_findings.jsonl"
        shutil.copy(juice_shop_fixture, input_path)

        annotated, prioritized = prioritize(input_path)

        # Both output files must exist and be non-empty
        assert annotated.exists() and annotated.stat().st_size > 0
        assert prioritized.exists() and prioritized.stat().st_size > 0

        # Annotated JSONL: every line must be valid JSON with scoring fields
        with open(annotated, encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh if line.strip()]
        assert len(lines) > 0
        for finding in lines:
            assert "priority" in finding, f"missing 'priority' in {finding.get('tool')}"
            assert "priority_reason" in finding
            assert "category" in finding
            assert finding["priority"] in ("critical", "high", "medium", "low", "info")

        # Prioritized JSON: top-level structure
        with open(prioritized, encoding="utf-8") as fh:
            report = json.load(fh)

        assert set(report.keys()) == {"metadata", "by_priority", "by_host", "by_category", "anchors"}

        meta = report["metadata"]
        for key in ("input_file", "scan_target", "generated_at",
                    "total_findings_raw", "total_findings_deduplicated", "priority_counts"):
            assert key in meta, f"missing metadata key: {key}"

        assert meta["total_findings_raw"] > 0
        assert meta["total_findings_deduplicated"] <= meta["total_findings_raw"]

        assert set(report["by_priority"].keys()) == {"critical", "high", "medium", "low", "info"}
        assert set(report["by_category"].keys()) == {
            "subdomain", "host", "service", "exposed_path",
            "tech_fingerprint", "vulnerability", "misconfiguration", "other",
        }
        assert isinstance(report["anchors"], list)

    def test_juice_shop_dedup_reduces_count(self, juice_shop_fixture: Path, tmp_path: Path):
        """The nuclei juice-shop-detect + app_version_probe merge should reduce raw count."""
        input_path = tmp_path / "juice_shop_findings.jsonl"
        shutil.copy(juice_shop_fixture, input_path)
        annotated, prioritized = prioritize(input_path)
        with open(prioritized, encoding="utf-8") as fh:
            report = json.load(fh)
        assert report["metadata"]["total_findings_deduplicated"] < report["metadata"]["total_findings_raw"]

    def test_juice_shop_has_critical_finding(self, juice_shop_fixture: Path, tmp_path: Path):
        """.env at status 200 must produce a critical finding."""
        input_path = tmp_path / "js2.jsonl"
        shutil.copy(juice_shop_fixture, input_path)
        _, prioritized = prioritize(input_path)
        with open(prioritized, encoding="utf-8") as fh:
            report = json.load(fh)
        assert len(report["by_priority"]["critical"]) >= 1

    def test_juice_shop_has_anchor(self, juice_shop_fixture: Path, tmp_path: Path):
        """app_version_probe must appear in anchors."""
        input_path = tmp_path / "js3.jsonl"
        shutil.copy(juice_shop_fixture, input_path)
        _, prioritized = prioritize(input_path)
        with open(prioritized, encoding="utf-8") as fh:
            report = json.load(fh)
        assert len(report["anchors"]) >= 1

    def test_hackout_ro_runs_cleanly(self, hackout_ro_fixture: Path, tmp_path: Path):
        """hackout.ro fixture must process without errors and produce a valid report."""
        input_path = tmp_path / "hackout_ro_findings.jsonl"
        shutil.copy(hackout_ro_fixture, input_path)
        annotated, prioritized = prioritize(input_path)
        with open(prioritized, encoding="utf-8") as fh:
            report = json.load(fh)
        assert report["metadata"]["total_findings_raw"] == 21
        assert report["metadata"]["total_findings_deduplicated"] <= 21
        # default-plesk-page (info severity) must score as low, not info
        all_findings: list = []
        for lst in report["by_priority"].values():
            all_findings.extend(lst)
        plesk = [f for f in all_findings if f.get("template_id") == "default-plesk-page"]
        assert plesk, "default-plesk-page finding not found in report"
        assert plesk[0]["priority"] == "low"

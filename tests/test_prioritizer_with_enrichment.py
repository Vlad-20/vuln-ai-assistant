"""
tests/test_prioritizer_with_enrichment.py

End-to-end tests that wire enrichment records into prioritizer.prioritize().

These tests exercise the CVE rule branch in prioritizer.score() that was
previously inert because no enrichment records existed in the pipeline.
All NVD/EPSS/KEV calls are mocked; the tests exercise the field-to-priority
mapping rather than any network behavior.
"""

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

import enrichment
from prioritizer import prioritize, score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enrichment_record(**kwargs) -> dict:
    """Build a minimal enrichment record dict with sensible defaults."""
    base = {
        'tool':               'enrichment',
        'host':               'target.example.com',
        'url':                'http://target.example.com',
        'product':            'juice_shop',
        'version':            '15.0.0',
        'source_fingerprint': 'juice_shop:15.0.0',
        'source_tools':       ['app_version_probe'],
        'cve_id':             'CVE-2024-TEST',
        'kev':                False,
        'cve_published':      '2024-01-01',
    }
    base.update(kwargs)
    return base


def _write_jsonl(path: Path, records: list[dict]):
    with open(path, 'w', encoding='utf-8') as fh:
        for r in records:
            fh.write(json.dumps(r) + '\n')


# ---------------------------------------------------------------------------
# score() unit tests — CVE rule branch
# ---------------------------------------------------------------------------

class TestScoreEnrichmentCveRules:
    """Direct unit tests for score() with enrichment-format records."""

    def test_kev_is_critical(self):
        f = _enrichment_record(kev=True, cve_id='CVE-2021-44228')
        priority, reason, category, _ = score(f)
        assert priority == 'critical'
        assert 'kev' in reason.lower()
        assert category == 'vulnerability'

    def test_kev_wins_over_low_cvss(self):
        """KEV flag takes precedence even when CVSS is low."""
        f = _enrichment_record(kev=True, cvss=2.5, cve_id='CVE-2021-44228')
        priority, reason, _, _ = score(f)
        assert priority == 'critical'
        assert 'kev' in reason.lower()

    def test_critical_cvss_no_kev_is_critical(self):
        f = _enrichment_record(cvss=9.8)
        priority, reason, category, _ = score(f)
        assert priority == 'critical'
        assert '9.8' in reason
        assert category == 'vulnerability'

    def test_high_epss_plus_high_cvss_is_critical(self):
        """EPSS >= 0.5 combined with CVSS >= 7 → critical."""
        f = _enrichment_record(cvss=7.5, epss=0.65)
        priority, reason, _, _ = score(f)
        assert priority == 'critical'
        assert 'epss' in reason.lower()

    def test_high_cvss_without_epss_is_high(self):
        """CVSS 7–8.9 with no EPSS → high."""
        f = _enrichment_record(cvss=7.5)
        priority, reason, _, _ = score(f)
        assert priority == 'high'

    def test_medium_cvss_is_medium(self):
        f = _enrichment_record(cvss=5.5)
        priority, _, _, _ = score(f)
        assert priority == 'medium'

    def test_low_cvss_is_low(self):
        f = _enrichment_record(cvss=2.0)
        priority, _, _, _ = score(f)
        assert priority == 'low'

    def test_high_epss_alone_with_borderline_cvss(self):
        """EPSS 0.3+ with CVSS >= 7 → still qualifies for high."""
        f = _enrichment_record(cvss=7.0, epss=0.35)
        priority, _, _, _ = score(f)
        assert priority == 'high'

    def test_enrichment_record_is_never_anchor(self):
        """Enrichment records should never be marked as anchors."""
        f = _enrichment_record(cvss=9.0)
        _, _, _, is_anchor = score(f)
        assert is_anchor is False


# ---------------------------------------------------------------------------
# End-to-end: enrichment records through prioritize()
# ---------------------------------------------------------------------------

class TestPrioritizeWithEnrichmentFixture:
    """
    Feed a JSONL containing enrichment records through prioritize() and verify
    the output metadata and priority groupings.
    """

    def test_kev_record_lands_in_critical_group(self, tmp_path):
        records = [
            _enrichment_record(kev=True, cve_id='CVE-2021-44228'),
        ]
        inp = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, records)
        _, prioritized = prioritize(inp)

        with open(prioritized, encoding='utf-8') as fh:
            report = json.load(fh)

        crits = report['by_priority']['critical']
        assert len(crits) == 1
        assert crits[0]['cve_id'] == 'CVE-2021-44228'
        assert crits[0]['priority'] == 'critical'
        assert 'kev' in crits[0]['priority_reason'].lower()

    def test_high_cvss_lands_in_critical(self, tmp_path):
        records = [_enrichment_record(cvss=9.5)]
        inp = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, records)
        _, prioritized = prioritize(inp)

        with open(prioritized, encoding='utf-8') as fh:
            report = json.load(fh)

        assert report['metadata']['priority_counts']['critical'] >= 1

    def test_epss_plus_cvss_critical(self, tmp_path):
        records = [_enrichment_record(cvss=8.0, epss=0.75, epss_percentile=0.92)]
        inp = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, records)
        _, prioritized = prioritize(inp)

        with open(prioritized, encoding='utf-8') as fh:
            report = json.load(fh)

        assert report['metadata']['priority_counts']['critical'] >= 1
        crit = report['by_priority']['critical'][0]
        assert 'epss' in crit['priority_reason'].lower()

    def test_medium_cvss_lands_in_medium(self, tmp_path):
        records = [_enrichment_record(cvss=5.5)]
        inp = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, records)
        _, prioritized = prioritize(inp)

        with open(prioritized, encoding='utf-8') as fh:
            report = json.load(fh)

        assert report['metadata']['priority_counts']['medium'] >= 1
        assert report['metadata']['priority_counts']['critical'] == 0
        assert report['metadata']['priority_counts']['high'] == 0

    def test_enrichment_record_grouped_in_vulnerability_category(self, tmp_path):
        records = [_enrichment_record(cvss=7.0)]
        inp = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, records)
        _, prioritized = prioritize(inp)

        with open(prioritized, encoding='utf-8') as fh:
            report = json.load(fh)

        vuln_findings = report['by_category']['vulnerability']
        assert len(vuln_findings) >= 1

    def test_mixed_findings_priority_counts(self, tmp_path):
        """Mix of enrichment records at different severities → correct counts."""
        records = [
            _enrichment_record(kev=True,  cve_id='CVE-A'),          # critical
            _enrichment_record(cvss=9.5,  cve_id='CVE-B'),          # critical
            _enrichment_record(cvss=7.5,  cve_id='CVE-C'),          # high
            _enrichment_record(cvss=5.5,  cve_id='CVE-D'),          # medium
            _enrichment_record(cvss=2.0,  cve_id='CVE-E'),          # low
        ]
        inp = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, records)
        _, prioritized = prioritize(inp)

        with open(prioritized, encoding='utf-8') as fh:
            pc = json.load(fh)['metadata']['priority_counts']

        assert pc['critical'] == 2
        assert pc['high']     == 1
        assert pc['medium']   == 1
        assert pc['low']      == 1

    def test_enrichment_records_grouped_by_host(self, tmp_path):
        """Enrichment records appear in by_host keyed to their host field."""
        records = [_enrichment_record(host='vuln.example.com', cvss=8.0)]
        inp = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, records)
        _, prioritized = prioritize(inp)

        with open(prioritized, encoding='utf-8') as fh:
            report = json.load(fh)

        assert 'vuln.example.com' in report['by_host']


# ---------------------------------------------------------------------------
# End-to-end via enrich_to_jsonl → prioritize
# ---------------------------------------------------------------------------

class TestFullPipelineEnrichThenPrioritize:
    """
    Simulate the complete pipeline:
      normalized_findings.jsonl → enrich_to_jsonl → enriched_findings.jsonl
      → prioritize → annotated + prioritized outputs.
    """

    def test_pipeline_kev_finding_is_critical(self, tmp_path):
        """
        A juice_shop app_version_probe finding that matches one KEV CVE should
        produce a critical finding after the full pipeline.
        """
        normalized = tmp_path / 'normalized_findings.jsonl'
        enriched   = tmp_path / 'enriched_findings.jsonl'

        avp_finding = {
            'tool': 'app_version_probe',
            'url': 'http://juice-shop:3000',
            'endpoint': 'http://juice-shop:3000/rest/admin/application-version',
            'product': 'juice_shop',
            'version': '15.0.0',
            'raw_response_snippet': '{"version":"15.0.0"}',
        }
        _write_jsonl(normalized, [avp_finding])

        mock_cve = {
            'cve_id':        'CVE-2021-44228',
            'cvss_score':    10.0,
            'cvss_version':  '3.1',
            'cvss_vector':   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            'cvss_severity': 'critical',
            'published':     '2021-12-10',
            'description':   'Log4Shell remote code execution',
            'references':    ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
        }

        with patch.object(enrichment, 'query_nvd', return_value=[mock_cve]), \
             patch.object(enrichment, 'query_epss',
                          return_value={'CVE-2021-44228': {'score': 0.97, 'percentile': 0.99}}), \
             patch.object(enrichment, 'load_kev_catalog',
                          return_value={'CVE-2021-44228': '2021-12-10'}):
            cve_count = enrichment.enrich_to_jsonl(normalized, enriched)

        assert cve_count == 1

        _, prioritized = prioritize(enriched)

        with open(prioritized, encoding='utf-8') as fh:
            report = json.load(fh)

        assert report['metadata']['priority_counts']['critical'] >= 1
        crit = report['by_priority']['critical'][0]
        assert crit['cve_id'] == 'CVE-2021-44228'
        assert crit['kev'] is True

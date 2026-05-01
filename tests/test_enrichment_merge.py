"""
tests/test_enrichment_merge.py

Unit tests for enrichment.enrich_to_jsonl().

All external network calls (NVD, EPSS, KEV) are mocked; these tests never hit
live APIs.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import enrichment


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

def _avp(product: str, version: str, url: str = 'http://target:3000') -> dict:
    return {
        'tool': 'app_version_probe',
        'url': url,
        'endpoint': url + '/version',
        'product': product,
        'version': version,
        'raw_response_snippet': '',
    }


def _nvd_cve(cve_id: str, score: float = 7.5) -> dict:
    return {
        'cve_id':        cve_id,
        'cvss_score':    score,
        'cvss_version':  '3.1',
        'cvss_vector':   f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'cvss_severity': 'high',
        'published':     '2024-01-15',
        'description':   f'Test description for {cve_id}',
        'references':    [f'https://nvd.nist.gov/vuln/detail/{cve_id}'],
    }


def _write_jsonl(path: Path, records: list[dict]):
    with open(path, 'w', encoding='utf-8') as fh:
        for r in records:
            fh.write(json.dumps(r) + '\n')


def _read_jsonl(path: Path) -> list[dict]:
    with open(path, 'r', encoding='utf-8') as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEnrichToJsonl:

    def test_single_cve_produces_one_enrichment_record(self, tmp_path):
        """One fingerprint + one NVD CVE → one new enrichment record appended."""
        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[_nvd_cve('CVE-2024-0001')]), \
             patch.object(enrichment, 'query_epss', return_value={
                 'CVE-2024-0001': {'score': 0.12, 'percentile': 0.75},
             }), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 1
        records = _read_jsonl(out)
        assert len(records) == 2  # 1 original + 1 enrichment

        orig = records[0]
        assert orig['tool'] == 'app_version_probe'

        rec = records[1]
        assert rec['tool'] == 'enrichment'
        assert rec['cve_id'] == 'CVE-2024-0001'
        assert rec['cvss'] == 7.5
        assert rec['cvss_version'] == '3.1'
        assert 'cvss_vector' in rec
        assert rec['epss'] == pytest.approx(0.12)
        assert rec['epss_percentile'] == pytest.approx(0.75)
        assert rec['kev'] is False
        assert rec['product'] == 'juice_shop'
        assert rec['version'] == '15.0.0'
        assert rec['source_fingerprint'] == 'juice_shop:15.0.0'
        assert 'app_version_probe' in rec['source_tools']

    def test_multi_cve_fingerprint_produces_multiple_records(self, tmp_path):
        """When NVD returns N CVEs for a fingerprint, N enrichment records are added."""
        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        cves = [_nvd_cve('CVE-2024-0001'), _nvd_cve('CVE-2024-0002', score=9.8),
                _nvd_cve('CVE-2024-0003', score=4.3)]

        with patch.object(enrichment, 'query_nvd', return_value=cves), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 3
        records = _read_jsonl(out)
        assert len(records) == 4  # 1 original + 3 enrichment

        cve_ids = {r['cve_id'] for r in records if r['tool'] == 'enrichment'}
        assert cve_ids == {'CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'}

    def test_no_cpe_mapping_produces_no_enrichment(self, tmp_path):
        """A fingerprint whose product isn't in _CPE_MAP produces zero enrichment records."""
        findings = [_avp('unknown_product_xyz', '1.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[]) as mock_nvd, \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 0
        mock_nvd.assert_not_called()
        records = _read_jsonl(out)
        assert len(records) == 1  # only the original

    def test_nvd_returns_empty_produces_no_enrichment(self, tmp_path):
        """When NVD returns an empty list, no enrichment records are written."""
        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 0
        records = _read_jsonl(out)
        assert len(records) == 1

    def test_kev_match_sets_flag_and_date(self, tmp_path):
        """CVE present in KEV → kev=True and kev_date_added populated."""
        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[_nvd_cve('CVE-2021-44228')]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog',
                          return_value={'CVE-2021-44228': '2021-12-10'}):
            enrichment.enrich_to_jsonl(inp, out)

        records = _read_jsonl(out)
        rec = next(r for r in records if r.get('tool') == 'enrichment')
        assert rec['kev'] is True
        assert rec['kev_date_added'] == '2021-12-10'

    def test_non_kev_cve_omits_kev_date_added(self, tmp_path):
        """CVE not in KEV → kev=False and kev_date_added absent."""
        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[_nvd_cve('CVE-2024-9999')]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            enrichment.enrich_to_jsonl(inp, out)

        records = _read_jsonl(out)
        rec = next(r for r in records if r.get('tool') == 'enrichment')
        assert rec['kev'] is False
        assert 'kev_date_added' not in rec

    def test_multi_tool_same_fingerprint_accumulates_source_tools(self, tmp_path):
        """When httpx and app_version_probe both identify the same product:version,
        the enrichment record lists both tools in source_tools."""
        findings = [
            {
                'tool': 'httpx',
                'url': 'http://target:3000',
                'status_code': 200,
                'title': 'Juice Shop',
                'technologies': ['juice_shop:15.0.0'],
                'webserver': '',
                'ip': '10.0.0.1',
                'cdn': '',
            },
            _avp('juice_shop', '15.0.0', 'http://target:3000'),
        ]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[_nvd_cve('CVE-2024-0001')]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 1
        records = _read_jsonl(out)
        rec = next(r for r in records if r.get('tool') == 'enrichment')
        # Both tools should be recorded
        assert set(rec['source_tools']) >= {'httpx', 'app_version_probe'}

    def test_epss_failure_still_produces_records(self, tmp_path):
        """If EPSS raises an exception, enrichment continues without EPSS fields."""
        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[_nvd_cve('CVE-2024-0001')]), \
             patch.object(enrichment, 'query_epss', side_effect=RuntimeError('EPSS down')), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 1
        records = _read_jsonl(out)
        rec = next(r for r in records if r.get('tool') == 'enrichment')
        assert 'epss' not in rec
        assert 'epss_percentile' not in rec

    def test_kev_failure_still_produces_records(self, tmp_path):
        """If KEV download fails, enrichment continues with kev=False."""
        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[_nvd_cve('CVE-2024-0001')]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', side_effect=RuntimeError('KEV down')):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 1
        records = _read_jsonl(out)
        rec = next(r for r in records if r.get('tool') == 'enrichment')
        assert rec['kev'] is False

    def test_empty_input_produces_empty_output(self, tmp_path):
        """An empty normalized_findings.jsonl produces an empty enriched_findings.jsonl."""
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        inp.write_text('', encoding='utf-8')

        with patch.object(enrichment, 'query_nvd', return_value=[]) as mock_nvd, \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 0
        mock_nvd.assert_not_called()
        assert out.read_text(encoding='utf-8').strip() == ''

    def test_original_findings_are_unchanged_in_output(self, tmp_path):
        """Every original finding record must pass through to the output file verbatim."""
        original = {
            'tool': 'nmap', 'host': '10.0.0.1', 'port': 443,
            'protocol': 'tcp', 'service': 'https', 'product': '', 'version': '',
        }
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, [original])

        with patch.object(enrichment, 'query_nvd', return_value=[]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            enrichment.enrich_to_jsonl(inp, out)

        records = _read_jsonl(out)
        assert len(records) == 1
        assert records[0] == original

    def test_description_truncated_to_500_chars(self, tmp_path):
        """CVE descriptions longer than 500 chars are truncated."""
        long_desc = 'A' * 600
        cve = {**_nvd_cve('CVE-2024-0001'), 'description': long_desc}

        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[cve]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            enrichment.enrich_to_jsonl(inp, out)

        records = _read_jsonl(out)
        rec = next(r for r in records if r.get('tool') == 'enrichment')
        assert len(rec['cve_description']) <= 500

    def test_no_cvss_fields_omitted(self, tmp_path):
        """When NVD returns a CVE with no CVSS data, cvss/cvss_version/cvss_vector
        are absent from the enrichment record rather than being None/empty."""
        cve = {**_nvd_cve('CVE-2024-0001'), 'cvss_score': None,
               'cvss_version': '', 'cvss_vector': ''}

        findings = [_avp('juice_shop', '15.0.0')]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[cve]), \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            enrichment.enrich_to_jsonl(inp, out)

        records = _read_jsonl(out)
        rec = next(r for r in records if r.get('tool') == 'enrichment')
        assert 'cvss' not in rec
        assert 'cvss_version' not in rec
        assert 'cvss_vector' not in rec

    def test_wpscan_fingerprint_extracted(self, tmp_path):
        """A wpscan finding with a version field produces a wordpress fingerprint."""
        findings = [{
            'tool': 'wpscan',
            'host': 'http://wp-site.example.com',
            'finding_name': 'WordPress 5.9',
            'severity': 'info',
            'description': 'WordPress installation',
            'finding_type': 'interesting_finding',
            'references': {},
            'version': '5.9',
        }]
        inp = tmp_path / 'norm.jsonl'
        out = tmp_path / 'enriched.jsonl'
        _write_jsonl(inp, findings)

        with patch.object(enrichment, 'query_nvd', return_value=[_nvd_cve('CVE-2022-1234')]) as mock_nvd, \
             patch.object(enrichment, 'query_epss', return_value={}), \
             patch.object(enrichment, 'load_kev_catalog', return_value={}):
            count = enrichment.enrich_to_jsonl(inp, out)

        assert count == 1
        # Verify NVD was called with a wordpress CPE
        call_args = mock_nvd.call_args[0][0]
        assert 'wordpress' in call_args

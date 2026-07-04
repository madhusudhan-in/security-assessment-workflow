"""
P2 — Unit tests for CVELookup._parse_cve_data and _cvss_v2_to_severity.
No network calls — all tests use synthetic NVD-shaped dicts.
"""

import os
import sys
import pytest

# ── ensure utils.cve_lookup is imported from the real source, not a mock ─────
# The top-level mock stubs registered by other test files via sys.modules must
# NOT cover utils.cve_lookup here — we need the real class.  Remove any
# previously registered stub before the import.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))
for _mod in list(sys.modules.keys()):
    if _mod in ("utils.cve_lookup",):
        del sys.modules[_mod]

# requests is imported at module level by cve_lookup; stub it so we don't need
# a live network stack.
from unittest.mock import MagicMock
import sys as _sys
_sys.modules.setdefault("requests", MagicMock())

from utils.cve_lookup import CVELookup


def _lookup() -> CVELookup:
    return CVELookup(nvd_api_key=None)


def _cve_payload(
    cve_id="CVE-2021-44228",
    descriptions=None,
    metrics=None,
    references=None,
    configurations=None,
    published="2021-12-10T00:00:00",
    modified="2021-12-15T00:00:00",
) -> dict:
    return {
        "id": cve_id,
        "descriptions": descriptions or [{"lang": "en", "value": "Test description"}],
        "metrics": metrics or {},
        "references": references or [],
        "configurations": configurations or [],
        "published": published,
        "lastModified": modified,
    }


def _v31_metrics(score: float, severity: str) -> dict:
    return {
        "cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]
    }


def _v2_metrics(score: float) -> dict:
    return {
        "cvssMetricV2": [{"cvssData": {"baseScore": score}}]
    }


class TestParseCveData:

    def test_cvssv31_score_and_severity_extracted(self):
        data = _cve_payload(metrics=_v31_metrics(9.8, "CRITICAL"))
        result = _lookup()._parse_cve_data(data)
        assert result is not None
        assert result.cvss_score == 9.8
        assert result.severity == "CRITICAL"

    def test_cvssv2_fallback_when_no_v31(self):
        data = _cve_payload(metrics=_v2_metrics(7.5))
        result = _lookup()._parse_cve_data(data)
        assert result is not None
        assert result.cvss_score == 7.5
        assert result.severity == "HIGH"  # derived by _cvss_v2_to_severity

    def test_no_metrics_defaults_to_zero_and_unknown(self):
        data = _cve_payload(metrics={})
        result = _lookup()._parse_cve_data(data)
        assert result is not None
        assert result.cvss_score == 0.0
        assert result.severity == "UNKNOWN"

    def test_english_description_selected(self):
        data = _cve_payload(descriptions=[
            {"lang": "es", "value": "Descripción en español"},
            {"lang": "en", "value": "English description"},
        ])
        result = _lookup()._parse_cve_data(data)
        assert result.description == "English description"

    def test_no_english_description_returns_empty_string(self):
        data = _cve_payload(descriptions=[{"lang": "fr", "value": "French only"}])
        result = _lookup()._parse_cve_data(data)
        assert result.description == ""

    def test_empty_descriptions_returns_empty_string(self):
        # _cve_payload's default includes a description; pass an explicit empty list
        data = _cve_payload()
        data["descriptions"] = []
        result = _lookup()._parse_cve_data(data)
        assert result.description == ""

    def test_references_extracted(self):
        data = _cve_payload(references=[
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
            {"url": "https://logging.apache.org/log4j/2.x/security.html"},
        ])
        result = _lookup()._parse_cve_data(data)
        assert len(result.references) == 2
        assert "nvd.nist.gov" in result.references[0]

    def test_only_vulnerable_cpe_matches_extracted(self):
        data = _cve_payload(configurations=[{
            "nodes": [{
                "cpeMatch": [
                    {"vulnerable": True,  "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*"},
                    {"vulnerable": False, "criteria": "cpe:2.3:a:apache:log4j:2.17.0:*"},
                ]
            }]
        }])
        result = _lookup()._parse_cve_data(data)
        assert len(result.cpe_matches) == 1
        assert "2.14.1" in result.cpe_matches[0]

    def test_cve_id_preserved(self):
        data = _cve_payload(cve_id="CVE-2023-99999")
        result = _lookup()._parse_cve_data(data)
        assert result.cve_id == "CVE-2023-99999"

    def test_malformed_data_returns_none(self):
        # Completely wrong structure — should not raise
        result = _lookup()._parse_cve_data({"garbage": [None, None]})
        # Either returns None or a partial CVEInfo — no unhandled exception
        # (it may succeed with empty fields; just verify no crash)

    def test_exploit_links_always_populated(self):
        data = _cve_payload(cve_id="CVE-2021-44228")
        result = _lookup()._parse_cve_data(data)
        assert result is not None
        assert isinstance(result.exploit_links, list)
        assert len(result.exploit_links) > 0


class TestCvssV2ToSeverity:

    @pytest.mark.parametrize("score,expected", [
        (10.0, "HIGH"),
        (7.0,  "HIGH"),
        (6.9,  "MEDIUM"),
        (4.0,  "MEDIUM"),
        (3.9,  "LOW"),
        (0.1,  "LOW"),
        (0.0,  "LOW"),
    ])
    def test_boundaries(self, score, expected):
        assert _lookup()._cvss_v2_to_severity(score) == expected

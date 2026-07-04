"""
Unit tests for _normalize_severity and _calculate_risk_score_from_severity.
Pure logic — no I/O, no network.
"""

import os
import sys
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

for _mod in [
    "anthropic", "nmap",
    "tools.nmap_wrapper", "tools.zap_wrapper", "tools.metasploit_wrapper",
    "utils.cve_lookup", "utils.exploit_search",
]:
    sys.modules.setdefault(_mod, MagicMock())

from orchestrator.workflow_engine_improved import WorkflowEngine


def _engine() -> WorkflowEngine:
    e = WorkflowEngine.__new__(WorkflowEngine)
    e.config = {
        "api": {"anthropic_api_key": "x", "model": "x"},
        "safety": {}, "workflow": {}, "tools": {},
    }
    e.config_path = MagicMock()
    return e


class TestNormalizeSeverity:
    """_normalize_severity(severity_str, cvss_score)"""

    # ── label-based ───────────────────────────────────────────────────────────

    @pytest.mark.parametrize("label", ["critical", "CRITICAL", "Critical"])
    def test_critical_label(self, label):
        assert _engine()._normalize_severity(label, 0.0) == "critical"

    @pytest.mark.parametrize("label", ["high", "HIGH"])
    def test_high_label(self, label):
        assert _engine()._normalize_severity(label, 0.0) == "high"

    @pytest.mark.parametrize("label", ["medium", "MEDIUM"])
    def test_medium_label(self, label):
        assert _engine()._normalize_severity(label, 0.0) == "medium"

    @pytest.mark.parametrize("label", ["low", "LOW"])
    def test_low_label(self, label):
        assert _engine()._normalize_severity(label, 0.0) == "low"

    @pytest.mark.parametrize("label", ["info", "INFO"])
    def test_info_label(self, label):
        assert _engine()._normalize_severity(label, 0.0) == "info"

    # ── CVSS fallback ─────────────────────────────────────────────────────────

    def test_cvss_9_returns_critical(self):
        assert _engine()._normalize_severity(None, 9.0) == "critical"

    def test_cvss_10_returns_critical(self):
        assert _engine()._normalize_severity(None, 10.0) == "critical"

    def test_cvss_7_returns_high(self):
        assert _engine()._normalize_severity(None, 7.0) == "high"

    def test_cvss_8_9_returns_high(self):
        assert _engine()._normalize_severity(None, 8.9) == "high"

    def test_cvss_4_returns_medium(self):
        assert _engine()._normalize_severity(None, 4.0) == "medium"

    def test_cvss_6_9_returns_medium(self):
        assert _engine()._normalize_severity(None, 6.9) == "medium"

    def test_cvss_0_1_returns_low(self):
        assert _engine()._normalize_severity(None, 0.1) == "low"

    def test_cvss_3_9_returns_low(self):
        assert _engine()._normalize_severity(None, 3.9) == "low"

    def test_cvss_0_returns_info(self):
        assert _engine()._normalize_severity(None, 0.0) == "info"

    def test_unknown_label_falls_back_to_cvss(self):
        # "UNKNOWN" is not in the known set → uses CVSS score
        assert _engine()._normalize_severity("UNKNOWN", 9.5) == "critical"
        assert _engine()._normalize_severity("UNKNOWN", 5.0) == "medium"

    def test_empty_string_label_falls_back_to_cvss(self):
        assert _engine()._normalize_severity("", 7.5) == "high"


class TestCalculateRiskScore:
    """_calculate_risk_score_from_severity(severity_dict) → float 0–10"""

    def test_no_findings_returns_zero(self):
        score = _engine()._calculate_risk_score_from_severity({})
        assert score == 0.0

    def test_single_critical_nonzero(self):
        score = _engine()._calculate_risk_score_from_severity({"critical": 1})
        assert score > 0

    def test_score_capped_at_ten(self):
        score = _engine()._calculate_risk_score_from_severity(
            {"critical": 100, "high": 100, "medium": 100}
        )
        assert score <= 10.0

    def test_critical_higher_than_medium(self):
        score_crit = _engine()._calculate_risk_score_from_severity({"critical": 1})
        score_med  = _engine()._calculate_risk_score_from_severity({"medium": 1})
        assert score_crit > score_med

    def test_high_higher_than_low(self):
        score_high = _engine()._calculate_risk_score_from_severity({"high": 1})
        score_low  = _engine()._calculate_risk_score_from_severity({"low": 1})
        assert score_high > score_low

    def test_return_type_is_float(self):
        score = _engine()._calculate_risk_score_from_severity({"medium": 3})
        assert isinstance(score, float)

    def test_more_findings_higher_score(self):
        score_few  = _engine()._calculate_risk_score_from_severity({"high": 1})
        score_many = _engine()._calculate_risk_score_from_severity({"high": 5})
        assert score_many > score_few

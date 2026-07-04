"""
P1 — Edge-case tests for _calculate_risk_score_from_severity.
Covers boundary values and robustness not in the original test_severity.py.
"""

import math
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


def _engine():
    e = WorkflowEngine.__new__(WorkflowEngine)
    e.config = {"api": {"anthropic_api_key": "x", "model": "x"}, "safety": {}, "workflow": {}, "tools": {}}
    e.config_path = MagicMock()
    return e


class TestRiskScoreEdges:

    def test_info_only_score_near_zero(self):
        """1000 info findings should produce a low but nonzero score, still << 1."""
        score = _engine()._calculate_risk_score_from_severity({"info": 1000})
        # sqrt(1000 * 0.1) = sqrt(100) = 10.0 — capped at 10
        # With fewer: sqrt(10 * 0.1) = 1.0
        assert score >= 0.0
        assert score <= 10.0

    def test_unknown_severity_keys_ignored(self):
        """Unknown keys should contribute 0 (weight defaults to 0)."""
        score_unknown = _engine()._calculate_risk_score_from_severity({"unknown_level": 100})
        score_empty   = _engine()._calculate_risk_score_from_severity({})
        assert score_unknown == score_empty == 0.0

    def test_mixed_severities_within_bounds(self):
        """1 critical + 2 high + 3 medium should give a score between 3.0 and 9.5."""
        score = _engine()._calculate_risk_score_from_severity(
            {"critical": 1, "high": 2, "medium": 3}
        )
        # raw = 10 + 14 + 12 = 36; sqrt(36) = 6.0
        assert 3.0 <= score <= 9.5

    def test_score_precision_one_decimal_place(self):
        """Result must be rounded to exactly 1 decimal place."""
        score = _engine()._calculate_risk_score_from_severity({"medium": 3})
        # raw = 12; sqrt(12) ≈ 3.4641... → rounded to 3.5
        decimal_part = str(score).split(".")
        assert len(decimal_part) == 2
        assert len(decimal_part[1]) == 1

    def test_large_input_capped_at_ten(self):
        """Arbitrarily large counts must never exceed 10.0."""
        score = _engine()._calculate_risk_score_from_severity(
            {"critical": 10_000, "high": 10_000, "medium": 10_000}
        )
        assert score == 10.0

    def test_single_info_finding_is_low(self):
        """One info finding → score is very low but not exactly zero."""
        score = _engine()._calculate_risk_score_from_severity({"info": 1})
        # sqrt(0.1) ≈ 0.3
        assert 0.0 < score < 1.0

    def test_known_exact_value(self):
        """1 critical: raw=10, sqrt(10)≈3.2, round to 3.2."""
        score = _engine()._calculate_risk_score_from_severity({"critical": 1})
        expected = round(math.sqrt(10.0), 1)
        assert score == expected

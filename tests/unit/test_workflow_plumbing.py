"""
P3 — Unit tests for _generate_workflow_id, _get_risk_level,
     WorkflowResult.to_markdown edge cases, and _extract_recommendations.
"""

import hashlib
import os
import sys
import tempfile
import time
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

for _mod in [
    "anthropic", "nmap",
    "tools.nmap_wrapper", "tools.zap_wrapper", "tools.metasploit_wrapper",
    "utils.cve_lookup", "utils.exploit_search",
]:
    sys.modules.setdefault(_mod, MagicMock())

from orchestrator.workflow_engine_improved import (
    WorkflowEngine, WorkflowResult, RiskLevel,
)


def _engine():
    e = WorkflowEngine.__new__(WorkflowEngine)
    e.config = {"api": {"anthropic_api_key": "x", "model": "x"}, "safety": {}, "workflow": {}, "tools": {}}
    e.config_path = MagicMock()
    return e


def _result(**kw):
    defaults = dict(
        workflow_id="wf_001", target="10.0.0.1",
        start_time="2024-01-01T00:00:00", end_time="2024-01-01T00:05:00",
        duration_seconds=300.0, stages_completed=["reconnaissance"],
        findings={}, recommendations=[], risk_score=5.0,
        risk_level="MEDIUM", summary="Test summary.",
    )
    defaults.update(kw)
    return WorkflowResult(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# _generate_workflow_id
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateWorkflowId:

    def test_id_starts_with_workflow_prefix(self):
        wid = _engine()._generate_workflow_id("10.0.0.1")
        assert wid.startswith("workflow_")

    def test_id_contains_target_hash(self):
        target = "192.168.1.10"
        expected_hash = hashlib.md5(target.encode()).hexdigest()[:8]
        wid = _engine()._generate_workflow_id(target)
        assert wid.endswith(expected_hash)

    def test_different_targets_produce_different_ids(self):
        e = _engine()
        id1 = e._generate_workflow_id("10.0.0.1")
        id2 = e._generate_workflow_id("10.0.0.2")
        # hashes differ
        assert id1[-8:] != id2[-8:]

    def test_same_target_produces_same_hash_suffix(self):
        e = _engine()
        id1 = e._generate_workflow_id("10.0.0.1")
        id2 = e._generate_workflow_id("10.0.0.1")
        # hash part is deterministic
        assert id1[-8:] == id2[-8:]

    def test_successive_calls_differ_by_timestamp(self):
        e = _engine()
        id1 = e._generate_workflow_id("10.0.0.1")
        time.sleep(1.1)  # ensure different second
        id2 = e._generate_workflow_id("10.0.0.1")
        # timestamps differ (middle segment)
        assert id1 != id2


# ─────────────────────────────────────────────────────────────────────────────
# _get_risk_level
# ─────────────────────────────────────────────────────────────────────────────

class TestGetRiskLevel:

    @pytest.mark.parametrize("score,expected", [
        (10.0, RiskLevel.CRITICAL),
        (9.0,  RiskLevel.CRITICAL),
        (8.9,  RiskLevel.HIGH),
        (7.0,  RiskLevel.HIGH),
        (6.9,  RiskLevel.MEDIUM),
        (4.0,  RiskLevel.MEDIUM),
        (3.9,  RiskLevel.LOW),
        (0.1,  RiskLevel.LOW),
        (0.0,  RiskLevel.INFO),
    ])
    def test_threshold_boundaries(self, score, expected):
        assert _engine()._get_risk_level(score) == expected

    def test_returns_risk_level_enum(self):
        result = _engine()._get_risk_level(5.0)
        assert isinstance(result, RiskLevel)


# ─────────────────────────────────────────────────────────────────────────────
# WorkflowResult.to_markdown edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestToMarkdownEdges:

    def test_zero_recommendations_no_crash(self):
        r = _result(recommendations=[])
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            name = f.name
        try:
            r.to_markdown(name)  # must not raise
            content = open(name).read()
            assert "## Recommendations" in content
        finally:
            os.unlink(name)

    def test_special_chars_in_summary_written_as_is(self):
        r = _result(summary="Risk: 5 < 7 & result > 0")
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            name = f.name
        try:
            r.to_markdown(name)
            content = open(name).read()
            assert "5 < 7 & result > 0" in content
        finally:
            os.unlink(name)

    def test_many_recommendations_all_written(self):
        recs = [f"Fix issue {i}" for i in range(10)]
        r = _result(recommendations=recs)
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            name = f.name
        try:
            r.to_markdown(name)
            content = open(name).read()
            for i, rec in enumerate(recs, 1):
                assert f"{i}. {rec}" in content
        finally:
            os.unlink(name)

    def test_errors_list_in_json_roundtrip(self):
        import json
        from dataclasses import asdict
        r = _result(errors=["stage timeout", "ZAP unavailable"])
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            name = f.name
        try:
            r.to_json(name)
            data = json.load(open(name))
            assert data["errors"] == ["stage timeout", "ZAP unavailable"]
        finally:
            os.unlink(name)


# ─────────────────────────────────────────────────────────────────────────────
# _extract_recommendations
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractRecommendations:

    def test_numbered_items_extracted(self):
        text = "Recommendations:\n1. Patch Apache\n2. Close port 22\n3. Enable MFA"
        recs = _engine()._extract_recommendations(text)
        assert any("Patch Apache" in r for r in recs)
        assert any("Close port 22" in r for r in recs)

    def test_bulleted_items_extracted(self):
        text = "Mitigation steps:\n- Update OpenSSL\n- Restrict SSH access"
        recs = _engine()._extract_recommendations(text)
        assert any("Update OpenSSL" in r for r in recs)

    def test_max_ten_returned(self):
        items = "\n".join(f"- Fix issue {i} with a detailed description here" for i in range(20))
        text = f"Remediation:\n{items}"
        recs = _engine()._extract_recommendations(text)
        assert len(recs) <= 10

    def test_empty_text_returns_empty_list(self):
        assert _engine()._extract_recommendations("") == []

    def test_very_short_items_filtered(self):
        text = "Recommendations:\n- Ok\n- Patch the critical Apache HTTP Server vulnerability now"
        recs = _engine()._extract_recommendations(text)
        # "Ok" is too short (< 10 chars) — should not appear
        assert not any(r == "Ok" for r in recs)

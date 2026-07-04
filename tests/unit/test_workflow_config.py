"""
Unit tests for WorkflowConfig and WorkflowResult dataclasses.
No I/O, no network, no AI calls.
"""

import json
import os
import sys
import tempfile

import pytest

# ── path bootstrap ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

from unittest.mock import MagicMock, patch

# Stub heavy imports so the module loads without real credentials / tools
for _mod in [
    "anthropic",
    "nmap",
    "tools.nmap_wrapper",
    "tools.zap_wrapper",
    "tools.metasploit_wrapper",
    "utils.cve_lookup",
    "utils.exploit_search",
]:
    sys.modules.setdefault(_mod, MagicMock())

from orchestrator.workflow_engine_improved import (
    WorkflowConfig,
    WorkflowMode,
    WorkflowResult,
    WorkflowStage,
)


# ─────────────────────────────────────────────────────────────────────────────
# WorkflowConfig
# ─────────────────────────────────────────────────────────────────────────────

class TestWorkflowConfig:
    def _make(self, **kw):
        defaults = dict(
            target="192.168.1.1",
            mode=WorkflowMode.FULL,
            stages=[WorkflowStage.RECONNAISSANCE, WorkflowStage.REPORTING],
        )
        defaults.update(kw)
        return WorkflowConfig(**defaults)

    def test_valid_creation(self):
        cfg = self._make()
        assert cfg.target == "192.168.1.1"
        assert cfg.mode == WorkflowMode.FULL
        assert cfg.auto_exploit is False

    def test_string_mode_coerced_to_enum(self):
        cfg = self._make(mode="quick")
        assert cfg.mode == WorkflowMode.QUICK

    def test_string_stages_coerced_to_enum(self):
        cfg = self._make(stages=["reconnaissance", "reporting"])
        assert WorkflowStage.RECONNAISSANCE in cfg.stages
        assert WorkflowStage.REPORTING in cfg.stages

    def test_empty_target_raises(self):
        with pytest.raises(ValueError, match="Target cannot be empty"):
            self._make(target="")

    def test_max_concurrent_below_one_raises(self):
        with pytest.raises(ValueError, match="max_concurrent must be at least 1"):
            self._make(max_concurrent=0)

    def test_timeout_too_short_raises(self):
        with pytest.raises(ValueError, match="timeout must be at least 60"):
            self._make(timeout=10)

    def test_defaults(self):
        cfg = self._make()
        assert cfg.max_concurrent == 3
        assert cfg.timeout == 7200
        assert cfg.retry_attempts == 3
        assert cfg.rate_limit == 60


# ─────────────────────────────────────────────────────────────────────────────
# WorkflowResult serialisation
# ─────────────────────────────────────────────────────────────────────────────

class TestWorkflowResult:
    def _make_result(self, **kw):
        defaults = dict(
            workflow_id="wf_test_001",
            target="10.0.0.1",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:05:00",
            duration_seconds=300.0,
            stages_completed=["reconnaissance", "reporting"],
            findings={"reconnaissance": {"open_ports": [{"port": 80}]}},
            recommendations=["Patch Apache", "Close port 22"],
            risk_score=6.5,
            risk_level="HIGH",
            summary="Two medium issues found.",
        )
        defaults.update(kw)
        return WorkflowResult(**defaults)

    def test_to_json_roundtrip(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            name = f.name
        try:
            result.to_json(name)
            with open(name) as f:
                data = json.load(f)
            assert data["workflow_id"] == "wf_test_001"
            assert data["risk_score"] == 6.5
            assert data["recommendations"] == ["Patch Apache", "Close port 22"]
            assert data["findings"]["reconnaissance"]["open_ports"][0]["port"] == 80
        finally:
            os.unlink(name)

    def test_to_markdown_structure(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            name = f.name
        try:
            result.to_markdown(name)
            content = open(name).read()
            assert "# Security Assessment Report" in content
            assert "wf_test_001" in content
            assert "6.5/10" in content
            assert "1. Patch Apache" in content
            assert "2. Close port 22" in content
            assert "Two medium issues found." in content
        finally:
            os.unlink(name)

    def test_errors_default_empty_list(self):
        result = self._make_result()
        assert result.errors == []

    def test_metadata_default_empty_dict(self):
        result = self._make_result()
        assert result.metadata == {}

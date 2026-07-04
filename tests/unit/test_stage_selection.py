"""
Unit tests for _get_stages_for_mode — the exploitation gate logic.

Key invariants:
- quick  → recon + reporting only, never exploitation
- full   → recon + vuln + reporting, never exploitation
- aggressive + auto_exploit=False  → no exploitation
- aggressive + auto_exploit=True   → includes exploitation
- custom → exact stages requested
- unknown mode → falls back to full
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

from orchestrator.workflow_engine_improved import WorkflowEngine, WorkflowStage


def _engine() -> WorkflowEngine:
    engine = WorkflowEngine.__new__(WorkflowEngine)
    engine.config = {
        "api": {"anthropic_api_key": "test", "model": "x"},
        "safety": {}, "workflow": {}, "tools": {},
    }
    engine.config_path = MagicMock()
    return engine


class TestGetStagesForMode:

    # ── quick ─────────────────────────────────────────────────────────────────

    def test_quick_has_recon_and_reporting(self):
        stages = _engine()._get_stages_for_mode("quick")
        assert WorkflowStage.RECONNAISSANCE in stages
        assert WorkflowStage.REPORTING in stages

    def test_quick_has_no_exploitation(self):
        stages = _engine()._get_stages_for_mode("quick")
        assert WorkflowStage.EXPLOITATION not in stages

    def test_quick_has_no_vuln_assessment(self):
        stages = _engine()._get_stages_for_mode("quick")
        assert WorkflowStage.VULNERABILITY_ASSESSMENT not in stages

    # ── full ──────────────────────────────────────────────────────────────────

    def test_full_has_vuln_assessment(self):
        stages = _engine()._get_stages_for_mode("full")
        assert WorkflowStage.VULNERABILITY_ASSESSMENT in stages

    def test_full_has_no_exploitation(self):
        stages = _engine()._get_stages_for_mode("full")
        assert WorkflowStage.EXPLOITATION not in stages

    def test_full_stage_order(self):
        stages = _engine()._get_stages_for_mode("full")
        assert stages.index(WorkflowStage.RECONNAISSANCE) < stages.index(WorkflowStage.VULNERABILITY_ASSESSMENT)
        assert stages.index(WorkflowStage.VULNERABILITY_ASSESSMENT) < stages.index(WorkflowStage.REPORTING)

    # ── aggressive gate ───────────────────────────────────────────────────────

    def test_aggressive_without_auto_exploit_no_exploitation(self):
        stages = _engine()._get_stages_for_mode("aggressive", auto_exploit=False)
        assert WorkflowStage.EXPLOITATION not in stages

    def test_aggressive_with_auto_exploit_includes_exploitation(self):
        stages = _engine()._get_stages_for_mode("aggressive", auto_exploit=True)
        assert WorkflowStage.EXPLOITATION in stages

    def test_aggressive_auto_exploit_stage_order(self):
        stages = _engine()._get_stages_for_mode("aggressive", auto_exploit=True)
        assert stages.index(WorkflowStage.VULNERABILITY_ASSESSMENT) < stages.index(WorkflowStage.EXPLOITATION)
        assert stages.index(WorkflowStage.EXPLOITATION) < stages.index(WorkflowStage.REPORTING)

    def test_aggressive_no_auto_exploit_still_has_recon(self):
        stages = _engine()._get_stages_for_mode("aggressive", auto_exploit=False)
        assert WorkflowStage.RECONNAISSANCE in stages
        assert WorkflowStage.VULNERABILITY_ASSESSMENT in stages
        assert WorkflowStage.REPORTING in stages

    # ── custom stages ─────────────────────────────────────────────────────────

    def test_custom_exact_stages_returned(self):
        custom = ["reconnaissance", "reporting"]
        stages = _engine()._get_stages_for_mode("custom", custom_stages=custom)
        assert stages == [WorkflowStage.RECONNAISSANCE, WorkflowStage.REPORTING]

    def test_custom_exploitation_only_when_explicitly_requested(self):
        custom = ["reconnaissance", "exploitation", "reporting"]
        stages = _engine()._get_stages_for_mode("custom", custom_stages=custom)
        assert WorkflowStage.EXPLOITATION in stages

    def test_custom_mode_without_stages_falls_back_to_full(self):
        # custom mode with no custom_stages list → fall back
        stages = _engine()._get_stages_for_mode("custom", custom_stages=None)
        assert WorkflowStage.VULNERABILITY_ASSESSMENT in stages
        assert WorkflowStage.EXPLOITATION not in stages

    # ── unknown mode fallback ─────────────────────────────────────────────────

    def test_unknown_mode_falls_back_to_full(self):
        stages = _engine()._get_stages_for_mode("nonexistent_mode")
        assert WorkflowStage.VULNERABILITY_ASSESSMENT in stages
        assert WorkflowStage.EXPLOITATION not in stages

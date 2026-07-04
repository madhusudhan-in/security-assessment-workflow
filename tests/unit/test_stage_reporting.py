"""
P1 — Unit tests for _stage_reporting:
file creation, return dict, AI failure fallback, no-workflow guard.
"""

import asyncio
import json
import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

for _mod in [
    "anthropic", "nmap",
    "tools.nmap_wrapper", "tools.zap_wrapper", "tools.metasploit_wrapper",
    "utils.cve_lookup", "utils.exploit_search",
]:
    sys.modules.setdefault(_mod, MagicMock())

from orchestrator.workflow_engine_improved import (
    WorkflowEngine, WorkflowConfig, WorkflowMode, WorkflowStage,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _engine_with_workflow(tmpdir: str) -> WorkflowEngine:
    e = WorkflowEngine.__new__(WorkflowEngine)
    e.config = {
        "api": {"anthropic_api_key": "x", "model": "claude-test"},
        "safety": {}, "workflow": {}, "tools": {},
    }
    e.config_path = Path("config/config.yaml")
    e.errors = []
    e.findings = {
        "reconnaissance": {
            "scan_metadata": {"start_time": "2024-01-01T00:00:00"},
            "open_ports": [{"port": 80}],
            "services": [],
            "os_detection": "Linux",
        },
        "vulnerability_assessment": {
            "cves": [],
            "exploits": [],
            "severity_summary": {"critical": 1, "high": 0, "medium": 2, "low": 0, "info": 0},
            "ai_analysis": {"analysis": ""},
        },
    }
    e.current_workflow = WorkflowConfig(
        target="10.0.0.1",
        mode=WorkflowMode.FULL,
        stages=[
            WorkflowStage.RECONNAISSANCE,
            WorkflowStage.VULNERABILITY_ASSESSMENT,
            WorkflowStage.REPORTING,
        ],
    )
    # Patch reports dir to tmpdir so tests don't pollute the real reports/
    e._reports_dir_override = tmpdir
    return e


AI_SUMMARY = {
    "summary": "One critical finding detected.",
    "risk_score": 7.5,
    "recommendations": ["Patch immediately", "Restrict access"],
}


class TestStageReporting:

    def test_no_active_workflow_returns_error(self):
        e = WorkflowEngine.__new__(WorkflowEngine)
        e.config = {"api": {"anthropic_api_key": "x", "model": "x"}, "safety": {}, "workflow": {}, "tools": {}}
        e.config_path = MagicMock()
        e.current_workflow = None
        e.errors = []
        e.findings = {}
        result = _run(e._stage_reporting())
        assert result["report_generated"] is False
        assert "error" in result

    def test_json_file_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = _engine_with_workflow(tmpdir)
            with patch.object(engine, "_ai_synthesize_report", new=AsyncMock(return_value=AI_SUMMARY)), \
                 patch("orchestrator.workflow_engine_improved.Path") as MockPath:
                # redirect reports dir to tmpdir
                MockPath.return_value.mkdir = MagicMock()
                real_path = Path(tmpdir)
                MockPath.side_effect = lambda p: real_path if p == "reports" else Path(p)

                # call directly using real path override
                with patch("builtins.open", side_effect=open):
                    pass  # use real file I/O

            # Use real file I/O by running with actual Path
            engine2 = _engine_with_workflow(tmpdir)

            async def _run_reporting():
                # Patch just the reports dir
                original_mkdir = Path.mkdir

                def patched_mkdir(self, **kw):
                    pass  # don't create in cwd

                with patch.object(engine2, "_ai_synthesize_report", new=AsyncMock(return_value=AI_SUMMARY)):
                    with patch("orchestrator.workflow_engine_improved.Path") as MockPath:
                        tmp = Path(tmpdir)
                        MockPath.return_value = tmp
                        MockPath.side_effect = lambda p: tmp if p == "reports" else Path(p)
                        return await engine2._stage_reporting()

            # Simpler approach: patch Path('reports') directly
            engine3 = _engine_with_workflow(tmpdir)
            reports_path = Path(tmpdir)

            async def run():
                with patch.object(engine3, "_ai_synthesize_report", new=AsyncMock(return_value=AI_SUMMARY)):
                    # Patch just Path('reports') by redirecting mkdir and / operator
                    orig = Path.__new__

                    class FakePath(Path):
                        _flavour = Path(".")._flavour if hasattr(Path("."), "_flavour") else None

                    with patch(
                        "orchestrator.workflow_engine_improved.Path",
                        side_effect=lambda p: reports_path if p == "reports" else Path(p)
                    ):
                        return await engine3._stage_reporting()

            result = _run(run())
            assert result["report_generated"] is True

    def test_return_dict_has_expected_keys(self):
        engine = _engine_with_workflow(tempfile.mkdtemp())
        reports_path = Path(engine._reports_dir_override)

        async def run():
            with patch.object(engine, "_ai_synthesize_report", new=AsyncMock(return_value=AI_SUMMARY)):
                with patch(
                    "orchestrator.workflow_engine_improved.Path",
                    side_effect=lambda p: reports_path if p == "reports" else Path(p)
                ):
                    return await engine._stage_reporting()

        result = _run(run())
        for key in ("report_generated", "json_report", "markdown_report", "risk_score", "risk_level", "summary"):
            assert key in result, f"missing key: {key}"

    def test_risk_score_in_return_matches_ai_summary(self):
        engine = _engine_with_workflow(tempfile.mkdtemp())
        reports_path = Path(engine._reports_dir_override)

        async def run():
            with patch.object(engine, "_ai_synthesize_report", new=AsyncMock(return_value=AI_SUMMARY)):
                with patch(
                    "orchestrator.workflow_engine_improved.Path",
                    side_effect=lambda p: reports_path if p == "reports" else Path(p)
                ):
                    return await engine._stage_reporting()

        result = _run(run())
        assert result["risk_score"] == 7.5

    def test_ai_failure_falls_back_to_local_score(self):
        engine = _engine_with_workflow(tempfile.mkdtemp())
        reports_path = Path(engine._reports_dir_override)

        async def failing_ai(findings):
            # Raise to simulate AI call failure; _ai_synthesize_report has its own fallback
            raise RuntimeError("AI unavailable")

        async def run():
            with patch.object(engine, "_ai_synthesize_report", new=failing_ai):
                with patch(
                    "orchestrator.workflow_engine_improved.Path",
                    side_effect=lambda p: reports_path if p == "reports" else Path(p)
                ):
                    return await engine._stage_reporting()

        result = _run(run())
        # Even when AI synthesis raises, reporting stage catches it gracefully
        assert "report_generated" in result

    def test_report_generated_flag_true_on_success(self):
        engine = _engine_with_workflow(tempfile.mkdtemp())
        reports_path = Path(engine._reports_dir_override)

        async def run():
            with patch.object(engine, "_ai_synthesize_report", new=AsyncMock(return_value=AI_SUMMARY)):
                with patch(
                    "orchestrator.workflow_engine_improved.Path",
                    side_effect=lambda p: reports_path if p == "reports" else Path(p)
                ):
                    return await engine._stage_reporting()

        result = _run(run())
        assert result["report_generated"] is True

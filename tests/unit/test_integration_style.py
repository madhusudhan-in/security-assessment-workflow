"""
P4 — Integration-style tests (all external I/O mocked).
Tests cross-method interactions: auth fired before stages, rate-limit sleep,
duplicate log handler prevention.
"""

import asyncio
import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

for _mod in [
    "anthropic", "nmap",
    "tools.nmap_wrapper", "tools.zap_wrapper", "tools.metasploit_wrapper",
    "utils.cve_lookup", "utils.exploit_search",
]:
    sys.modules.setdefault(_mod, MagicMock())

from orchestrator.workflow_engine_improved import (
    WorkflowEngine, WorkflowEngineError, setup_logging,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ─────────────────────────────────────────────────────────────────────────────
# Auth check fires before any stage in run_workflow
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthBeforeStages:

    def _minimal_engine(self) -> WorkflowEngine:
        e = WorkflowEngine.__new__(WorkflowEngine)
        e.config = {
            "api": {"anthropic_api_key": "x", "model": "x"},
            "safety": {"authorization_file": "/nonexistent/path.txt"},
            "workflow": {"auto_exploit": False, "max_concurrent_scans": 1, "timeout": 7200, "retry_attempts": 1},
            "tools": {},
        }
        e.config_path = Path("config/config.yaml")
        e._nmap = MagicMock()
        e._cve_lookup = MagicMock()
        e._exploit_search = MagicMock()
        e._zap = MagicMock()
        e._msf = MagicMock()
        e.ai_client = MagicMock()
        e.current_workflow = None
        e.findings = {}
        e.errors = []
        e._last_ai_call = __import__("datetime").datetime.now()
        e._ai_call_count = 0
        return e

    def test_unauthorized_target_raises_before_recon(self):
        engine = self._minimal_engine()
        stage_recon_called = {"called": False}

        async def fake_recon(target):
            stage_recon_called["called"] = True
            return {}

        engine._stage_reconnaissance = fake_recon

        with pytest.raises(WorkflowEngineError, match="not in the authorization file"):
            _run(engine.run_workflow("1.2.3.4", mode="quick"))

        assert not stage_recon_called["called"], \
            "_stage_reconnaissance was called despite failed authorization"

    def test_authorized_target_proceeds_to_recon(self):
        engine = self._minimal_engine()

        # Patch auth to pass
        engine._check_authorization = MagicMock(return_value=True)

        recon_called = {"called": False}

        async def fake_recon(target):
            recon_called["called"] = True
            return {
                "open_ports": [], "services": [], "os_detection": None,
                "nse_scripts": None, "nmap_scan": None,
                "scan_metadata": {
                    "start_time": __import__("datetime").datetime.now().isoformat(),
                    "target": target,
                }
            }

        async def fake_ai_decide(results):
            return {"recommendations": "", "priority_services": [], "timestamp": ""}

        async def fake_reporting():
            return {"report_generated": True, "timestamp": ""}

        engine._stage_reconnaissance = fake_recon
        engine._ai_decide_next_steps = fake_ai_decide
        engine._stage_reporting = fake_reporting
        engine._ai_analysis = AsyncMock(return_value={"risk_score": 0, "recommendations": [], "summary": ""})

        _run(engine.run_workflow("10.0.0.1", mode="quick"))
        assert recon_called["called"]


# ─────────────────────────────────────────────────────────────────────────────
# CVE batch_lookup rate-limit sleep
# ─────────────────────────────────────────────────────────────────────────────

class TestCVEBatchRateLimitSleep:

    def test_sleep_called_once_per_service(self):
        # Remove the mock stub to get the real CVELookup
        for _mod in list(sys.modules.keys()):
            if _mod == "utils.cve_lookup":
                del sys.modules[_mod]
        sys.modules.setdefault("requests", MagicMock())
        from utils.cve_lookup import CVELookup

        lookup = CVELookup(nvd_api_key=None)

        services = [
            {"product": "Apache HTTP Server", "version": "2.4.49"},
            {"product": "OpenSSH", "version": "7.9"},
            {"product": "nginx", "version": "1.18.0"},
        ]

        import utils.cve_lookup as cve_mod
        with patch.object(lookup, "search_by_product", return_value=[]), \
             patch.object(cve_mod.time, "sleep") as mock_sleep:
            lookup.batch_lookup(services)

        assert mock_sleep.call_count == len(services)
        for c in mock_sleep.call_args_list:
            assert c == call(0.6)

    def test_service_without_product_or_version_skipped(self):
        for _mod in list(sys.modules.keys()):
            if _mod == "utils.cve_lookup":
                del sys.modules[_mod]
        sys.modules.setdefault("requests", MagicMock())
        from utils.cve_lookup import CVELookup

        lookup = CVELookup(nvd_api_key=None)

        # Service with empty product/version is skipped (falsy guard).
        # Only the service with non-empty product+version should trigger a lookup.
        services = [
            {"product": "", "version": ""},          # skipped — empty product
            {"product": "Apache", "version": "2.4"},  # looked up
        ]

        import utils.cve_lookup as cve_mod
        with patch.object(lookup, "search_by_product", return_value=[]) as mock_search, \
             patch.object(cve_mod.time, "sleep"):
            lookup.batch_lookup(services)

        assert mock_search.call_count == 1


# ─────────────────────────────────────────────────────────────────────────────
# setup_logging — duplicate handler prevention
# ─────────────────────────────────────────────────────────────────────────────

class TestSetupLogging:

    def test_second_call_does_not_add_duplicate_handlers(self):
        import logging
        # Clear any existing handlers on the module logger
        logger = logging.getLogger("orchestrator.workflow_engine_improved")
        logger.handlers.clear()

        logger1 = setup_logging("INFO")
        count_after_first = len(logger1.handlers)

        logger2 = setup_logging("INFO")
        count_after_second = len(logger2.handlers)

        assert count_after_second == count_after_first, \
            "Calling setup_logging twice added duplicate handlers"

    def test_file_handler_created_when_log_file_specified(self):
        import logging
        from logging.handlers import RotatingFileHandler

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "test.log")

            # Get a fresh logger name to avoid shared state
            logger_name = f"test_logger_{os.urandom(4).hex()}"
            with patch("orchestrator.workflow_engine_improved.logging") as mock_logging:
                import logging as real_logging
                mock_logger = real_logging.getLogger(logger_name)
                mock_logger.handlers.clear()
                mock_logging.getLogger.return_value = mock_logger
                mock_logging.StreamHandler = real_logging.StreamHandler
                mock_logging.Formatter = real_logging.Formatter
                mock_logging.INFO = real_logging.INFO

                setup_logging("INFO", log_file=log_path)

            assert any(isinstance(h, RotatingFileHandler) for h in mock_logger.handlers)

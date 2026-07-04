"""
Unit tests for _web_application_scan ZAP gate logic.
Verifies that ZAP is skipped when not configured, and invoked correctly when it is.
"""

import asyncio
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

for _mod in [
    "anthropic", "nmap",
    "tools.nmap_wrapper", "tools.zap_wrapper", "tools.metasploit_wrapper",
    "utils.cve_lookup", "utils.exploit_search",
]:
    sys.modules.setdefault(_mod, MagicMock())

from orchestrator.workflow_engine_improved import WorkflowEngine


def _engine_with_zap_config(enabled: bool, api_key: str = "testkey") -> WorkflowEngine:
    engine = WorkflowEngine.__new__(WorkflowEngine)
    engine.config = {
        "api": {"anthropic_api_key": "x", "model": "x"},
        "safety": {}, "workflow": {}, "tools": {
            "zap": {
                "enabled": enabled,
                "api_key": api_key,
                "proxy_host": "localhost",
                "proxy_port": 8080,
            }
        },
    }
    engine.config_path = MagicMock()
    return engine


HTTP_PORT = {"port": 80, "service": "http"}
HTTPS_PORT = {"port": 443, "service": "https"}


class TestWebApplicationScan:

    def test_zap_not_enabled_returns_empty(self):
        engine = _engine_with_zap_config(enabled=False)
        result = asyncio.get_event_loop().run_until_complete(
            engine._web_application_scan("10.0.0.1", [HTTP_PORT])
        )
        assert result == []

    def test_zap_no_api_key_returns_empty(self):
        engine = _engine_with_zap_config(enabled=True, api_key="")
        result = asyncio.get_event_loop().run_until_complete(
            engine._web_application_scan("10.0.0.1", [HTTP_PORT])
        )
        assert result == []

    def test_zap_no_ports_returns_empty(self):
        engine = _engine_with_zap_config(enabled=True)
        # Patch ZAPWrapper so it's not instantiated against a real ZAP
        with patch("tools.zap_wrapper.ZAPWrapper"):
            result = asyncio.get_event_loop().run_until_complete(
                engine._web_application_scan("10.0.0.1", [])
            )
        assert result == []

    def test_http_port_uses_http_scheme(self):
        engine = _engine_with_zap_config(enabled=True)
        captured_urls = []

        mock_alert = MagicMock()
        mock_alert.url = "http://10.0.0.1:80/"
        mock_alert.name = "XSS"
        mock_alert.risk = "High"
        mock_alert.confidence = "Medium"
        mock_alert.description = "Cross-site scripting"
        mock_alert.solution = "Sanitize input"
        mock_alert.cwe_id = "79"
        mock_alert.wasc_id = "8"
        mock_alert.param = "q"
        mock_alert.evidence = "<script>"

        mock_result = MagicMock()
        mock_result.alerts = [mock_alert]

        mock_zap = MagicMock()
        mock_zap.full_scan.return_value = mock_result

        with patch("tools.zap_wrapper.ZAPWrapper", return_value=mock_zap):
            result = asyncio.get_event_loop().run_until_complete(
                engine._web_application_scan("10.0.0.1", [HTTP_PORT])
            )

        assert len(result) == 1
        assert result[0]["name"] == "XSS"
        assert result[0]["port"] == 80
        # verify the URL passed to full_scan started with http://
        call_url = mock_zap.full_scan.call_args[0][0]
        assert call_url.startswith("http://")

    def test_https_port_uses_https_scheme(self):
        engine = _engine_with_zap_config(enabled=True)

        mock_result = MagicMock()
        mock_result.alerts = []
        mock_zap = MagicMock()
        mock_zap.full_scan.return_value = mock_result

        with patch("tools.zap_wrapper.ZAPWrapper", return_value=mock_zap):
            asyncio.get_event_loop().run_until_complete(
                engine._web_application_scan("10.0.0.1", [HTTPS_PORT])
            )

        call_url = mock_zap.full_scan.call_args[0][0]
        assert call_url.startswith("https://")

    def test_zap_exception_handled_gracefully(self):
        engine = _engine_with_zap_config(enabled=True)

        mock_zap = MagicMock()
        mock_zap.full_scan.side_effect = ConnectionError("ZAP not running")

        with patch("tools.zap_wrapper.ZAPWrapper", return_value=mock_zap):
            # Should not raise — exception is caught and logged
            result = asyncio.get_event_loop().run_until_complete(
                engine._web_application_scan("10.0.0.1", [HTTP_PORT])
            )

        assert result == []

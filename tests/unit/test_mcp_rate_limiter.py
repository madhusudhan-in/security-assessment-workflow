"""
Unit tests for the MCP server rate-limiter logic.
Tests the _check_rate_limit function in each server module in isolation —
no actual MCP server is started.
"""

import importlib
import os
import sys
import time
import types
import pytest
from collections import deque
from unittest.mock import MagicMock

# ── stub all heavy deps before any server import ──────────────────────────────
for _mod in [
    "mcp", "mcp.server", "mcp.types", "mcp.server.stdio",
    "nmap",
    "tools.nmap_wrapper", "tools.zap_wrapper", "tools.metasploit_wrapper",
    "utils.cve_lookup", "utils.exploit_search",
    "anthropic",
]:
    sys.modules.setdefault(_mod, MagicMock())

# Stub mcp.server.Server so the module-level `app = Server(...)` doesn't crash
_mcp_server = sys.modules["mcp.server"]
_mcp_server.Server = MagicMock(return_value=MagicMock())
_mcp_types = sys.modules["mcp.types"]
_mcp_types.Tool = MagicMock()
_mcp_types.TextContent = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))


def _load_rate_limiter(env_var: str, server_file: str, limit: int = 3):
    """
    Load _check_rate_limit and _request_timestamps from a server module,
    injecting a low rate limit so tests run fast.
    """
    os.environ[env_var] = str(limit)
    # Force a fresh import each time so module-level state resets
    mod_name = f"mcp_servers.{server_file}"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    mod = importlib.import_module(f"mcp_servers.{server_file}")
    # reset the deque so previous test state doesn't bleed in
    mod._request_timestamps.clear()
    return mod._check_rate_limit, mod._request_timestamps


class TestNmapRateLimiter:

    def test_within_limit_does_not_raise(self):
        fn, ts = _load_rate_limiter("NMAP_MCP_RATE_LIMIT", "nmap_server", limit=5)
        for _ in range(5):
            fn()  # should not raise
        assert len(ts) == 5

    def test_exceeding_limit_raises_runtime_error(self):
        fn, ts = _load_rate_limiter("NMAP_MCP_RATE_LIMIT", "nmap_server", limit=3)
        fn(); fn(); fn()
        with pytest.raises(RuntimeError, match="rate limit"):
            fn()

    def test_old_timestamps_expire(self):
        fn, ts = _load_rate_limiter("NMAP_MCP_RATE_LIMIT", "nmap_server", limit=2)
        # Manually insert an old timestamp (>60 s ago)
        ts.append(time.monotonic() - 61)
        fn()  # should succeed because old entry expires
        fn()  # still within limit


class TestZapRateLimiter:

    def test_within_limit_does_not_raise(self):
        fn, ts = _load_rate_limiter("ZAP_MCP_RATE_LIMIT", "zap_server", limit=4)
        for _ in range(4):
            fn()

    def test_exceeding_limit_raises(self):
        fn, ts = _load_rate_limiter("ZAP_MCP_RATE_LIMIT", "zap_server", limit=2)
        fn(); fn()
        with pytest.raises(RuntimeError):
            fn()


class TestMetasploitRateLimiter:

    def test_within_limit_does_not_raise(self):
        fn, ts = _load_rate_limiter("MSF_MCP_RATE_LIMIT", "metasploit_server", limit=3)
        for _ in range(3):
            fn()

    def test_exceeding_limit_raises(self):
        fn, ts = _load_rate_limiter("MSF_MCP_RATE_LIMIT", "metasploit_server", limit=2)
        fn(); fn()
        with pytest.raises(RuntimeError):
            fn()


class TestAuxRateLimiter:

    def test_within_limit_does_not_raise(self):
        fn, ts = _load_rate_limiter("AUX_MCP_RATE_LIMIT", "auxiliary_tools_server", limit=5)
        for _ in range(5):
            fn()

    def test_exceeding_limit_raises(self):
        fn, ts = _load_rate_limiter("AUX_MCP_RATE_LIMIT", "auxiliary_tools_server", limit=2)
        fn(); fn()
        with pytest.raises(RuntimeError):
            fn()

    def test_window_resets_after_expiry(self):
        fn, ts = _load_rate_limiter("AUX_MCP_RATE_LIMIT", "auxiliary_tools_server", limit=2)
        ts.append(time.monotonic() - 61)  # old entry
        ts.append(time.monotonic() - 61)  # old entry
        fn()  # both expired; this should succeed
        fn()  # still within fresh window

"""
Unit tests for _check_authorization:
- exact IP
- exact hostname
- CIDR block matching
- wildcard hostname matching
- URL with scheme stripped
- missing / unconfigured auth file
- commented lines ignored
"""

import os
import sys
import tempfile

import pytest
from unittest.mock import MagicMock, patch

# ── path bootstrap ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

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

from orchestrator.workflow_engine_improved import WorkflowEngine


def _engine_with_auth_file(path: str) -> WorkflowEngine:
    """Return a WorkflowEngine whose config points at the given auth file."""
    engine = WorkflowEngine.__new__(WorkflowEngine)
    engine.config = {
        "api": {"anthropic_api_key": "test", "model": "claude-test"},
        "safety": {"authorization_file": path},
        "workflow": {},
        "tools": {},
    }
    engine.config_path = MagicMock()
    return engine


def _write_auth(lines: list[str]) -> str:
    """Write auth file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(lines))
    f.close()
    return f.name


class TestCheckAuthorization:

    # ── exact matches ─────────────────────────────────────────────────────────

    def test_exact_ip_match(self):
        path = _write_auth(["192.168.1.10"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("192.168.1.10") is True
        finally:
            os.unlink(path)

    def test_exact_ip_no_match(self):
        path = _write_auth(["192.168.1.10"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("192.168.1.11") is False
        finally:
            os.unlink(path)

    def test_exact_hostname_match(self):
        path = _write_auth(["testlab.example.com"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("testlab.example.com") is True
        finally:
            os.unlink(path)

    # ── CIDR ─────────────────────────────────────────────────────────────────

    def test_cidr_match(self):
        path = _write_auth(["10.0.0.0/24"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("10.0.0.55") is True
        finally:
            os.unlink(path)

    def test_cidr_boundary_first(self):
        path = _write_auth(["10.0.0.0/24"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("10.0.0.0") is True
        finally:
            os.unlink(path)

    def test_cidr_boundary_last(self):
        path = _write_auth(["10.0.0.0/24"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("10.0.0.255") is True
        finally:
            os.unlink(path)

    def test_cidr_no_match(self):
        path = _write_auth(["10.0.0.0/24"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("10.0.1.1") is False
        finally:
            os.unlink(path)

    def test_cidr_slash32_exact(self):
        path = _write_auth(["192.168.50.5/32"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("192.168.50.5") is True
            assert engine._check_authorization("192.168.50.6") is False
        finally:
            os.unlink(path)

    # ── wildcard ─────────────────────────────────────────────────────────────

    def test_wildcard_subdomain_match(self):
        path = _write_auth(["*.pentest.lab"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("web.pentest.lab") is True
        finally:
            os.unlink(path)

    def test_wildcard_no_match_parent(self):
        path = _write_auth(["*.pentest.lab"])
        try:
            engine = _engine_with_auth_file(path)
            # bare domain without subdomain should NOT match *.pentest.lab
            assert engine._check_authorization("pentest.lab") is False
        finally:
            os.unlink(path)

    def test_wildcard_no_match_different_domain(self):
        path = _write_auth(["*.pentest.lab"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("web.other.lab") is False
        finally:
            os.unlink(path)

    # ── URL scheme stripping ──────────────────────────────────────────────────

    def test_url_with_https_scheme_stripped(self):
        path = _write_auth(["192.168.1.10"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("https://192.168.1.10/admin") is True
        finally:
            os.unlink(path)

    def test_url_with_http_scheme_stripped(self):
        path = _write_auth(["testlab.example.com"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("http://testlab.example.com/login") is True
        finally:
            os.unlink(path)

    def test_url_with_port_stripped(self):
        path = _write_auth(["192.168.1.10"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("http://192.168.1.10:8080/") is True
        finally:
            os.unlink(path)

    # ── comments and blank lines ──────────────────────────────────────────────

    def test_comment_lines_ignored(self):
        path = _write_auth(["# this is a comment", "192.168.1.10"])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("# this is a comment") is False
            assert engine._check_authorization("192.168.1.10") is True
        finally:
            os.unlink(path)

    def test_blank_lines_ignored(self):
        path = _write_auth(["", "192.168.1.10", ""])
        try:
            engine = _engine_with_auth_file(path)
            assert engine._check_authorization("192.168.1.10") is True
        finally:
            os.unlink(path)

    # ── missing / unconfigured file ───────────────────────────────────────────

    def test_missing_auth_file_returns_false(self):
        engine = _engine_with_auth_file("/nonexistent/path/auth.txt")
        assert engine._check_authorization("192.168.1.1") is False

    def test_no_auth_file_configured_returns_false(self):
        engine = WorkflowEngine.__new__(WorkflowEngine)
        engine.config = {
            "api": {"anthropic_api_key": "test", "model": "x"},
            "safety": {},  # no authorization_file key
            "workflow": {},
            "tools": {},
        }
        engine.config_path = MagicMock()
        assert engine._check_authorization("192.168.1.1") is False

"""
MCP Server for OWASP ZAP Integration
Provides tools for web application scanning via MCP protocol.
"""

import asyncio
import json
import logging
import time
from collections import deque
from typing import Any, Dict, List, Optional
from mcp.server import Server
from mcp.types import Tool, TextContent
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.zap_wrapper import ZAPWrapper
from dataclasses import asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Server("zap-web-scanner")

# ── Per-tool rate limiter ────────────────────────────────────────────────────
# Enforces a per-minute ceiling so the AI cannot flood the target with scans.
_RATE_LIMIT_PER_MIN = int(os.getenv("ZAP_MCP_RATE_LIMIT", "10"))
_request_timestamps: deque = deque()


def _check_rate_limit() -> None:
    """Raise if more than _RATE_LIMIT_PER_MIN requests in the last 60 seconds."""
    now = time.monotonic()
    # Purge entries older than 60 s
    while _request_timestamps and now - _request_timestamps[0] > 60:
        _request_timestamps.popleft()
    if len(_request_timestamps) >= _RATE_LIMIT_PER_MIN:
        raise RuntimeError(
            f"ZAP MCP rate limit reached ({_RATE_LIMIT_PER_MIN} req/min). "
            "Wait before issuing more scan requests."
        )
    _request_timestamps.append(now)


# ── Lazy ZAP wrapper (credentials from env/config) ───────────────────────────
_zap_wrapper: Optional[ZAPWrapper] = None


def _get_zap() -> ZAPWrapper:
    global _zap_wrapper
    if _zap_wrapper is None:
        api_key = os.getenv("ZAP_API_KEY", "")
        proxy_host = os.getenv("ZAP_PROXY_HOST", "localhost")
        proxy_port = int(os.getenv("ZAP_PROXY_PORT", "8080"))
        _zap_wrapper = ZAPWrapper(api_key=api_key, proxy_host=proxy_host, proxy_port=proxy_port)
    return _zap_wrapper


@app.list_tools()
async def list_tools() -> List[Tool]:
    """Advertise available ZAP tools."""
    return [
        Tool(
            name="zap_full_scan",
            description="Run a full ZAP scan (spider + active scan) against a web target URL",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Full URL to scan (e.g. http://host:port)"},
                    "use_ajax": {"type": "boolean", "description": "Use AJAX spider (default true)", "default": True},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="zap_spider_scan",
            description="Run ZAP spider crawl only — no active attack",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Full URL to spider"},
                    "max_depth": {"type": "integer", "description": "Spider depth (default 5)", "default": 5},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="zap_active_scan",
            description="Run ZAP active vulnerability scan against an already-spidered target",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Full URL to actively scan"},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="zap_passive_scan",
            description="Run ZAP passive scan — analyse proxied traffic without active attack",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Full URL"},
                },
                "required": ["target"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Dispatch tool calls with rate-limit enforcement."""
    try:
        _check_rate_limit()
        zap = _get_zap()

        if name == "zap_full_scan":
            target = arguments["target"]
            use_ajax = arguments.get("use_ajax", True)
            logger.info(f"ZAP full scan: {target} (ajax={use_ajax})")
            result = await asyncio.to_thread(zap.full_scan, target, use_ajax)
            return [TextContent(type="text", text=json.dumps(asdict(result), indent=2))]

        elif name == "zap_spider_scan":
            target = arguments["target"]
            max_depth = arguments.get("max_depth", 5)
            logger.info(f"ZAP spider: {target} depth={max_depth}")
            result = await asyncio.to_thread(zap.spider_scan, target, max_depth)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "zap_active_scan":
            target = arguments["target"]
            logger.info(f"ZAP active scan: {target}")
            result = await asyncio.to_thread(zap.active_scan, target)
            return [TextContent(type="text", text=json.dumps(asdict(result), indent=2))]

        elif name == "zap_passive_scan":
            target = arguments["target"]
            logger.info(f"ZAP passive scan: {target}")
            result = await asyncio.to_thread(zap.passive_scan, target)
            return [TextContent(type="text", text=json.dumps(asdict(result), indent=2))]

        else:
            raise ValueError(f"Unknown tool: {name}")

    except Exception as e:
        logger.error(f"Error executing {name}: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e), "tool": name, "arguments": arguments}, indent=2),
        )]


async def main() -> None:
    from mcp.server.stdio import stdio_server
    logger.info("Starting ZAP MCP Server...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())


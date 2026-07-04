"""
MCP Server for Metasploit Framework Integration
Provides tools for controlled exploit checking and execution via MCP protocol.

IMPORTANT: All exploitation capabilities require:
  1. The target to be listed in config/authorized_targets.txt
  2. auto_exploit: true in config/config.yaml
  3. Explicit operator approval at the interactive prompt (check→approve→run gate)
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

from tools.metasploit_wrapper import MetasploitWrapper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Server("metasploit-exploit-engine")

# ── Per-tool rate limiter ────────────────────────────────────────────────────
_RATE_LIMIT_PER_MIN = int(os.getenv("MSF_MCP_RATE_LIMIT", "5"))
_request_timestamps: deque = deque()


def _check_rate_limit() -> None:
    now = time.monotonic()
    while _request_timestamps and now - _request_timestamps[0] > 60:
        _request_timestamps.popleft()
    if len(_request_timestamps) >= _RATE_LIMIT_PER_MIN:
        raise RuntimeError(
            f"Metasploit MCP rate limit reached ({_RATE_LIMIT_PER_MIN} req/min). "
            "Wait before issuing more requests."
        )
    _request_timestamps.append(now)


# ── Lazy Metasploit wrapper ───────────────────────────────────────────────────
_msf_wrapper: Optional[MetasploitWrapper] = None


def _get_msf() -> MetasploitWrapper:
    global _msf_wrapper
    if _msf_wrapper is None:
        _msf_wrapper = MetasploitWrapper(
            host=os.getenv("MSF_HOST", "localhost"),
            port=int(os.getenv("MSF_PORT", "55553")),
            username=os.getenv("MSF_USERNAME", "msf"),
            password=os.getenv("MSF_PASSWORD", ""),
            ssl=os.getenv("MSF_SSL", "true").lower() == "true",
        )
    return _msf_wrapper


@app.list_tools()
async def list_tools() -> List[Tool]:
    """Advertise available Metasploit tools."""
    return [
        Tool(
            name="msf_search_exploits",
            description="Search Metasploit modules by keyword, CVE, or product name",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term (CVE ID, product, keyword)"},
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="msf_check_exploit",
            description=(
                "Run Metasploit exploit.check() — a READ-ONLY probe that determines whether "
                "the target is vulnerable WITHOUT executing the exploit. Safe to run."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "module_name": {"type": "string", "description": "Full module path (e.g. exploit/windows/smb/ms17_010_eternalblue)"},
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "options": {"type": "object", "description": "Additional module options", "default": {}},
                },
                "required": ["module_name", "target"],
            },
        ),
        Tool(
            name="msf_get_module_info",
            description="Get detailed information about a Metasploit module",
            inputSchema={
                "type": "object",
                "properties": {
                    "module_name": {"type": "string", "description": "Full module path"},
                },
                "required": ["module_name"],
            },
        ),
        Tool(
            name="msf_list_sessions",
            description="List active Metasploit sessions (post-exploitation)",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Dispatch tool calls with rate-limit enforcement."""
    try:
        _check_rate_limit()
        msf = _get_msf()

        if name == "msf_search_exploits":
            query = arguments["query"]
            logger.info(f"MSF search: {query}")
            modules = await asyncio.to_thread(msf.search_exploits, query)
            payload = [
                {
                    "name": m.name,
                    "fullname": m.fullname,
                    "type": m.type,
                    "rank": m.rank,
                    "description": m.description,
                }
                for m in modules
            ]
            return [TextContent(type="text", text=json.dumps(payload, indent=2))]

        elif name == "msf_check_exploit":
            module_name = arguments["module_name"]
            target = arguments["target"]
            options = arguments.get("options", {})
            logger.info(f"MSF check: {module_name} → {target}")
            result = await asyncio.to_thread(msf.check_exploit, module_name, target, options)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "msf_get_module_info":
            module_name = arguments["module_name"]
            info = await asyncio.to_thread(msf.get_module_info, module_name)
            if info:
                from dataclasses import asdict
                return [TextContent(type="text", text=json.dumps(asdict(info), indent=2))]
            return [TextContent(type="text", text=json.dumps({"error": "Module not found"}))]

        elif name == "msf_list_sessions":
            sessions = await asyncio.to_thread(msf.get_sessions)
            return [TextContent(type="text", text=json.dumps(sessions, indent=2))]

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
    logger.info("Starting Metasploit MCP Server...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())


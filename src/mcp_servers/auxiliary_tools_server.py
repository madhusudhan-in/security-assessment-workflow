"""
MCP Server for Auxiliary Security Tools
Provides Gobuster, Hping3, and WafWoof endpoints via MCP protocol.

These are the tools listed in the blog's architecture diagram under the
"Tool Layer" that had no MCP server previously.
"""

import asyncio
import json
import logging
import subprocess
import time
from collections import deque
from typing import Any, Dict, List
from mcp.server import Server
from mcp.types import Tool, TextContent
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Server("auxiliary-security-tools")

# ── Per-tool rate limiter ─────────────────────────────────────────────────────
_RATE_LIMIT_PER_MIN = int(os.getenv("AUX_MCP_RATE_LIMIT", "20"))
_request_timestamps: deque = deque()


def _check_rate_limit() -> None:
    now = time.monotonic()
    while _request_timestamps and now - _request_timestamps[0] > 60:
        _request_timestamps.popleft()
    if len(_request_timestamps) >= _RATE_LIMIT_PER_MIN:
        raise RuntimeError(
            f"Auxiliary tools MCP rate limit reached ({_RATE_LIMIT_PER_MIN} req/min)."
        )
    _request_timestamps.append(now)


def _run(cmd: List[str], timeout: int = 120) -> Dict[str, Any]:
    """Run a subprocess and return stdout/stderr/returncode."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Command timed out", "returncode": -1}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


@app.list_tools()
async def list_tools() -> List[Tool]:
    return [
        Tool(
            name="gobuster_dir_scan",
            description="Brute-force directories and files on an HTTP/HTTPS target using Gobuster",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Full URL (e.g. http://host:port)"},
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file",
                        "default": "/usr/share/wordlists/dirb/common.txt",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "Comma-separated file extensions (e.g. php,html,js)",
                        "default": "php,html,js,txt",
                    },
                    "threads": {"type": "integer", "description": "Number of threads (default 50)", "default": 50},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="hping3_port_probe",
            description="Send crafted TCP/UDP packets to probe a port using Hping3",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "port": {"type": "integer", "description": "Target port"},
                    "count": {"type": "integer", "description": "Number of packets to send (default 10)", "default": 10},
                    "mode": {
                        "type": "string",
                        "description": "Packet type: tcp (default), udp, icmp",
                        "default": "tcp",
                    },
                },
                "required": ["target", "port"],
            },
        ),
        Tool(
            name="wafw00f_detect",
            description="Detect the Web Application Firewall (WAF) protecting a target using WafWoof",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Full URL or hostname"},
                },
                "required": ["target"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    try:
        _check_rate_limit()

        if name == "gobuster_dir_scan":
            target = arguments["target"]
            wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            extensions = arguments.get("extensions", "php,html,js,txt")
            threads = arguments.get("threads", 50)

            gobuster_path = os.getenv("GOBUSTER_PATH", "/usr/bin/gobuster")
            cmd = [
                gobuster_path, "dir",
                "-u", target,
                "-w", wordlist,
                "-x", extensions,
                "-t", str(threads),
                "--no-progress",
                "-o", "/dev/stdout",
            ]
            logger.info(f"Running gobuster on {target}")
            result = await asyncio.to_thread(_run, cmd, 600)

            # Parse found paths from output
            paths = []
            for line in result["stdout"].splitlines():
                if line.startswith("/") or "(Status:" in line:
                    paths.append(line.strip())

            return [TextContent(
                type="text",
                text=json.dumps({
                    "target": target,
                    "paths_found": paths,
                    "total": len(paths),
                    "raw": result["stdout"][:4000],
                    "error": result["stderr"] or None,
                }, indent=2),
            )]

        elif name == "hping3_port_probe":
            target = arguments["target"]
            port = arguments["port"]
            count = arguments.get("count", 10)
            mode = arguments.get("mode", "tcp")

            hping_path = os.getenv("HPING3_PATH", "/usr/sbin/hping3")
            mode_flag = {"tcp": "-S", "udp": "--udp", "icmp": "--icmp"}.get(mode, "-S")
            cmd = [
                hping_path,
                mode_flag,
                "-p", str(port),
                "-c", str(count),
                target,
            ]
            logger.info(f"Hping3 probe {target}:{port} mode={mode}")
            result = await asyncio.to_thread(_run, cmd, 60)
            return [TextContent(
                type="text",
                text=json.dumps({
                    "target": target,
                    "port": port,
                    "mode": mode,
                    "output": result["stdout"],
                    "error": result["stderr"] or None,
                }, indent=2),
            )]

        elif name == "wafw00f_detect":
            target = arguments["target"]
            wafw00f_path = os.getenv("WAFW00F_PATH", "/usr/local/bin/wafw00f")
            cmd = [wafw00f_path, target, "-o", "-", "-f", "json"]
            logger.info(f"WAF detection: {target}")
            result = await asyncio.to_thread(_run, cmd, 120)

            waf_info: Any = result["stdout"]
            try:
                waf_info = json.loads(result["stdout"])
            except (json.JSONDecodeError, ValueError):
                pass  # Return raw output if not JSON

            return [TextContent(
                type="text",
                text=json.dumps({
                    "target": target,
                    "result": waf_info,
                    "error": result["stderr"] or None,
                }, indent=2),
            )]

        else:
            raise ValueError(f"Unknown tool: {name}")

    except Exception as e:
        logger.error(f"Error executing {name}: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e), "tool": name}, indent=2),
        )]


async def main() -> None:
    from mcp.server.stdio import stdio_server
    logger.info("Starting Auxiliary Tools MCP Server...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())


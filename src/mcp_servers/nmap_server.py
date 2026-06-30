"""
MCP Server for Nmap Integration
Provides tools for network scanning and reconnaissance via MCP protocol
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from mcp.server import Server
from mcp.types import Tool, TextContent
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.nmap_wrapper import NmapWrapper, NmapScanResult
from dataclasses import asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
app = Server("nmap-security-scanner")

# Initialize Nmap wrapper
nmap_wrapper = NmapWrapper()


@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available Nmap tools"""
    return [
        Tool(
            name="nmap_quick_scan",
            description="Perform a quick port scan to discover open ports on a target",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname to scan"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nmap_full_scan",
            description="Perform comprehensive scan with service detection and OS fingerprinting",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname to scan"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range to scan (e.g., '1-1000' or '80,443,8080')",
                        "default": "1-65535"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nmap_vulnerability_scan",
            description="Run NSE vulnerability detection scripts against target",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname to scan"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Specific ports to scan (optional)"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nmap_run_nse_script",
            description="Execute a specific NSE script against target",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "script": {
                        "type": "string",
                        "description": "NSE script name (e.g., 'http-enum', 'smb-vuln-ms17-010')"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Specific ports (optional)"
                    }
                },
                "required": ["target", "script"]
            }
        ),
        Tool(
            name="nmap_os_detection",
            description="Perform operating system detection on target",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nmap_aggressive_scan",
            description="Perform aggressive scan with all detection methods (OS, version, scripts, traceroute)",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nmap_service_detection",
            description="Detect services and versions running on open ports",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Specific ports to check"
                    }
                },
                "required": ["target", "ports"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    
    try:
        if name == "nmap_quick_scan":
            target = arguments["target"]
            logger.info(f"Executing quick scan on {target}")
            
            result = nmap_wrapper.quick_scan(target)
            return [TextContent(
                type="text",
                text=json.dumps(asdict(result), indent=2)
            )]
        
        elif name == "nmap_full_scan":
            target = arguments["target"]
            ports = arguments.get("ports", "1-65535")
            logger.info(f"Executing full scan on {target} (ports: {ports})")
            
            result = nmap_wrapper.full_scan(target, ports)
            return [TextContent(
                type="text",
                text=json.dumps(asdict(result), indent=2)
            )]
        
        elif name == "nmap_vulnerability_scan":
            target = arguments["target"]
            ports = arguments.get("ports")
            logger.info(f"Executing vulnerability scan on {target}")
            
            result = nmap_wrapper.vulnerability_scan(target, ports)
            return [TextContent(
                type="text",
                text=json.dumps(asdict(result), indent=2)
            )]
        
        elif name == "nmap_run_nse_script":
            target = arguments["target"]
            script = arguments["script"]
            ports = arguments.get("ports")
            logger.info(f"Running NSE script '{script}' on {target}")
            
            result = nmap_wrapper.run_nse_script(target, script, ports)
            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2)
            )]
        
        elif name == "nmap_os_detection":
            target = arguments["target"]
            logger.info(f"Performing OS detection on {target}")
            
            result = nmap_wrapper.os_detection(target)
            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2)
            )]
        
        elif name == "nmap_aggressive_scan":
            target = arguments["target"]
            logger.info(f"Executing aggressive scan on {target}")
            
            result = nmap_wrapper.aggressive_scan(target)
            return [TextContent(
                type="text",
                text=json.dumps(asdict(result), indent=2)
            )]
        
        elif name == "nmap_service_detection":
            target = arguments["target"]
            ports = arguments["ports"]
            logger.info(f"Detecting services on {target}:{ports}")
            
            result = nmap_wrapper.full_scan(target, ports)
            
            # Extract only service information
            services = {}
            for host in result.hosts:
                for port in host.ports:
                    services[f"{port.port}/{port.protocol}"] = {
                        "service": port.service,
                        "version": port.version,
                        "product": port.product,
                        "state": port.state
                    }
            
            return [TextContent(
                type="text",
                text=json.dumps(services, indent=2)
            )]
        
        else:
            raise ValueError(f"Unknown tool: {name}")
    
    except Exception as e:
        logger.error(f"Error executing {name}: {e}")
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": str(e),
                "tool": name,
                "arguments": arguments
            }, indent=2)
        )]


async def main():
    """Run the MCP server"""
    from mcp.server.stdio import stdio_server
    
    logger.info("Starting Nmap MCP Server...")
    
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())

# Made with Bob

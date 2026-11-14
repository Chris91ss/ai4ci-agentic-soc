"""MCP server: the only way the triage agent reaches SOC data, detectors and containment."""

from agentic_soc.mcp_server.quoting import contains_injection, looks_like_injection, quote
from agentic_soc.mcp_server.server import INSTRUCTIONS, build_server
from agentic_soc.mcp_server.tools import SocContext, SocTools, ToolError

__all__ = [
    "INSTRUCTIONS",
    "SocContext",
    "SocTools",
    "ToolError",
    "build_server",
    "contains_injection",
    "looks_like_injection",
    "quote",
]

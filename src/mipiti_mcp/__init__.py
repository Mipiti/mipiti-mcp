"""Mipiti MCP Server — security posture platform via Model Context Protocol."""

__version__ = "0.2.0"

from .client import MipitiClient
from .server import mcp, set_request_client

__all__ = ["MipitiClient", "mcp", "set_request_client"]

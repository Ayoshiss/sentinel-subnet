"""
Minimal MCP server, tool registry and dispatch.

Model Context Protocol is how an agent discovers and calls tools: `tools/list`
to see what is available, `tools/call` to invoke one. This implements those two
operations in-process. The JSON-RPC transport that normally carries them is
deliberately absent, it adds nothing to what this milestone is proving, which
is that a tool call can be executed inside an enclave and attested.

In Sentinel the server runs *inside* the confidential VM. Callers never reach it
directly; requests arrive via the gateway and results leave with an attestation
attached (see `enclave.py`).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class ToolError(Exception):
    """A tool failed. Carries no credential material."""


@runtime_checkable
class Tool(Protocol):
    """One callable capability, e.g. `postgres.query`."""

    name: str
    description: str

    def input_schema(self) -> dict[str, Any]: ...
    def call(self, arguments: dict[str, Any]) -> Any: ...


class MCPServer:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ToolError(f"tool {tool.name!r} is already registered")
        self._tools[tool.name] = tool

    def list_tools(self) -> list[dict[str, Any]]:
        """The `tools/list` response."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema(),
            }
            for t in sorted(self._tools.values(), key=lambda t: t.name)
        ]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """The `tools/call` response."""
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"unknown tool {name!r}")
        return tool.call(arguments or {})

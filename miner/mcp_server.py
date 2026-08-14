"""
In-enclave MCP server (stub).

Hosts the tool handlers (Postgres, Solana RPC, and enterprise connectors) that
run inside the SEV-SNP enclave using credentials sealed to the enclave. The
operator of the host machine cannot read the queries, credentials, or results.
"""

from __future__ import annotations

from typing import Any, Callable


class MCPServer:
    def __init__(self, config) -> None:
        self.config = config
        self._handlers: dict[str, Callable[..., Any]] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        self.register_tool("postgres.query", self._postgres_query)
        self.register_tool("solana.rpc", self._solana_rpc)

    def register_tool(self, name: str, handler: Callable[..., Any]) -> None:
        self._handlers[name] = handler

    def call(self, name: str, arguments: dict) -> dict:
        """Dispatch an MCP tool call to its handler."""
        if name not in self._handlers:
            return {"isError": True, "error": f"unknown tool: {name}"}
        return self._handlers[name](**arguments)

    # --- tool handlers (stubs) ---
    def _postgres_query(self, connection_id: str, sql: str, params: list | None = None) -> dict:
        raise NotImplementedError("Postgres handler lands in testnet phase.")

    def _solana_rpc(self, method: str, params: list | None = None) -> dict:
        raise NotImplementedError("Solana RPC handler lands in testnet phase.")

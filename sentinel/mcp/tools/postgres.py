"""
`postgres.query` — the first real Sentinel tool.

Runs a query against a customer's database from inside the enclave, using a
credential the Key Broker released only after attestation. The tool itself is
deliberately dumb: it holds no secret, makes no trust decision, and returns
plain data. Access control happened before it ran (`kbs.py`); proof of integrity
happens after it returns (`enclave.attest_result`).

Read-only by default. An agent that has talked its way into a tool call should
not be able to drop a table, so writes must be enabled explicitly by the
operator deploying the miner.
"""

from __future__ import annotations

from typing import Any, Sequence

from ...database import Database, QueryError
from ..server import ToolError

# Statements that modify data or schema. Blocked unless writes are enabled.
_WRITE_PREFIXES = (
    "insert", "update", "delete", "drop", "truncate", "alter",
    "create", "grant", "revoke", "copy", "call", "do",
)


def _first_keyword(sql: str) -> str:
    stripped = sql.lstrip()
    # Skip leading SQL comments so `/* x */ DROP ...` cannot slip through.
    while stripped.startswith("--") or stripped.startswith("/*"):
        if stripped.startswith("--"):
            _, _, stripped = stripped.partition("\n")
        else:
            _, _, stripped = stripped.partition("*/")
        stripped = stripped.lstrip()
    return stripped.split(None, 1)[0].lower() if stripped.split() else ""


class PostgresQueryTool:
    name = "postgres.query"
    description = (
        "Run a SQL query against the customer database inside a confidential "
        "enclave. Returns columns and rows; the response is attested."
    )

    def __init__(self, database: Database, allow_writes: bool = False, max_rows: int = 1000) -> None:
        self.database = database
        self.allow_writes = allow_writes
        self.max_rows = max_rows

    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "SQL to execute"},
                "params": {
                    "type": "array",
                    "description": "Bound parameters, used instead of string interpolation",
                    "items": {},
                },
            },
            "required": ["sql"],
        }

    def call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        sql = arguments.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            raise ToolError("`sql` is required and must be a non-empty string")

        params: Sequence[Any] = arguments.get("params") or ()
        if not isinstance(params, (list, tuple)):
            raise ToolError("`params` must be an array")

        if not self.allow_writes and _first_keyword(sql) in _WRITE_PREFIXES:
            raise ToolError(
                "this tool is read-only; enable writes explicitly to run "
                f"'{_first_keyword(sql).upper()}'"
            )

        try:
            result = self.database.query(sql, tuple(params))
        except QueryError as exc:
            raise ToolError(str(exc)) from exc

        payload = result.to_dict()
        if len(payload["rows"]) > self.max_rows:
            payload["rows"] = payload["rows"][: self.max_rows]
            payload["truncated"] = True
            payload["row_count"] = len(payload["rows"])
        return payload

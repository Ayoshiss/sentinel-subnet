"""MCP dispatch, the postgres.query tool, and the full attested-query flow."""

import pytest

from sentinel.attestation import (
    MockSilicon,
    VerificationError,
    bind_response,
    new_nonce,
    sha384,
    verify,
    verifier_from_public_key,
)
from sentinel.database import Credentials, MockDatabase, QueryError
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer, ToolError
from sentinel.mcp.tools import PostgresQueryTool

APPROVED = sha384(b"sentinel-miner-image-v0.1")
DSN = "postgres://user:secret@customer-db:5432/app"
RESOURCE = "customer-db"


@pytest.fixture
def db() -> MockDatabase:
    return MockDatabase(Credentials(dsn=DSN, resource=RESOURCE))


@pytest.fixture
def server(db: MockDatabase) -> MCPServer:
    s = MCPServer()
    s.register(PostgresQueryTool(db))
    return s


# --- MCP surface --------------------------------------------------------------

def test_tools_are_discoverable(server: MCPServer):
    tools = server.list_tools()
    assert [t["name"] for t in tools] == ["postgres.query"]
    assert "sql" in tools[0]["inputSchema"]["properties"]
    assert tools[0]["inputSchema"]["required"] == ["sql"]


def test_unknown_tool_is_rejected(server: MCPServer):
    with pytest.raises(ToolError, match="unknown tool"):
        server.call_tool("postgres.drop_everything", {})


def test_duplicate_registration_is_rejected(server: MCPServer, db: MockDatabase):
    with pytest.raises(ToolError, match="already registered"):
        server.register(PostgresQueryTool(db))


# --- the tool -----------------------------------------------------------------

def test_query_returns_rows(server: MCPServer):
    out = server.call_tool("postgres.query", {"sql": "SELECT * FROM customers"})
    assert out["columns"] == ["id", "email", "plan"]
    assert out["row_count"] == 3


def test_params_are_passed_through(server: MCPServer, db: MockDatabase):
    server.call_tool("postgres.query", {"sql": "SELECT * FROM t WHERE id = %s", "params": [7]})
    assert db.queries[-1] == ("SELECT * FROM t WHERE id = %s", (7,))


def test_missing_sql_is_rejected(server: MCPServer):
    for bad in ({}, {"sql": ""}, {"sql": "   "}, {"sql": 42}):
        with pytest.raises(ToolError, match="`sql` is required"):
            server.call_tool("postgres.query", bad)


def test_bad_params_type_is_rejected(server: MCPServer):
    with pytest.raises(ToolError, match="`params` must be an array"):
        server.call_tool("postgres.query", {"sql": "SELECT 1", "params": "nope"})


@pytest.mark.parametrize(
    "sql",
    [
        "DROP TABLE customers",
        "delete from customers",
        "  UPDATE customers SET plan = 'free'",
        "-- innocent\nDROP TABLE customers",
        "/* hidden */ TRUNCATE customers",
    ],
)
def test_writes_are_blocked_by_default(server: MCPServer, sql: str):
    """Read-only means read-only, including behind comments."""
    with pytest.raises(ToolError, match="read-only"):
        server.call_tool("postgres.query", {"sql": sql})


def test_writes_run_when_explicitly_enabled(db: MockDatabase):
    s = MCPServer()
    s.register(PostgresQueryTool(db, allow_writes=True))
    s.call_tool("postgres.query", {"sql": "DELETE FROM customers WHERE id = 1"})
    assert db.queries[-1][0].startswith("DELETE")


def test_rows_are_capped(db: MockDatabase):
    s = MCPServer()
    s.register(PostgresQueryTool(db, max_rows=2))
    out = s.call_tool("postgres.query", {"sql": "SELECT * FROM customers"})
    assert out["row_count"] == 2
    assert out["truncated"] is True


def test_database_errors_surface_as_tool_errors(server: MCPServer, db: MockDatabase):
    db.close()
    with pytest.raises(ToolError, match="closed database"):
        server.call_tool("postgres.query", {"sql": "SELECT 1"})


# --- the whole point: an agent verifies the answer without trusting the miner --

def full_flow():
    """Boot enclave, unlock credential, query, attest. Returns everything needed."""
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DSN)
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)

    credentials = enclave.unlock(broker, RESOURCE)
    server = MCPServer()
    server.register(PostgresQueryTool(MockDatabase(credentials)))

    request_id, nonce = "req-1", new_nonce()
    attested = enclave.run_attested(
        request_id, nonce,
        lambda: server.call_tool("postgres.query", {"sql": "SELECT * FROM customers"}),
    )
    return enclave, attested, request_id, nonce


def test_end_to_end_result_is_independently_verifiable():
    enclave, attested, request_id, nonce = full_flow()
    assert attested.result["row_count"] == 3

    # Verified by a third party holding only the published public key.
    assert verify(
        attested.attestation,
        verifier_from_public_key(enclave.public_key_hex),
        approved_measurement=APPROVED,
        expected_nonce=nonce,
        expected_report_data=bind_response(request_id, attested.response_hash),
    )


def test_altered_result_fails_verification():
    """A miner that edits a row after attesting is caught."""
    from sentinel.database import canonical

    enclave, attested, request_id, nonce = full_flow()
    forged = dict(attested.result)
    forged["rows"] = [[1, "attacker@evil.com", "enterprise"]]

    with pytest.raises(VerificationError, match="response binding"):
        verify(
            attested.attestation,
            verifier_from_public_key(enclave.public_key_hex),
            approved_measurement=APPROVED,
            expected_nonce=nonce,
            expected_report_data=bind_response(request_id, sha384(canonical(forged))),
        )


def test_response_hash_is_stable_across_key_order():
    """Binding must not depend on dict iteration order."""
    from sentinel.database import canonical

    a = {"columns": ["id"], "rows": [[1]], "row_count": 1}
    b = {"row_count": 1, "rows": [[1]], "columns": ["id"]}
    assert sha384(canonical(a)) == sha384(canonical(b))

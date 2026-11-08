"""
Integration test against a real Postgres.

Skipped unless DATABASE_URL is set, so CI stays fast and dependency-free while
the real path is still one command away locally:

    docker compose up -d postgres
    DATABASE_URL=postgres://tao:tao@localhost:5432/tao \\
        python -m pytest tests/test_postgres_integration.py -q

This is the coverage MockDatabase deliberately does not provide: real SQL, real
types, real connection handling.
"""

import os

import pytest

from sentinel.attestation import (
    MockSilicon, bind_response, new_nonce, sha384, verify, verifier_from_public_key,
)
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer, ToolError
from sentinel.mcp.tools import PostgresQueryTool

DATABASE_URL = os.getenv("DATABASE_URL")
APPROVED = sha384(b"sentinel-miner-image-v0.1")
RESOURCE = "customer-db"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DATABASE_URL, reason="set DATABASE_URL to run integration tests"),
]


@pytest.fixture
def live_db():
    from sentinel.database import Credentials, PostgresDatabase

    db = PostgresDatabase(Credentials(dsn=DATABASE_URL, resource=RESOURCE))
    yield db
    db.close()


def test_real_query_returns_rows(live_db):
    result = live_db.query("SELECT 1 AS one, 'x' AS letter")
    assert result.columns == ["one", "letter"]
    assert result.rows == [[1, "x"]]


def test_bound_parameters_work(live_db):
    result = live_db.query("SELECT %s::int AS n", (42,))
    assert result.rows == [[42]]


def test_write_still_blocked_against_real_db(live_db):
    server = MCPServer()
    server.register(PostgresQueryTool(live_db))
    with pytest.raises(ToolError, match="read-only"):
        server.call_tool("postgres.query", {"sql": "CREATE TABLE should_not_exist (id int)"})


def test_full_attested_flow_against_real_db():
    """The Milestone 2 flow end to end, with a real database behind it."""
    from sentinel.database import PostgresDatabase

    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DATABASE_URL)
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)

    credentials = enclave.unlock(broker, RESOURCE)
    db = PostgresDatabase(credentials)
    try:
        server = MCPServer()
        server.register(PostgresQueryTool(db))

        request_id, nonce = "req-live", new_nonce()
        attested = enclave.run_attested(
            request_id, nonce,
            lambda: server.call_tool("postgres.query", {"sql": "SELECT 1 AS ok"}),
        )
        assert attested.result["rows"] == [[1]]
        assert verify(
            attested.attestation,
            verifier_from_public_key(enclave.public_key_hex),
            approved_measurement=APPROVED,
            expected_nonce=nonce,
            expected_report_data=bind_response(
                request_id, attested.response_hash, attested.broker, attested.tls
            ),
        )
    finally:
        db.close()


def test_a_failed_query_does_not_break_the_next(live_db):
    """Found in the first pilot rehearsal: a query the role was refused left the
    connection in an aborted transaction, and every later query failed with it."""
    from sentinel.database import QueryError

    with pytest.raises(QueryError):
        live_db.query("SELECT * FROM no_such_table")
    assert live_db.query("SELECT 1 AS ok").rows == [[1]]


def test_no_transaction_is_left_open(live_db):
    """An open transaction holds locks and an old snapshot on the customer's
    database for as long as the miner runs."""
    from psycopg.pq import TransactionStatus

    live_db.query("SELECT 1")
    assert live_db._conn.info.transaction_status == TransactionStatus.IDLE


def test_the_engine_still_refuses_writes_after_a_rollback(live_db):
    from sentinel.database import QueryError

    for _ in range(2):
        with pytest.raises(QueryError, match="read-only transaction"):
            live_db.query("CREATE TEMP TABLE should_not_exist (id int)")

"""
Miner serving layer: hotkey auth, attested execution, and the refusals.

The interesting tests here are the ones that should FAIL: unsigned requests,
forged signatures, replays, and requests addressed to a different miner. Those
are what stop an unauthorised caller reaching a customer's database through an
enclave that would otherwise happily answer.

Runs a real threaded server over a real socket, so the wire format, header
casing and body framing are exercised rather than mocked.
"""

import threading

import pytest
from bittensor import http_auth
from bittensor.sp_core import Keypair

from sentinel.attestation import (
    MockSilicon, bind_response, new_nonce, sha384, verify, verifier_from_public_key,
)
from sentinel.database import Credentials, MockDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.serving import MinerHandler, Request
from sentinel.serving.client import MinerClient, MinerClientError
from sentinel.serving.server import make_server

APPROVED = sha384(b"sentinel-miner-image-v0.1")
RESOURCE = "customer-db"
DSN = "postgres://app:secret@customer-db:5432/prod"


# --- fixtures -----------------------------------------------------------------

@pytest.fixture
def miner_wallet():
    """A hotkey for the miner. Raw Keypairs satisfy the signer protocol."""
    return Keypair.create_from_uri("//Miner")


@pytest.fixture
def validator_wallet():
    return Keypair.create_from_uri("//Validator")


@pytest.fixture
def handler(miner_wallet):
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DSN)
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    credentials = enclave.unlock(broker, RESOURCE)

    mcp = MCPServer()
    mcp.register(PostgresQueryTool(MockDatabase(credentials)))
    return MinerHandler(enclave, mcp, hotkey_ss58=miner_wallet.ss58_address)


@pytest.fixture
def live(handler):
    """A real server on a real port; torn down after the test."""
    server = make_server(handler, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def signed(wallet, receiver, method, path, body=b""):
    return http_auth.sign(wallet, method=method, path=path, body=body, receiver_ss58=receiver)


# --- auth: the refusals -------------------------------------------------------

def test_unsigned_request_is_rejected(handler):
    r = handler.handle(Request("GET", "/tools"))
    assert r.status == 401


def test_signature_for_a_different_miner_is_rejected(handler, validator_wallet):
    """Receiver binding: a request addressed elsewhere must not be accepted here."""
    other = Keypair.create_from_uri("//SomeoneElse").ss58_address
    headers = signed(validator_wallet, other, "GET", "/tools")
    r = handler.handle(Request("GET", "/tools", headers))
    assert r.status == 401
    assert "Receiver" in r.payload["type"] or "receiver" in r.payload["error"].lower()


def test_signature_over_a_different_path_is_rejected(handler, validator_wallet, miner_wallet):
    """A signature is bound to method+path; it cannot be moved to another route."""
    headers = signed(validator_wallet, miner_wallet.ss58_address, "GET", "/tools")
    r = handler.handle(Request("POST", "/call", headers, b'{"tool":"x","nonce":"y"}'))
    assert r.status == 401


def test_tampered_body_is_rejected(handler, validator_wallet, miner_wallet):
    body = b'{"tool":"postgres.query","arguments":{"sql":"SELECT 1"},"nonce":"aa"}'
    headers = signed(validator_wallet, miner_wallet.ss58_address, "POST", "/call", body)
    tampered = body.replace(b"SELECT 1", b"DROP TABLE t")
    r = handler.handle(Request("POST", "/call", headers, tampered))
    assert r.status == 401


def test_replayed_request_is_rejected(handler, validator_wallet, miner_wallet):
    """The nonce store must refuse a byte-identical second request."""
    body = b'{"nonce":"' + new_nonce().encode() + b'"}'
    headers = signed(validator_wallet, miner_wallet.ss58_address, "POST", "/challenge", body)

    assert handler.handle(Request("POST", "/challenge", headers, body)).status == 200
    second = handler.handle(Request("POST", "/challenge", headers, body))
    assert second.status == 401
    assert "Replay" in second.payload["type"]


def test_hotkey_allowlist_is_enforced(handler, validator_wallet, miner_wallet):
    """A miner may restrict callers to, say, the validators in the metagraph."""
    handler.allowed_hotkeys = {Keypair.create_from_uri("//OnlyThisOne").ss58_address}
    headers = signed(validator_wallet, miner_wallet.ss58_address, "GET", "/tools")
    r = handler.handle(Request("GET", "/tools", headers))
    assert r.status == 401
    assert "not permitted" in r.payload["error"]


# --- health is public ---------------------------------------------------------

def test_health_needs_no_signature(handler):
    r = handler.handle(Request("GET", "/health"))
    assert r.status == 200
    assert r.payload["ok"] is True
    assert r.payload["launch_measurement"] == APPROVED


def test_health_exposes_no_secrets(handler):
    r = handler.handle(Request("GET", "/health"))
    assert "secret" not in str(r.payload)
    assert DSN not in str(r.payload)


# --- input validation ---------------------------------------------------------

def test_malformed_json_is_a_400(handler, validator_wallet, miner_wallet):
    body = b"{not json"
    headers = signed(validator_wallet, miner_wallet.ss58_address, "POST", "/call", body)
    assert handler.handle(Request("POST", "/call", headers, body)).status == 400


def test_missing_attestation_nonce_is_a_400(handler, validator_wallet, miner_wallet):
    body = b'{"tool":"postgres.query","arguments":{"sql":"SELECT 1"}}'
    headers = signed(validator_wallet, miner_wallet.ss58_address, "POST", "/call", body)
    r = handler.handle(Request("POST", "/call", headers, body))
    assert r.status == 400 and "nonce" in r.payload["error"]


def test_unknown_route_is_a_404(handler, validator_wallet, miner_wallet):
    headers = signed(validator_wallet, miner_wallet.ss58_address, "GET", "/nope")
    assert handler.handle(Request("GET", "/nope", headers)).status == 404


# --- end to end over a real socket -------------------------------------------

def test_attested_query_over_http(live, validator_wallet, miner_wallet):
    client = MinerClient(live, validator_wallet, miner_wallet.ss58_address)

    health = client.health()
    assert health["ok"] is True

    assert [t["name"] for t in client.list_tools()] == ["postgres.query"]

    nonce = new_nonce()
    out = client.call("postgres.query", {"sql": "SELECT * FROM customers"}, nonce, request_id="req-1")
    assert out["result"]["row_count"] == 3

    # The validator verifies with the miner's published public key alone.
    from sentinel.attestation import AttestationReport
    att = AttestationReport(**out["attestation"])
    assert verify(
        att,
        verifier_from_public_key(health["public_key"]),
        approved_measurement=APPROVED,
        expected_nonce=nonce,
        expected_report_data=bind_response("req-1", out["response_hash"]),
    )


def test_challenge_over_http_is_bound_to_the_nonce(live, validator_wallet, miner_wallet):
    client = MinerClient(live, validator_wallet, miner_wallet.ss58_address)
    health = client.health()

    nonce = new_nonce()
    out = client.challenge(nonce)

    from sentinel.attestation import AttestationReport
    att = AttestationReport(**out["attestation"])
    assert verify(
        att,
        verifier_from_public_key(health["public_key"]),
        approved_measurement=APPROVED,
        expected_nonce=nonce,
        expected_report_data=bind_response("challenge", out["response_hash"]),
    )


def test_client_surfaces_auth_failure(live, validator_wallet):
    """Signing for the wrong miner fails over the wire, not just in-process."""
    wrong = Keypair.create_from_uri("//NotTheMiner").ss58_address
    client = MinerClient(live, validator_wallet, wrong)
    with pytest.raises(MinerClientError, match="401"):
        client.list_tools()


def test_write_guard_still_applies_over_http(live, validator_wallet, miner_wallet):
    client = MinerClient(live, validator_wallet, miner_wallet.ss58_address)
    with pytest.raises(MinerClientError, match="read-only"):
        client.call("postgres.query", {"sql": "DROP TABLE customers"}, new_nonce())

"""The standard MCP endpoint: what an off-the-shelf MCP client talks to."""

import json
import urllib.request

import pytest

from sentinel.attestation import AttestationReport, bind_response, sha384, verify, verifier_from_public_key
from sentinel.serving import Request
from sentinel.serving.apikeys import ApiKeyStore, mint
from sentinel.serving.server import make_server
from tests.test_serving import handler, miner_wallet  # noqa: F401 - fixtures


@pytest.fixture
def keyed(handler):  # noqa: F811
    key, digest = mint()
    handler.api_keys = ApiKeyStore({"pilot-agent": digest})
    return handler, {"Authorization": "Bearer " + key}


def rpc(h, headers, method, params=None, id=1):
    body = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        body["id"] = id
    if params is not None:
        body["params"] = params
    return h.handle(Request("POST", "/mcp", headers, json.dumps(body).encode()))


def test_the_handshake_a_client_starts_with(keyed):
    h, auth = keyed
    r = rpc(h, auth, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                    "clientInfo": {"name": "test", "version": "1"}})
    assert r.payload["result"]["protocolVersion"] == "2025-03-26"
    assert "tools" in r.payload["result"]["capabilities"]
    assert rpc(h, auth, "notifications/initialized", id=None).status == 202


def test_an_unknown_protocol_version_gets_the_newest(keyed):
    h, auth = keyed
    r = rpc(h, auth, "initialize", {"protocolVersion": "1999-01-01"})
    assert r.payload["result"]["protocolVersion"] == "2025-06-18"


def test_tools_are_listed_with_their_schema(keyed):
    h, auth = keyed
    tools = rpc(h, auth, "tools/list").payload["result"]["tools"]
    assert [t["name"] for t in tools] == ["postgres.query"]
    assert "inputSchema" in tools[0]


def test_a_tool_call_returns_rows_and_a_proof_that_verifies(keyed):
    h, auth = keyed
    nonce = "ab" * 16
    r = rpc(h, auth, "tools/call", {"name": "postgres.query", "arguments": {"sql": "SELECT 1"},
                                    "_meta": {"nonce": nonce}})
    result = r.payload["result"]
    assert result["isError"] is False
    proof = result["structuredContent"]
    assert json.loads(result["content"][0]["text"]) == proof["result"]
    report = AttestationReport(**proof["attestation"])
    assert report.nonce == nonce
    binding = bind_response(proof["request_id"], proof["response_hash"], proof.get("broker", ""))
    verify(report, verifier_from_public_key(h.enclave.public_key_hex),
           approved_measurement=sha384(b"sentinel-miner-image-v0.1"),
           expected_nonce=nonce, expected_report_data=binding)


def test_without_a_nonce_the_miner_picks_one_and_says_so(keyed):
    h, auth = keyed
    r = rpc(h, auth, "tools/call", {"name": "postgres.query", "arguments": {"sql": "SELECT 1"}})
    proof = r.payload["result"]["structuredContent"]
    assert proof["nonce"] == proof["attestation"]["nonce"] and len(proof["nonce"]) == 32


def test_writes_are_refused_as_a_tool_error_not_a_crash(keyed):
    h, auth = keyed
    r = rpc(h, auth, "tools/call", {"name": "postgres.query", "arguments": {"sql": "DROP TABLE x"}})
    assert r.payload["result"]["isError"] is True
    assert "read-only" in r.payload["result"]["content"][0]["text"]


def test_unknown_methods_and_bad_requests_are_json_rpc_errors(keyed):
    h, auth = keyed
    assert rpc(h, auth, "resources/list").payload["error"]["code"] == -32601
    bad = h.handle(Request("POST", "/mcp", auth, b'{"method": "tools/list", "id": 1}'))
    assert bad.payload["error"]["code"] == -32600


def test_the_endpoint_needs_the_same_key_as_everything_else(handler):  # noqa: F811
    _, digest = mint()
    handler.api_keys = ApiKeyStore({"pilot-agent": digest})
    r = rpc(handler, {"Authorization": "Bearer sk_sentinel_wrong"}, "tools/list")
    assert r.status == 401


def test_a_scoped_key_cannot_call_outside_its_scope(handler):  # noqa: F811
    key, digest = mint()
    handler.api_keys = ApiKeyStore({"support": {"digest": digest, "scopes": ["support"]}})
    auth = {"Authorization": "Bearer " + key}
    assert rpc(handler, auth, "tools/list").payload["result"]["tools"] == []
    r = rpc(handler, auth, "tools/call", {"name": "postgres.query", "arguments": {"sql": "SELECT 1"}})
    assert "not permitted" in r.payload["error"]["message"]


def test_over_a_real_socket(keyed):
    h, auth = keyed
    server = make_server(h, "127.0.0.1", 0)
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/mcp",
            data=json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}).encode(),
            headers={**auth, "Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert json.loads(resp.read())["id"] == 7
    finally:
        server.shutdown()

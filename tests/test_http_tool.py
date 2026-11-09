"""
API keys held inside the enclave (`<scope>.request`).

A real HTTPS server on localhost plays the customer's API, so every check runs
over real sockets: the key is added inside the enclave, never returned, sent
only to the customer's host, and only for calls on the allow list.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinel.attestation import MockSilicon, sha384
from sentinel.database import canonical
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.server import ToolError
from sentinel.mcp.tools import HttpRequestTool, is_http_secret, parse_spec
from sentinel.tls import EnclaveTls, TlsIssuer, make_ca

KEY = "sk_test_51NOTREALabcdefghijklmnop"
APPROVED = sha384(b"sentinel-miner-image-v0.1")
ROOT = pathlib.Path(__file__).resolve().parent.parent


class FakeApi(BaseHTTPRequestHandler):
    seen: list[dict] = []
    other_port = 0

    def log_message(self, *args):  # keep test output clean
        pass

    def _record(self, body=b""):
        FakeApi.seen.append({"method": self.command, "path": self.path,
                             "auth": self.headers.get("Authorization"),
                             "cookie": self.headers.get("Cookie"), "body": body})

    def _send(self, status, payload, content_type="application/json", extra=None):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._record()
        if self.path.startswith("/v1/balance"):
            self._send(200, {"available": [{"amount": 4200, "currency": "usd"}]})
        elif self.path == "/v1/echo":
            self._send(200, {"you_sent": self.headers.get("Authorization")})
        elif self.path == "/v1/redirect":
            self._send(302, b"", extra={"Location": f"https://127.0.0.1:{FakeApi.other_port}/steal"})
        elif self.path == "/v1/big":
            self._send(200, b"x" * 5000, content_type="text/plain")
        elif self.path.startswith("/v1/charges/"):
            self._send(200, {"id": self.path.rsplit("/", 1)[-1], "amount": 1299})
        elif self.path == "/v1/missing":
            self._send(404, {"error": {"message": "No such thing"}})
        else:
            self._send(500, {"error": "unexpected path " + self.path})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self._record(self.rfile.read(length))
        self._send(200, {"id": "re_1", "status": "succeeded"})


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    """Two HTTPS servers under one test CA: the customer's API and another host."""
    ca_dir = tmp_path_factory.mktemp("ca") / "ca"
    make_ca(ca_dir)
    issuer = TlsIssuer.from_dir(ca_dir, ["127.0.0.1"])
    servers = []
    for _ in range(2):
        key = EnclaveTls()
        key.accept(issuer.issue(key.spki.hex()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
        server.socket = key.server_context().wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    FakeApi.other_port = servers[1].server_port
    client = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    yield servers[0].server_port, client
    for s in servers:
        s.shutdown()


def secret(port, **overrides):
    spec = {
        "kind": "http",
        "base_url": f"https://127.0.0.1:{port}",
        "auth": {"header": "Authorization", "value": f"Bearer {KEY}"},
        "allow": [
            {"method": "GET", "path": "/v1/balance"},
            {"method": "GET", "path": "/v1/echo"},
            {"method": "GET", "path": "/v1/redirect"},
            {"method": "GET", "path": "/v1/big"},
            {"method": "GET", "path": "/v1/missing"},
            {"method": "GET", "path": "/v1/charges/*"},
        ],
    }
    spec.update(overrides)
    return json.dumps(spec)


def tool(api, **overrides):
    port, client = api
    return HttpRequestTool(parse_spec(secret(port, **overrides)), "stripe", ssl_context=client)


@pytest.fixture(autouse=True)
def fresh_log():
    FakeApi.seen.clear()


# -- the key is used, never shown ----------------------------------------------

def test_the_enclave_adds_the_key_and_the_agent_gets_the_answer(api):
    out = tool(api).call({"path": "/v1/balance"})
    assert out["status"] == 200
    assert out["body"] == {"available": [{"amount": 4200, "currency": "usd"}]}
    assert out["request"] == {"method": "GET", "url": f"https://127.0.0.1:{api[0]}/v1/balance"}
    assert FakeApi.seen[-1]["auth"] == f"Bearer {KEY}"
    assert KEY not in json.dumps(out)


def test_an_api_that_echoes_the_key_does_not_hand_it_to_the_agent(api):
    out = tool(api).call({"path": "/v1/echo"})
    assert KEY not in json.dumps(out)
    assert "[redacted]" in json.dumps(out)


def test_the_agent_cannot_replace_the_key_or_add_cookies(api):
    tool(api).call({"path": "/v1/balance", "headers": {
        "Authorization": "Bearer attacker", "Cookie": "session=x", "Accept": "application/json"}})
    assert FakeApi.seen[-1]["auth"] == f"Bearer {KEY}"
    assert FakeApi.seen[-1]["cookie"] is None


def test_the_tool_list_does_not_contain_the_key(api):
    mcp = MCPServer()
    mcp.register(tool(api))
    assert KEY not in json.dumps(mcp.list_tools())
    assert KEY not in repr(parse_spec(secret(api[0])))


# -- only the customer's host, only the allowed calls ---------------------------

@pytest.mark.parametrize("path", [
    "/v1/customers",                     # not listed
    "/v1/balance/extra",                 # exact rule, not a prefix
    "/v1/charges/",                      # wildcard needs something after it
    "/v1/charges/../customers",          # dot segments
    "/v1/charges/%2e%2e/customers",      # encoded dots
    "/v1/charges/x%2fy",                 # encoded slash
    "//evil.example/v1/balance",         # scheme-relative
    "/v1/balance?expand=all",            # query smuggled into the path
    "v1/balance",                        # relative
])
def test_paths_outside_the_allow_list_are_refused(api, path):
    with pytest.raises(ToolError):
        tool(api).call({"path": path})
    assert FakeApi.seen == []


def test_methods_outside_the_allow_list_are_refused(api):
    with pytest.raises(ToolError, match="not on this scope's allow list"):
        tool(api).call({"method": "POST", "path": "/v1/balance"})
    assert FakeApi.seen == []


def test_a_listed_write_works_and_carries_its_body(api):
    t = tool(api, allow=[{"method": "POST", "path": "/v1/refunds"}])
    out = t.call({"method": "POST", "path": "/v1/refunds", "form": {"charge": "ch_1"},
                  "headers": {"Idempotency-Key": "abc"}})
    assert out["status"] == 200
    assert FakeApi.seen[-1]["body"] == b"charge=ch_1"


def test_a_wildcard_rule_allows_paths_below_it(api):
    out = tool(api).call({"path": "/v1/charges/ch_123", "query": {"expand": "customer"}})
    assert out["body"]["id"].startswith("ch_123")


def test_a_redirect_is_not_followed_so_the_key_stays_on_the_customers_host(api):
    out = tool(api).call({"path": "/v1/redirect"})
    assert out["status"] == 302
    assert out["redirect_not_followed"].endswith("/steal")
    assert [s["path"] for s in FakeApi.seen] == ["/v1/redirect"]


def test_proxy_settings_from_the_environment_are_ignored(api, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    assert tool(api).call({"path": "/v1/balance"})["status"] == 200


def test_a_host_with_an_untrusted_certificate_is_refused(api):
    port, _ = api
    t = HttpRequestTool(parse_spec(secret(port)), "stripe")  # system CAs only
    with pytest.raises(ToolError, match="CERTIFICATE_VERIFY_FAILED"):
        t.call({"path": "/v1/balance"})
    assert FakeApi.seen == []


def test_errors_from_the_api_come_back_as_answers(api):
    out = tool(api).call({"path": "/v1/missing"})
    assert out["status"] == 404
    assert out["body"]["error"]["message"] == "No such thing"


def test_large_responses_are_truncated(api):
    out = tool(api, max_response_bytes=1000).call({"path": "/v1/big"})
    assert out["truncated"] is True and len(out["body"]) == 1000


# -- the secret itself ---------------------------------------------------------

@pytest.mark.parametrize("overrides, message", [
    ({"base_url": "http://127.0.0.1:1"}, "https"),
    ({"base_url": "https://user:pw@api.example.com"}, "no credentials"),
    ({"base_url": "https://api.example.com/v1"}, "origin only"),
    ({"allow": []}, "at least one"),
    ({"allow": [{"method": "GET", "path": "/v1/*/x"}]}, "trailing"),
    ({"allow": [{"method": "TRACE", "path": "/"}]}, "unsupported method"),
    ({"auth": {"header": "Authorization", "value": ""}}, "non-empty"),
    ({"auth": {"header": "X-Key", "value": "a\r\nHost: evil"}}, "single-line"),
])
def test_bad_secrets_are_refused_without_quoting_the_key(overrides, message):
    with pytest.raises(ToolError, match=message) as exc:
        parse_spec(secret(1, **overrides))
    assert KEY not in str(exc.value)


def test_a_dsn_is_not_mistaken_for_an_http_secret():
    assert not is_http_secret("postgresql://u:p@db/prod")
    assert not is_http_secret("sqlite:///")
    assert is_http_secret(secret(1))


# -- end to end: released sealed by the key server, attested on the way out -----

def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_key_server_releases_an_api_key_and_the_proof_covers_the_call(api):
    port, client = api
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret("stripe", secret(port))
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)

    credentials = enclave.unlock(broker, "stripe")
    run_miner = load_script("run_miner")
    t = run_miner.open_tool(credentials, "stripe", None)
    assert t.name == "stripe.request"
    t._opener = HttpRequestTool(t.spec, "stripe", ssl_context=client)._opener

    mcp = MCPServer()
    mcp.register(t)
    attested = enclave.run_attested("req-1", "ab" * 32,
                                    lambda: mcp.call_tool("stripe.request", {"path": "/v1/balance"}))
    assert attested.result["request"]["url"].endswith("/v1/balance")
    assert attested.response_hash == sha384(canonical(attested.result))
    assert KEY not in json.dumps(attested.result)


def test_the_key_server_reads_a_secret_file_and_checks_it_at_start(tmp_path):
    run_broker = load_script("run_broker")
    good = tmp_path / "stripe.json"
    good.write_text(secret(443))
    assert run_broker.parse_scopes([f"stripe=@{good}"])["stripe"] == secret(443)

    bad = tmp_path / "bad.json"
    bad.write_text(secret(443, base_url="http://api.example.com"))
    with pytest.raises(SystemExit, match="https") as exc:
        run_broker.parse_scopes([f"stripe=@{bad}"])
    assert KEY not in str(exc.value)

    with pytest.raises(SystemExit, match="cannot read"):
        run_broker.parse_scopes([f"stripe=@{tmp_path / 'missing.json'}"])

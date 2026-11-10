"""
Miner request handling, auth, execute, attest.

Deliberately framework-agnostic: `MinerHandler.handle()` maps a `Request` to a
`Response` and knows nothing about sockets. The stdlib server in `server.py`
wraps it, and swapping in FastAPI or anything else later touches only that
wrapper. It also means every behaviour below is unit-testable without binding a
port.

Every authenticated route follows the same three steps:

    1. VERIFY   the caller's hotkey signature (bittensor.http_auth)
    2. EXECUTE  the work inside the enclave
    3. ATTEST   bind the exact response into a fresh attestation report

Step 3 is what makes the reply checkable by someone who does not trust the
miner: the validator, the gateway, or the paying agent can each verify it
against the chip's public key alone.
"""

from __future__ import annotations

import inspect
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping

from bittensor import http_auth
from bittensor.sp_core import CRYPTO_SR25519

from ..enclave import Enclave
from .apikeys import ApiKeyStore
from ..mcp import MCPServer, ToolError

#: Routes that answer without a signature. Liveness only, no state, no secrets.
PUBLIC_PATHS = frozenset({"/health"})

#: MCP protocol revisions this endpoint speaks, newest first. Only tools are
#: offered, and their shape has not changed across these.
MCP_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


def _tool_allowed(tool: str, scopes: frozenset[str] | None) -> bool:
    """Whether a caller limited to `scopes` may call `tool`.

    Tools are named `<scope>.query`, so the scope is the part before the first
    dot. A tool with no dot belongs to no scope and is reachable only by a
    caller with no restriction.
    """
    if scopes is None:
        return True
    return "." in tool and tool.split(".", 1)[0] in scopes


def _in_scope(tools: list[dict[str, Any]], scopes: frozenset[str] | None) -> list[dict[str, Any]]:
    if scopes is None:
        return tools
    return [t for t in tools if _tool_allowed(str(t.get("name", "")), scopes)]


def _bearer(headers: Mapping[str, str]) -> str | None:
    """The token from `Authorization: Bearer ...`, header name case-insensitive."""
    for name, value in headers.items():
        if name.lower() == "authorization":
            parts = value.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
                return parts[1].strip()
    return None


@dataclass(frozen=True)
class Identity:
    """Who is calling, however they proved it.

    The handler needs two things from a caller and no more: something to name it
    by, and a unique value to fall back on for a request id. Keeping that
    explicit is what lets a second authentication scheme exist at all, rather
    than the Bittensor `Caller` type being load-bearing throughout.
    """

    kind: str                          # "hotkey" or "api-key"
    name: str                          # ss58 address, or the key's label
    nonce_ns: str
    #: Which scopes this caller may reach. None means all of them, which is
    #: what a validator gets: it is challenging the miner, not querying a
    #: customer's data, and a probe must be able to reach whatever is served.
    scopes: frozenset[str] | None = None


@dataclass
class Request:
    method: str
    path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def json(self) -> dict[str, Any]:
        if not self.body:
            return {}
        try:
            parsed = json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise BadRequest(f"body is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise BadRequest("body must be a JSON object")
        return parsed


@dataclass
class Response:
    status: int
    payload: dict[str, Any]

    def to_bytes(self) -> bytes:
        return json.dumps(self.payload, separators=(",", ":"), default=str).encode()


#: Whether this bittensor makes the receiver name each sender's signature scheme.
#: From 11.3.2 it does, and a call without one is refused: the scheme must come
#: from the receiver's own configuration, never from the request, or a classical
#: signature could pass for a hashed identity. Older versions took it from the
#: request header, so the argument is passed only where it exists.
_VERIFY_TAKES_SCHEME = "expected_crypto_type" in inspect.signature(http_auth.verify).parameters


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    return next((v for k, v in headers.items() if k.lower() == wanted), None)


class BadRequest(Exception):
    """Malformed input from the caller. Never carries credential material."""


class MinerHandler:
    """Serves attested MCP tool calls to authenticated Bittensor hotkeys."""

    def __init__(
        self,
        enclave: Enclave,
        mcp: MCPServer,
        hotkey_ss58: str,
        *,
        nonce_store: http_auth.NonceStore | None = None,
        max_age: float = http_auth.DEFAULT_MAX_AGE,
        allowed_skew: float = http_auth.DEFAULT_ALLOWED_SKEW,
        require_receiver: bool = True,
        allowed_hotkeys: set[str] | None = None,
        api_keys: ApiKeyStore | None = None,
        sender_schemes: Mapping[str, int] | None = None,
    ) -> None:
        self.enclave = enclave
        self.mcp = mcp
        self.hotkey_ss58 = hotkey_ss58
        # Replay protection lives here rather than in the caller so a restart
        # cannot be used to replay a captured request.
        self.nonce_store = nonce_store or http_auth.InMemoryNonceStore()
        self.max_age = max_age
        self.allowed_skew = allowed_skew
        self.require_receiver = require_receiver
        #: Optional allowlist, e.g. the validator hotkeys in the metagraph.
        #: None means any registered hotkey may call.
        self.allowed_hotkeys = allowed_hotkeys
        #: Keys for callers who are not on Bittensor. None means the only way in
        #: is a hotkey signature, which is correct on the subnet and useless to
        #: a customer running this over their own database.
        self.api_keys = api_keys
        #: The signature scheme each sender is trusted to use, by hotkey. Any
        #: sender not listed is held to sr25519, which is what every validator
        #: hotkey on the subnet uses today; a hashed or other key has to be
        #: listed here to be accepted, so it fails closed rather than open.
        self.sender_schemes = dict(sender_schemes or {})
        #: Set when the chip stops answering, and never cleared.
        #:
        #: A SEV-SNP guest can lose its firmware channel permanently while the
        #: process keeps running: if a request to the AMD security processor
        #: times out, the kernel disables the VMPCK rather than risk reusing an
        #: IV, and nothing but a reboot brings it back. Observed in production
        #: on 2026-09-24, rc -110 from the ASP, dead for ten hours.
        #:
        #: Without this the miner answers /health with ok=true the whole time,
        #: which is the worst shape a failure can take: alive, discoverable,
        #: scoring zero, and looking fine to whoever is watching.
        self.attestation_error: str | None = None

    # -- routing ---------------------------------------------------------------

    def handle(self, request: Request) -> Response:
        try:
            if request.path in PUBLIC_PATHS:
                return self._health()

            caller = self._authenticate(request)

            if request.method == "GET" and request.path == "/tools":
                # Filtered, not annotated. A caller's tool list is exactly what
                # it may reach, so there is nothing to tempt it into asking for
                # something it will be refused.
                return Response(200, {"tools": _in_scope(self.mcp.list_tools(), caller.scopes)})
            if request.method == "POST" and request.path == "/call":
                return self._call(request, caller)
            if request.method == "POST" and request.path == "/challenge":
                return self._challenge(request, caller)
            if request.path == "/mcp":
                if request.method != "POST":
                    # Streamable HTTP lets a server decline the GET stream; this
                    # one has nothing to push, so every reply is the POST's body.
                    return Response(405, {"error": "POST JSON-RPC to /mcp; no event stream is offered"})
                return self._mcp(request, caller)
            return Response(404, {"error": f"no route for {request.method} {request.path}"})

        except http_auth.AuthError as exc:
            # 401 for anything the signature layer rejects: bad signature,
            # replay, staleness, wrong receiver, malformed headers.
            return Response(401, {"error": str(exc), "type": type(exc).__name__})
        except BadRequest as exc:
            return Response(400, {"error": str(exc)})
        except ToolError as exc:
            return Response(400, {"error": str(exc), "type": "ToolError"})
        except Exception as exc:  # noqa: BLE001 - never leak internals to a caller
            if type(exc).__name__ == "GuestError":
                # Matched by name rather than imported: the mock path must not
                # depend on the hardware package being installed.
                self.attestation_error = str(exc)
            return Response(500, {"error": f"internal error: {type(exc).__name__}"})

    # -- routes ----------------------------------------------------------------

    def _health(self) -> Response:
        """Unauthenticated liveness. Advertises identity, never secrets.

        How a caller should check this miner's proofs depends on what is signing
        them, so the answer says which. A mock publishes a bare Ed25519 key. Real
        silicon has no such key to publish and publishes AMD's certificates
        instead, which is what lets a validator verify without reaching KDS.

        Handing out the certificates gives an attacker nothing: they are public
        by design, and the chain is checked against a root pinned in the
        verifier, so a substituted one fails.
        """
        if self.attestation_error is not None:
            # 503, not 200 with a flag: a monitor that only reads status codes
            # should see this, and so should anything deciding whether to route
            # work here.
            return Response(503, {
                "ok": False,
                "hotkey": self.hotkey_ss58,
                "error": "attestation unavailable; the chip is not answering",
                "detail": self.attestation_error,
                "recovery": "a disabled VMPCK needs a host reboot; restarting "
                            "the process does not clear it",
            })

        body: dict[str, object] = {
            "ok": True,
            "hotkey": self.hotkey_ss58,
            "chip_id": self.enclave.chip_id,
            "launch_measurement": self.enclave.launch_measurement,
        }
        if self.enclave.broker_fingerprint:
            # Which broker's credential this miner holds. Public, and bound into
            # every answer anyway; here so a customer can check before asking.
            body["broker"] = self.enclave.broker_fingerprint
        tls = getattr(self.enclave, "tls", None)
        if tls is not None:
            # The key this miner serves HTTPS under. Every answer binds it too;
            # here so a client can see what to expect before it asks.
            body["tls"] = tls.fingerprint

        certificates = getattr(self.enclave.silicon, "certificates", None)
        event_log = self._event_log_b64()
        if event_log:
            # TDX has no certificates to hand out: the validator fetches Intel's
            # collateral itself. What it cannot fetch is the firmware's event
            # log, which is what explains the signed registers.
            body["attestation"] = "tdx"
            body["event_log"] = event_log
        elif certificates:
            import base64

            body["attestation"] = "sev-snp"
            body["certificates"] = {
                name: base64.b64encode(der).decode()
                for name, der in certificates.items()
            }
        else:
            body["attestation"] = "mock"
            body["public_key"] = self.enclave.public_key_hex
        return Response(200, body)

    def _event_log_b64(self) -> str:
        """The TDX event log, packed. Fixed for the life of the boot, so packed once."""
        if not hasattr(self, "_packed_log"):
            log = getattr(self.enclave.silicon, "event_log", None)
            packed = ""
            if log:
                import base64

                from ..tdx import encode_event_log

                packed = base64.b64encode(encode_event_log(log)).decode()
            self._packed_log = packed
        return self._packed_log

    def _call(self, request: Request, caller: Identity) -> Response:
        """Execute one MCP tool call inside the enclave and attest the result."""
        body = request.json()
        tool = body.get("tool")
        if not isinstance(tool, str) or not tool:
            raise BadRequest("`tool` is required")
        arguments = body.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise BadRequest("`arguments` must be an object")
        if not _tool_allowed(tool, caller.scopes):
            # 403, not 404: pretending the tool does not exist would be a lie a
            # caller can disprove by reading the docs, and an operator chasing a
            # permissions problem deserves to be told it is a permissions
            # problem.
            raise http_auth.AuthError(
                f"{caller.name!r} is not permitted the {tool!r} scope"
            )

        nonce = self._require_nonce(body)
        request_id = str(body.get("request_id") or caller.nonce_ns)

        attested = self.enclave.run_attested(
            request_id, nonce, lambda: self.mcp.call_tool(tool, arguments)
        )
        return Response(200, {"request_id": request_id, **attested.to_dict()})

    def _mcp(self, request: Request, caller: Identity) -> Response:
        """The standard MCP endpoint, so an off-the-shelf MCP client can connect.

        JSON-RPC 2.0 over Streamable HTTP, answered with plain JSON. Same
        authentication and scopes as /tools and /call. Every tool result carries
        the attestation in `structuredContent`, so a client that ignores it still
        works and one that checks it can. The attestation nonce comes from
        `params._meta.nonce` when the caller sends one; otherwise the miner picks
        it, which still proves which code answered but not that the answer is
        fresh, so a caller that cares sends its own.
        """
        body = request.json()
        rpc_id = body.get("id")
        method = body.get("method")

        def ok(result: dict) -> Response:
            return Response(200, {"jsonrpc": "2.0", "id": rpc_id, "result": result})

        def error(code: int, message: str) -> Response:
            return Response(200, {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})

        if body.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return error(-32600, "not a JSON-RPC 2.0 request")
        if "id" not in body:
            # A notification, e.g. notifications/initialized. Nothing to answer.
            return Response(202, {})
        params = body.get("params") or {}
        if not isinstance(params, dict):
            return error(-32602, "params must be an object")

        if method == "initialize":
            requested = params.get("protocolVersion")
            return ok({
                "protocolVersion": requested if requested in MCP_VERSIONS else MCP_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "sentinel", "version": "0.1"},
                "instructions": "Every tool result is attested: structuredContent "
                                "carries the proof of which code produced it and "
                                "which key server released its credential.",
            })
        if method == "ping":
            return ok({})
        if method == "tools/list":
            return ok({"tools": _in_scope(self.mcp.list_tools(), caller.scopes)})
        if method != "tools/call":
            return error(-32601, f"method {method!r} is not supported")

        tool = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(tool, str) or not tool or not isinstance(arguments, dict):
            return error(-32602, "tools/call needs a name and object arguments")
        if not _tool_allowed(tool, caller.scopes):
            return error(-32602, f"{caller.name!r} is not permitted the {tool!r} scope")
        meta = params.get("_meta") or {}
        nonce = meta.get("nonce") if isinstance(meta, dict) else None
        if not isinstance(nonce, str) or not nonce:
            nonce = secrets.token_hex(16)
        request_id = caller.nonce_ns
        try:
            attested = self.enclave.run_attested(
                request_id, nonce, lambda: self.mcp.call_tool(tool, arguments)
            )
        except ToolError as exc:
            return ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})
        proof = {"request_id": request_id, "nonce": nonce, **attested.to_dict()}
        # With the event log the proof stands on its own: anyone holding it can
        # replay which image booted, without reaching the miner. Not bound, and
        # it need not be: it is believed only if it replays to signed registers.
        event_log = self._event_log_b64()
        if event_log:
            proof["event_log"] = event_log
        return ok({
            "content": [{"type": "text", "text": json.dumps(proof.get("result"), default=str)}],
            "structuredContent": proof,
            "isError": False,
        })

    def _challenge(self, request: Request, caller: Identity) -> Response:
        """Answer a validator's liveness/integrity challenge with an attestation.

        Proves, on demand, that this miner is still the approved image on a
        genuine chip: bound to the validator's nonce so a previous answer
        cannot be replayed.
        """
        nonce = self._require_nonce(request.json())
        attested = self.enclave.attest_result(
            "challenge", {"chip_id": self.enclave.chip_id}, nonce
        )
        return Response(200, {"request_id": "challenge", **attested.to_dict()})

    # -- internals -------------------------------------------------------------

    def _authenticate(self, request: Request) -> Identity:
        """Identify the caller by API key if one is presented, else by hotkey.

        A bearer token is checked first and never falls through to the hotkey
        path on failure. Falling through would let an attacker probe keys and
        then try signatures on the same request, and would make a rejected key
        indistinguishable from an absent one.
        """
        token = _bearer(request.headers)
        if token is not None:
            if self.api_keys is None:
                raise http_auth.AuthError("API key authentication is not enabled here")
            label = self.api_keys.label_for(token)
            if label is None:
                raise http_auth.AuthError("unknown API key")
            return Identity(
                kind="api-key", name=label, nonce_ns=secrets.token_hex(8),
                scopes=self.api_keys.scopes_for(label),
            )

        scheme = {}
        if _VERIFY_TAKES_SCHEME:
            # Chosen by the claimed sender from our own table, then enforced by
            # verify: the request can name who it is, not how to check it.
            sender = _header(request.headers, "X-Bittensor-Hotkey") or ""
            scheme["expected_crypto_type"] = self.sender_schemes.get(sender, CRYPTO_SR25519)
        caller = http_auth.verify(
            request.headers,
            request.body,
            method=request.method,
            path=request.path,
            self_hotkey_ss58=self.hotkey_ss58,
            max_age=self.max_age,
            allowed_skew=self.allowed_skew,
            require_receiver=self.require_receiver,
            nonce_store=self.nonce_store,
            **scheme,
        )
        if self.allowed_hotkeys is not None and caller.hotkey_ss58 not in self.allowed_hotkeys:
            raise http_auth.AuthError(f"hotkey {caller.hotkey_ss58} is not permitted")
        return Identity(kind="hotkey", name=caller.hotkey_ss58, nonce_ns=str(caller.nonce_ns))

    @staticmethod
    def _require_nonce(body: Mapping[str, Any]) -> str:
        """The attestation nonce, supplied by the challenger.

        Distinct from the HTTP auth nonce: that one proves the *request* is
        fresh, this one proves the *attestation* is. The caller chooses it so
        the miner cannot pre-compute a report.
        """
        nonce = body.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise BadRequest("`nonce` is required (hex challenge from the caller)")
        return nonce

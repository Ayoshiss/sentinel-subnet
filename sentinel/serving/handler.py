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

import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping

from bittensor import http_auth

from ..enclave import Enclave
from .apikeys import ApiKeyStore
from ..mcp import MCPServer, ToolError

#: Routes that answer without a signature. Liveness only, no state, no secrets.
PUBLIC_PATHS = frozenset({"/health"})


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

    kind: str          # "hotkey" or "api-key"
    name: str          # ss58 address, or the key's label
    nonce_ns: str


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
                return Response(200, {"tools": self.mcp.list_tools()})
            if request.method == "POST" and request.path == "/call":
                return self._call(request, caller)
            if request.method == "POST" and request.path == "/challenge":
                return self._challenge(request, caller)
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

        certificates = getattr(self.enclave.silicon, "certificates", None)
        if certificates:
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

    def _call(self, request: Request, caller: Identity) -> Response:
        """Execute one MCP tool call inside the enclave and attest the result."""
        body = request.json()
        tool = body.get("tool")
        if not isinstance(tool, str) or not tool:
            raise BadRequest("`tool` is required")
        arguments = body.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise BadRequest("`arguments` must be an object")
        nonce = self._require_nonce(body)
        request_id = str(body.get("request_id") or caller.nonce_ns)

        attested = self.enclave.run_attested(
            request_id, nonce, lambda: self.mcp.call_tool(tool, arguments)
        )
        return Response(200, {"request_id": request_id, **attested.to_dict()})

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
            return Identity(kind="api-key", name=label, nonce_ns=secrets.token_hex(8))

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

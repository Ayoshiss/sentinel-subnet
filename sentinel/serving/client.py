"""
Signed client for talking to a Sentinel miner.

Used by the validator to challenge miners, and by any agent paying for tool
calls. Every request is signed with the caller's hotkey and addressed to a
specific miner hotkey, so a captured request cannot be replayed against a
different miner.

Verification of the *response* is deliberately not done here, the caller does
it explicitly with `sentinel.attestation.verify`, because "who checked the
attestation" should never be a hidden detail.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from bittensor import http_auth


class MinerClientError(Exception):
    pass


@dataclass
class MinerResponse:
    """A reply plus what a validator needs to score it.

    Headers and latency matter as much as the body here: an attested response
    served from a cache arrives without its matching proof, and a slow miner is
    a worse miner even when it answers correctly.
    """

    payload: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)
    latency_ms: float = 0.0

    def header(self, name: str) -> str:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return ""


class MinerClient:
    """Talks to one miner at `base_url`, signing as `wallet`'s hotkey."""

    def __init__(self, base_url: str, wallet: Any, miner_hotkey_ss58: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.wallet = wallet
        self.miner_hotkey_ss58 = miner_hotkey_ss58
        self.timeout = timeout

    # -- routes ---------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Unauthenticated: used to discover a miner's chip and measurement."""
        return self._request("GET", "/health", signed=False)

    def list_tools(self) -> list[dict[str, Any]]:
        return self._request("GET", "/tools")["tools"]

    def call(self, tool: str, arguments: dict[str, Any], nonce: str, request_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"tool": tool, "arguments": arguments, "nonce": nonce}
        if request_id is not None:
            payload["request_id"] = request_id
        return self._request("POST", "/call", payload)

    def challenge(self, nonce: str) -> dict[str, Any]:
        """Ask the miner to prove, right now, what code it is running."""
        return self._request("POST", "/challenge", {"nonce": nonce})

    # -- full responses, for scoring ------------------------------------------

    def call_full(self, tool: str, arguments: dict[str, Any], nonce: str,
                  request_id: str | None = None) -> MinerResponse:
        payload: dict[str, Any] = {"tool": tool, "arguments": arguments, "nonce": nonce}
        if request_id is not None:
            payload["request_id"] = request_id
        return self._request_full("POST", "/call", payload)

    def challenge_full(self, nonce: str) -> MinerResponse:
        return self._request_full("POST", "/challenge", {"nonce": nonce})

    # -- internals ------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        signed: bool = True,
    ) -> dict[str, Any]:
        return self._request_full(method, path, payload, signed=signed).payload

    def _request_full(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        signed: bool = True,
    ) -> MinerResponse:
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
        headers = {"Content-Type": "application/json"}
        if signed:
            headers.update(
                http_auth.sign(
                    self.wallet,
                    method=method,
                    path=path,
                    body=body,
                    receiver_ss58=self.miner_hotkey_ss58,
                )
            )

        req = urllib.request.Request(f"{self.base_url}{path}", data=body or None, headers=headers, method=method)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read() or b"{}")
                return MinerResponse(
                    payload=data,
                    headers=dict(resp.headers.items()),
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                )
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            try:
                detail = json.loads(detail).get("error", detail)
            except json.JSONDecodeError:
                pass
            raise MinerClientError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise MinerClientError(f"{method} {path} -> unreachable: {exc.reason}") from exc

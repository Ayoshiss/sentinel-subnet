"""
Signed client for talking to a Sentinel miner.

Used by the validator to challenge miners, and by any agent paying for tool
calls. Every request is signed with the caller's hotkey and addressed to a
specific miner hotkey, so a captured request cannot be replayed against a
different miner.

Verification of the *response* is deliberately not done here — the caller does
it explicitly with `sentinel.attestation.verify`, because "who checked the
attestation" should never be a hidden detail.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from bittensor import http_auth


class MinerClientError(Exception):
    pass


class MinerClient:
    """Talks to one miner at `base_url`, signing as `wallet`'s hotkey."""

    def __init__(self, base_url: str, wallet: Any, miner_hotkey_ss58: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.wallet = wallet
        self.miner_hotkey_ss58 = miner_hotkey_ss58
        self.timeout = timeout

    # -- routes ---------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Unauthenticated — used to discover a miner's chip and measurement."""
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

    # -- internals ------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        signed: bool = True,
    ) -> dict[str, Any]:
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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            try:
                detail = json.loads(detail).get("error", detail)
            except json.JSONDecodeError:
                pass
            raise MinerClientError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise MinerClientError(f"{method} {path} -> unreachable: {exc.reason}") from exc

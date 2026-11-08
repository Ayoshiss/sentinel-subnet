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

import http.client
import json
import ssl
import time
import urllib.parse
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
    #: Fingerprint of the TLS key the server presented, empty over plain HTTP.
    #: Compared with the one the proof names, it shows whether the connection
    #: ended inside the attested enclave.
    peer_tls: str = ""

    def header(self, name: str) -> str:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return ""


class MinerClient:
    """Talks to one miner at `base_url`, signing as `wallet`'s hotkey."""

    def __init__(self, base_url: str, wallet: Any, miner_hotkey_ss58: str, timeout: float = 30.0,
                 ca_file: str | None = None) -> None:
        """Over https, `ca_file` makes the client require a certificate from that
        CA (the customer's key server CA). Without it the certificate is not
        checked against any CA; the caller compares `peer_tls` with the proof.
        """
        self.base_url = base_url.rstrip("/")
        self.wallet = wallet
        self.miner_hotkey_ss58 = miner_hotkey_ss58
        self.timeout = timeout
        self.ca_file = ca_file

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

        url = urllib.parse.urlsplit(self.base_url)
        if url.scheme == "https":
            if self.ca_file:
                context = ssl.create_default_context(cafile=self.ca_file)
            else:
                # Not trust on first use: the key is checked against the proof,
                # which the chip signs, by whoever reads `peer_tls`.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                url.hostname, url.port or 443, timeout=self.timeout, context=context
            )
        elif url.scheme == "http":
            conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=self.timeout)
        else:
            raise MinerClientError(f"unsupported URL {self.base_url}")
        started = time.perf_counter()
        try:
            conn.request(method, url.path + path, body=body or None, headers=headers)
            peer_tls = ""
            if url.scheme == "https" and conn.sock is not None:
                from ..tls import cert_fingerprint

                der = conn.sock.getpeercert(binary_form=True)
                peer_tls = cert_fingerprint(der) if der else ""
            resp = conn.getresponse()
            raw = resp.read()
            latency_ms = (time.perf_counter() - started) * 1000.0
        except (OSError, http.client.HTTPException) as exc:
            raise MinerClientError(f"{method} {path} -> unreachable: {exc}") from exc
        finally:
            conn.close()
        if resp.status >= 400:
            detail = raw.decode(errors="replace")
            try:
                detail = json.loads(detail).get("error", detail)
            except (json.JSONDecodeError, AttributeError):
                pass
            raise MinerClientError(f"{method} {path} -> HTTP {resp.status}: {detail}")
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            raise MinerClientError(f"{method} {path} -> not JSON: {exc}") from exc
        return MinerResponse(
            payload=data, headers=dict(resp.getheaders()),
            latency_ms=latency_ms, peer_tls=peer_tls,
        )

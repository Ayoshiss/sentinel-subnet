"""
The broker, across a network boundary.

Until this existed the miner built the `KeyBroker` and the `Enclave` in one
process, so the enclave attested to a broker in its own memory and the party
holding the secret was the party being checked. The mechanism ran correctly and
demonstrated nothing: custody separation is the entire claim, and custody was
not separated.

This is the seam that fixes it. `Enclave.unlock()` only ever calls `challenge()`
and `release()`, so a client with those two methods substitutes for the local
broker without the enclave knowing the difference. The customer runs the broker
on their own machine; the enclave runs on hardware they do not trust.

**The credential crosses the wire in the clear.** `kbs.py` has always said so,
and over a function call it was theoretical. Over a network it is not, so this
module refuses a plaintext URL unless an operator explicitly asks for one. The
better fix is to encrypt the released secret to the enclave's ephemeral public
key carried in the attestation report, so the transport is not trusted at all;
that is tracked and not done.

What authenticates the enclave to the broker is the attestation itself. There is
no API key here on purpose: anything else would be a second, weaker credential
guarding the first.
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from dataclasses import asdict

from .attestation import AttestationReport
from .database import Credentials
from .kbs import CredentialReleaseError, KeyBroker
from .serving.handler import Request, Response

logger = logging.getLogger("sentinel.kbs")

DEFAULT_TIMEOUT = 20.0


class BrokerUnreachable(CredentialReleaseError):
    """The broker could not be reached at all.

    Distinct from a refusal on purpose. A refusal means this enclave is not
    trusted and no retry will help; unreachable means nobody has decided
    anything yet, and an operator should go and look at the network rather than
    at their image.
    """


class RemoteBroker:
    """A `KeyBroker` that lives somewhere else.

    Implements only what `Enclave.unlock()` uses. Storing secrets and trusting
    chips are deliberately absent: those are the customer's decisions, made on
    the customer's machine, and a miner being able to call them over the network
    would undo the separation this class exists to create.
    """

    def __init__(self, url: str, timeout: float = DEFAULT_TIMEOUT, insecure: bool = False) -> None:
        url = url.rstrip("/")
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"broker URL must be http(s), got {url!r}")
        if url.startswith("http://") and not insecure:
            raise ValueError(
                f"{url} is plaintext, and the released credential travels over "
                "this connection. Use https, or pass the insecure flag if this "
                "is a loopback test."
            )
        self.url = url
        self.timeout = timeout

    def _post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            self.url + path, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            try:
                detail = json.loads(detail).get("error", detail)
            except json.JSONDecodeError:
                pass
            if exc.code == 403:
                # A decision: this enclave is not trusted with this secret. The
                # reason travels unchanged, because an operator needs to know
                # whether it was the measurement, the TCB or a stale nonce.
                raise CredentialReleaseError(f"broker refused: {detail}") from exc
            # Anything else is not a verdict. A 404 means the URL is wrong and a
            # 502 means something in front of the broker is broken; calling
            # either "refused" would send an operator to rebuild an image that
            # was never the problem.
            raise BrokerUnreachable(
                f"broker at {self.url} answered {exc.code}, which is not a "
                f"release decision: {detail}"
            ) from exc
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise BrokerUnreachable(f"could not reach the broker at {self.url}: {exc}") from exc

    def challenge(self) -> str:
        return str(self._post("/challenge", {})["nonce"])

    def release(
        self,
        resource: str,
        report: AttestationReport,
        certificates: dict[str, bytes] | None = None,
    ) -> Credentials:
        payload: dict = {"resource": resource, "attestation": asdict(report)}
        if certificates:
            # Same shape the miner's /health already uses, so there is one
            # encoding for certificates in the codebase rather than two.
            payload["certificates"] = {
                name: base64.b64encode(der).decode()
                for name, der in certificates.items()
            }
        answer = self._post("/release", payload)
        return Credentials(dsn=answer["dsn"], resource=answer["resource"])


def _decode_certs(raw: object) -> dict[str, bytes] | None:
    """Decode base64 certificates sent by an enclave.

    Enclave-supplied and therefore hostile until proven otherwise; this only
    gets them into `bytes`, and `CertChain` is what decides whether they chain
    to AMD's pinned root.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("certificates must be an object of name to base64")
    try:
        return {str(name): base64.b64decode(value, validate=True) for name, value in raw.items()}
    except Exception as exc:  # noqa: BLE001 - any decode failure is a rejection
        raise ValueError(f"unreadable certificates: {exc}") from exc


def verifier_factory(product: str, measurements: list[str], min_tcb: dict | None = None):
    """Build a `SevSnpVerifier` around certificates that arrived with a report.

    The customer's broker has no access to the miner's host, so it cannot read
    the VCEK/ASK/ARK the host provisioned. Taking them from the enclave is safe
    for exactly one reason: `CertChain.verify_self` pins AMD's root, so a chain
    an attacker generated fails there. What it buys is verification that never
    depends on AMD's KDS being reachable.
    """
    from cryptography import x509

    from .sevsnp import SevSnpPolicy, SevSnpVerifier
    from .sevsnp.certs import CertChain
    from .sevsnp.verifier import min_tcb_for

    approved = [bytes.fromhex(m) for m in measurements]
    tcb = min_tcb or min_tcb_for(product)

    def build(certs: dict[str, bytes]):
        missing = {"ASK", "ARK"} - set(certs or {})
        if missing:
            raise CredentialReleaseError(
                f"enclave supplied no {', '.join(sorted(missing))}; cannot check "
                "the chain to AMD's root, so nothing is released"
            )
        chain = CertChain(
            product=product,
            ask=x509.load_der_x509_certificate(certs["ASK"]),
            ark=x509.load_der_x509_certificate(certs["ARK"]),
        )
        return SevSnpVerifier(
            product,
            SevSnpPolicy(approved_measurement=approved, **tcb),
            chain=chain,
            offline=True,
        )

    return build


class BrokerHandler:
    """The customer's side: two routes, and nothing that reveals a secret.

    `/challenge` issues a nonce. `/release` takes an attestation and either
    returns the credential or refuses. Both are unauthenticated by design,
    because the attestation *is* the authentication: an enclave that cannot
    prove what it booted gets nothing, and one that can does not need a
    password as well. Adding an API key here would put a weaker secret in front
    of a stronger one on the same wire.

    Shares `Request`/`Response` with the miner handler so `serving.server`
    carries it unchanged.
    """

    def __init__(self, broker: KeyBroker) -> None:
        self.broker = broker

    def handle(self, request: Request) -> Response:
        if request.path == "/health":
            # No secret counts, no resource names: a reachability probe should
            # not double as an inventory of what the broker holds.
            return Response(200, {"status": "ok", "role": "broker"})

        if request.method != "POST":
            return Response(405, {"error": f"{request.method} not allowed"})

        try:
            payload = request.json()
        except Exception as exc:  # BadRequest, which is private to the handler
            return Response(400, {"error": str(exc)})

        if request.path == "/challenge":
            return Response(200, {"nonce": self.broker.challenge()})

        if request.path == "/release":
            resource = payload.get("resource")
            attestation = payload.get("attestation")
            if not isinstance(resource, str) or not isinstance(attestation, dict):
                return Response(400, {"error": "resource and attestation are required"})
            try:
                report = AttestationReport(**attestation)
            except TypeError as exc:
                return Response(400, {"error": f"malformed attestation: {exc}"})
            try:
                certificates = _decode_certs(payload.get("certificates"))
            except ValueError as exc:
                return Response(400, {"error": str(exc)})
            try:
                credentials = self.broker.release(resource, report, certificates)
            except CredentialReleaseError as exc:
                # 403, not 500: the request was well formed and the answer is no.
                # The reason travels back because an operator debugging a refusal
                # needs to know whether it was the measurement, the TCB or a
                # stale nonce. None of those strings contain the secret.
                logger.warning("refused release of %r: %s", resource, exc)
                return Response(403, {"error": str(exc)})
            logger.info("released %r to an attested enclave", resource)
            return Response(200, {"dsn": credentials.dsn, "resource": credentials.resource})

        return Response(404, {"error": f"no route for {request.path}"})

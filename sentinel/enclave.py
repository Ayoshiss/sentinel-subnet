"""
The enclave — confidential execution, from credential fetch to attested reply.

Everything a miner does on a customer's behalf happens in here. The enclave is
the only component that ever holds a plaintext credential, and it holds it only
in memory, only after proving what it is running.

Two attestations happen per request, and they are different proofs:

    1. UNLOCK  — "I am the approved image on a genuine chip, give me the
                  credential for this resource."          (checked by the KBS)
    2. RESPOND — "this exact result came out of that image, unmodified."
                  (checked by the agent, the gateway, or a validator)

Splitting them matters. The first controls access to secrets; the second makes
the answer independently verifiable by someone who was never involved in the
first. Neither requires trusting the miner operator.

Simulation caveat carries through from `attestation.py`: `MockSilicon` signs in
software, so this proves the protocol, not the hardware root of trust.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .attestation import (
    AttestationAgent,
    AttestationReport,
    Silicon,
    bind_response,
    sha384,
)
from .database import Credentials, canonical
from .kbs import KeyBroker, release_binding


@dataclass
class AttestedResponse:
    """A result plus the proof that this exact result came from approved code."""

    result: Any
    attestation: AttestationReport
    response_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "attestation": {
                "chip_id": self.attestation.chip_id,
                "launch_measurement": self.attestation.launch_measurement,
                "tcb_level": self.attestation.tcb_level,
                "nonce": self.attestation.nonce,
                "report_data": self.attestation.report_data,
                "signature": self.attestation.signature,
            },
            "response_hash": self.response_hash,
        }


class Enclave:
    """A confidential VM running the approved Sentinel miner image."""

    def __init__(
        self,
        silicon: Silicon,
        launch_measurement: str,
        tcb_level: int = 7,
    ) -> None:
        self.silicon = silicon
        self.launch_measurement = launch_measurement
        self.agent = AttestationAgent(silicon, launch_measurement, tcb_level)
        self._credentials: dict[str, Credentials] = {}

    @property
    def chip_id(self) -> str:
        return self.silicon.chip_id

    @property
    def public_key_hex(self) -> str:
        """Published so anyone can verify this enclave's responses."""
        return self.silicon.public_verifier().public_key_hex

    # -- 1. unlock -------------------------------------------------------------

    def unlock(self, broker: KeyBroker, resource: str) -> Credentials:
        """Attest to the broker and receive the credential for `resource`.

        Raises `CredentialReleaseError` (from the broker) if this enclave is not
        running approved code on a trusted chip.
        """
        nonce = broker.challenge()
        report = self.agent.attest(nonce, release_binding(resource))
        credentials = broker.release(resource, report)
        self._credentials[resource] = credentials
        return credentials

    def credential_for(self, resource: str) -> Credentials | None:
        """In-memory only. Nothing is written to disk."""
        return self._credentials.get(resource)

    # -- 2. respond ------------------------------------------------------------

    def attest_result(self, request_id: str, result: Any, nonce: str) -> AttestedResponse:
        """Bind `result` into a fresh report so it cannot be altered in transit."""
        response_hash = sha384(canonical(result))
        report = self.agent.attest(nonce, bind_response(request_id, response_hash))
        return AttestedResponse(result=result, attestation=report, response_hash=response_hash)

    def run_attested(
        self,
        request_id: str,
        nonce: str,
        work: Callable[[], Any],
    ) -> AttestedResponse:
        """Execute `work` inside the enclave and attest whatever it returns."""
        return self.attest_result(request_id, work(), nonce)

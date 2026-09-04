"""
Sentinel attestation core.

Proves that a response was produced by genuine, unmodified code running inside
a trusted execution environment (TEE). A report binds three things:

    * the launch measurement : WHICH code booted (integrity)
    * a fresh nonce          : that this proof is live, not replayed
    * the response binding   : that the proof is for THIS exact response

The report is signed by the chip. In production the signer is an AMD SEV-SNP
processor (VCEK, chained to the AMD root key). Here it is `MockSilicon`, which
signs with an Ed25519 key held only by the mock chip; verification uses the
matching PUBLIC key. That asymmetry is the point: a verifier needs no secret,
so the same trust shape as a real VCEK signature checked against AMD's public
certificate chain. The whole flow, generation, binding, verification,
tamper-detection, works and is testable today, and the real SEV-SNP backend
swaps in behind the identical `Silicon` interface.

MOCK, NOT PRODUCTION SECURITY. Ed25519 gives the correct *shape* (public
verifiability), but the key is generated in software by this process, not
burned into silicon and certified by AMD. It proves the protocol, not the
hardware root of trust.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, asdict
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sha384(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def new_nonce() -> str:
    """A fresh 32-byte challenge nonce (hex)."""
    return secrets.token_hex(32)


def bind_response(request_id: str, response_hash: str) -> str:
    """Value bound into the report so a proof cannot be reused for other data."""
    return sha384(f"{request_id}:{response_hash}".encode())


@dataclass
class AttestationReport:
    chip_id: str
    launch_measurement: str   # hash of the booted image
    tcb_level: int            # firmware/microcode version
    nonce: str                # challenge freshness
    report_data: str          # bind_response(request_id, response_hash)
    signature: str            # signed by the chip

    def canonical(self) -> bytes:
        body = {k: v for k, v in asdict(self).items() if k != "signature"}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class Silicon(Protocol):
    """The chip. MockSilicon now; RealSevSnp (via /dev/sev-guest) later."""
    chip_id: str
    def sign(self, message: bytes) -> str: ...
    def public_verifier(self) -> "Verifier": ...


class Verifier(Protocol):
    def valid(self, message: bytes, signature: str) -> bool: ...


# --- Mock backend (dev / CI / demo) ------------------------------------------

class _Ed25519Verifier:
    """Verifies a report using the chip's PUBLIC key only.

    Holds no secret material, which is the whole point: verification is public.
    A gateway, a validator, or the paying agent can each check a report
    independently, exactly as they would check a real VCEK signature against
    AMD's published certificate chain.
    """

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @property
    def public_key_hex(self) -> str:
        """The public key, safe to publish anywhere."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def valid(self, message: bytes, signature: str) -> bool:
        try:
            self._public_key.verify(bytes.fromhex(signature), message)
            return True
        except (InvalidSignature, ValueError):
            return False


def verifier_from_public_key(public_key_hex: str) -> _Ed25519Verifier:
    """Build a verifier from a published public key alone, no chip, no secret.

    Models the real world: you fetch the chip's certificate, and that is enough
    to check every report it ever signs.
    """
    return _Ed25519Verifier(
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    )


class MockSilicon:
    """Stands in for an AMD SEV-SNP chip, signing with an Ed25519 key.

    The private key never leaves this object, mirroring a VCEK that never
    leaves the processor. `public_verifier()` hands out only the public half.
    The real implementation replaces this with a VCEK-signed report and an
    AMD-certificate-chain verifier; the interface is identical, so nothing
    upstream changes when the hardware backend lands.

    This is a simulation. The key is software-generated, not silicon-resident
    and AMD-certified, so it proves the protocol, not the hardware root of trust.
    """

    def __init__(
        self,
        chip_id: str | None = None,
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.chip_id = chip_id or f"MOCK-EPYC-{secrets.token_hex(4)}"
        self._private_key = private_key or Ed25519PrivateKey.generate()

    @classmethod
    def from_seed(cls, seed: bytes, chip_id: str | None = None) -> "MockSilicon":
        """Deterministic chip from a 32-byte seed (reproducible tests/demos)."""
        return cls(chip_id=chip_id, private_key=Ed25519PrivateKey.from_private_bytes(seed))

    def sign(self, message: bytes) -> str:
        return self._private_key.sign(message).hex()

    def public_verifier(self) -> _Ed25519Verifier:
        return _Ed25519Verifier(self._private_key.public_key())

    @property
    def public_key_hex(self) -> str:
        """Publishable identity of this chip."""
        return self.public_verifier().public_key_hex


# --- Attestation agent (runs inside the enclave) ------------------------------

class AttestationAgent:
    def __init__(self, silicon: Silicon, launch_measurement: str, tcb_level: int = 7) -> None:
        self.silicon = silicon
        self.launch_measurement = launch_measurement
        self.tcb_level = tcb_level

    def attest(self, nonce: str, report_data: str) -> AttestationReport:
        report = AttestationReport(
            chip_id=self.silicon.chip_id,
            launch_measurement=self.launch_measurement,
            tcb_level=self.tcb_level,
            nonce=nonce,
            report_data=report_data,
            signature="",
        )
        report.signature = self.silicon.sign(report.canonical())
        return report


# --- Verification (runs anywhere: gateway, validator, or the agent itself) ---

class VerificationError(Exception):
    pass


def verify(
    report: AttestationReport,
    verifier: Verifier,
    approved_measurement: str,
    expected_nonce: str,
    min_tcb: int = 7,
    expected_report_data: str | None = None,
) -> bool:
    """Verify a report. Raises VerificationError on any failed check."""
    if not verifier.valid(report.canonical(), report.signature):
        raise VerificationError("signature invalid (not signed by a genuine chip)")
    if report.launch_measurement != approved_measurement:
        raise VerificationError("launch measurement mismatch (code was tampered)")
    if report.tcb_level < min_tcb:
        raise VerificationError(f"stale TCB {report.tcb_level} < {min_tcb} (vulnerable firmware)")
    if report.nonce != expected_nonce:
        raise VerificationError("nonce mismatch (replayed or stale attestation)")
    if expected_report_data is not None and report.report_data != expected_report_data:
        raise VerificationError("response binding mismatch (proof is for a different response)")
    return True

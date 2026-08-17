"""
Key Broker Service — credentials are released to *code*, not to people.

This is the piece that makes Sentinel's central claim true. A customer's database
password is never handed to a miner operator. It is held by the broker and
released only to an enclave that has just proved, cryptographically, three
things at once:

    * it is running on a chip the broker trusts        (signature + chip registry)
    * it booted the approved image                     (launch measurement)
    * the proof is fresh and for THIS resource         (broker-issued nonce + binding)

Fail any one and the credential is never emitted. An operator who swaps in
modified code does not get a degraded service; they get nothing.

Mirrors the real Confidential Containers flow — Trustee/KBS validating an
SEV-SNP report against a policy before releasing a secret from Vault. Here the
chip registry stands in for AMD's certificate directory, and `MockSilicon`
stands in for the processor. The interfaces are the same, so the real backend
drops in without changing callers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .attestation import (
    AttestationReport,
    VerificationError,
    bind_response,
    new_nonce,
    sha384,
    verify,
    verifier_from_public_key,
)
from .database import Credentials


class CredentialReleaseError(Exception):
    """Raised whenever a credential is withheld. Never leaks the secret."""


@dataclass
class ReleasePolicy:
    """What an enclave must prove before any secret is released."""

    approved_measurement: str
    min_tcb: int = 7
    nonce_ttl_seconds: float = 60.0


def release_binding(resource: str) -> str:
    """The value an enclave must bind into its report to request `resource`.

    Ties the proof to one specific secret, so an attestation obtained for the
    analytics database cannot be replayed to unlock the payments database.
    """
    return bind_response("kbs-release", sha384(resource.encode()))


@dataclass
class KeyBroker:
    """Holds secrets; releases them only against a valid, fresh attestation."""

    policy: ReleasePolicy
    _secrets: dict[str, Credentials] = field(default_factory=dict, repr=False)
    _trusted_chips: dict[str, str] = field(default_factory=dict, repr=False)
    _issued_nonces: dict[str, float] = field(default_factory=dict, repr=False)

    # -- setup -----------------------------------------------------------------

    def store_secret(self, resource: str, dsn: str) -> None:
        """Deposit a credential. This is the only place the DSN lives at rest."""
        self._secrets[resource] = Credentials(dsn=dsn, resource=resource)

    def trust_chip(self, chip_id: str, public_key_hex: str) -> None:
        """Register a chip as genuine.

        Stands in for AMD's VCEK certificate directory: in production the broker
        fetches the cert for a reported chip ID and checks it chains to AMD's
        root, rather than consulting a local map.
        """
        self._trusted_chips[chip_id] = public_key_hex

    # -- protocol --------------------------------------------------------------

    def challenge(self) -> str:
        """Issue a fresh nonce. The enclave must bind it into its report."""
        self._expire_nonces()
        nonce = new_nonce()
        self._issued_nonces[nonce] = time.monotonic() + self.policy.nonce_ttl_seconds
        return nonce

    def release(self, resource: str, report: AttestationReport) -> Credentials:
        """Verify the report and release the credential, or raise.

        Order matters: cheap structural checks first, signature last, and the
        secret is only read from storage after every check has passed.
        """
        if resource not in self._secrets:
            raise CredentialReleaseError(f"no secret stored for resource {resource!r}")

        # Freshness — the nonce must be one we issued and have not yet spent.
        self._expire_nonces()
        if report.nonce not in self._issued_nonces:
            raise CredentialReleaseError("unknown or expired nonce (replayed attestation)")

        # Chip identity — an unregistered chip is not a chip we will trust.
        public_key = self._trusted_chips.get(report.chip_id)
        if public_key is None:
            raise CredentialReleaseError(
                f"chip {report.chip_id!r} is not a trusted processor"
            )

        # Full attestation check: signature, image, TCB, freshness, resource binding.
        try:
            verify(
                report,
                verifier_from_public_key(public_key),
                approved_measurement=self.policy.approved_measurement,
                expected_nonce=report.nonce,
                min_tcb=self.policy.min_tcb,
                expected_report_data=release_binding(resource),
            )
        except VerificationError as exc:
            raise CredentialReleaseError(f"attestation rejected: {exc}") from exc

        # Spend the nonce so this proof cannot unlock anything twice.
        self._issued_nonces.pop(report.nonce, None)
        return self._secrets[resource]

    # -- internals -------------------------------------------------------------

    def _expire_nonces(self) -> None:
        now = time.monotonic()
        for nonce, expiry in list(self._issued_nonces.items()):
            if now > expiry:
                del self._issued_nonces[nonce]

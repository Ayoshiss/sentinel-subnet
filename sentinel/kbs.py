"""
Key Broker Service, credentials are released to *code*, not to people.

This is the piece that makes Sentinel's central claim true. A customer's database
password is never handed to a miner operator. It is held by the broker and
released only to an enclave that has just proved, cryptographically, three
things at once:

    * it is running on a chip the broker trusts        (signature + chip registry)
    * it booted the approved image                     (launch measurement)
    * the proof is fresh and for THIS resource         (broker-issued nonce + binding)

Fail any one and the credential is never emitted. An operator who swaps in
modified code does not get a degraded service; they get nothing.

Mirrors the real Confidential Containers flow, Trustee/KBS validating an
SEV-SNP report against a policy before releasing a secret from Vault. Here the
chip registry stands in for AMD's certificate directory, and `MockSilicon`
stands in for the processor. The interfaces are the same, so the real backend
drops in without changing callers.

Once the decision to release is made, the credential is sealed to a key the
enclave generated and bound into the attestation (`sentinel.sealing`), so only
that enclave can read it, whatever carries it. A plaintext release remains
only for tests that exercise the gate itself, and only when the policy asks.
"""

from __future__ import annotations

import time
from typing import Iterable
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
from .sealing import BrokerIdentity, SealedCredential, SealingError


class CredentialReleaseError(Exception):
    """Raised whenever a credential is withheld. Never leaks the secret."""


@dataclass
class ReleasePolicy:
    """What an enclave must prove before any secret is released."""

    #: One measurement, or several: identical code measures differently on
    #: different hosts, so a single value describes one machine, not a fleet.
    approved_measurement: str | Iterable[str]
    min_tcb: int = 7
    nonce_ttl_seconds: float = 60.0
    #: Return the credential unsealed when the enclave supplies no key. For
    #: tests of the gate only: a real broker refuses, because a plaintext
    #: credential is readable by whoever relays it.
    allow_plaintext_release: bool = False


def release_binding(resource: str, enclave_key: str = "") -> str:
    """The value an enclave must bind into its report to request `resource`.

    Ties the proof to one specific secret, so an attestation obtained for the
    analytics database cannot be replayed to unlock the payments database. With
    `enclave_key` it also ties the proof to the key the credential is sealed to,
    so a relay cannot substitute a key of its own: the attestation would no
    longer match.
    """
    if enclave_key:
        return bind_response("kbs-release", sha384(f"{resource}:{enclave_key}".encode()))
    return bind_response("kbs-release", sha384(resource.encode()))


#: A SEV-SNP report arrives as the whole 1184-byte structure, hex encoded, in the
#: `signature` field. A mock Ed25519 signature is 64 bytes. Nothing else is near
#: either length, so the shape identifies which verification path a report needs
#: without the report having to announce it.
SEVSNP_SIGNATURE_HEX_LEN = 1184 * 2


def looks_like_sevsnp(signature_hex: str) -> bool:
    """Whether this signature is a real SEV-SNP report rather than a mock one."""
    return len(signature_hex) >= SEVSNP_SIGNATURE_HEX_LEN and not looks_like_tdx(signature_hex)


def looks_like_tdx(signature_hex: str) -> bool:
    """Whether this signature is an Intel TDX quote.

    Length alone cannot tell, since a quote is longer than a SEV-SNP report.
    The header can: version 4 and TEE type 0x81, little endian. A SEV-SNP
    report opens with its own version, which is never 4 alongside that type.
    """
    return signature_hex[:4].lower() == "0400" and signature_hex[8:16].lower() == "81000000"


@dataclass
class KeyBroker:
    """Holds secrets; releases them only against a valid, fresh attestation.

    Two kinds of proof reach `release()`, and they are verified differently.

    A `MockSilicon` report is Ed25519 signed, so the broker checks it against a
    public key registered in advance with `trust_chip`. That models a directory
    of known-good chips and is what the development path uses.

    A real SEV-SNP report cannot work that way, because a processor has no bare
    public key to register. It is verified through AMD's certificate chain: the
    report is signed by the chip's VCEK, the VCEK by AMD's signing key, and that
    by AMD's root, which is pinned. Supply a `SevSnpVerifier` as `sevsnp` and the
    broker routes real reports to it, ignoring the chip registry entirely.

    Without a verifier configured, a real report is refused rather than falling
    back to the registry. A broker that cannot check a proof must not release a
    secret against it.
    """

    policy: ReleasePolicy
    #: Verifier for real hardware. `None` means this broker only accepts mocks.
    sevsnp: object | None = None
    #: Certificates the enclave supplied with its report, `{name: der}`. The
    #: extended report carries these so verification never has to reach AMD.
    sevsnp_certs: dict[str, bytes] = field(default_factory=dict, repr=False)
    #: Builds a verifier from certificates handed over with the report, used
    #: when the broker runs on a different machine from the enclave and so
    #: cannot read the host's own certificate store. `Callable[[dict[str, bytes]],
    #: verifier]`. Safe because the root stays pinned inside `CertChain`: an
    #: enclave that supplies its own invented chain fails rather than passing.
    sevsnp_factory: object | None = None
    #: Verifier for Intel TDX, a `TdxVerifier`. `None` refuses TDX quotes.
    tdx: object | None = None
    #: Signs every sealed release. Customers recognise their broker by it.
    identity: BrokerIdentity = field(default_factory=BrokerIdentity)
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

    def release(
        self,
        resource: str,
        report: AttestationReport,
        certificates: dict[str, bytes] | None = None,
        event_log: bytes | None = None,
        enclave_key: str | None = None,
    ) -> Credentials | SealedCredential:
        """Verify the report and release the credential, or raise.

        With `enclave_key`, the credential comes back sealed to it, and the
        report must bind that key. Without one, only a policy that allows
        plaintext release returns anything.

        Order matters: cheap structural checks first, signature last, and the
        secret is only read from storage after every check has passed.
        """
        if resource not in self._secrets:
            raise CredentialReleaseError(f"no secret stored for resource {resource!r}")
        if not enclave_key and not self.policy.allow_plaintext_release:
            raise CredentialReleaseError(
                "the enclave sent no key to seal the credential to; this broker "
                "does not release credentials in the clear"
            )
        binding = release_binding(resource, enclave_key or "")

        # Freshness: the nonce must be one we issued and have not yet spent.
        self._expire_nonces()
        if report.nonce not in self._issued_nonces:
            raise CredentialReleaseError("unknown or expired nonce (replayed attestation)")

        # Real silicon and mock silicon prove themselves differently, so the
        # shape of the signature decides which check applies.
        if looks_like_tdx(report.signature):
            self._verify_tdx(report, binding, event_log)
        elif looks_like_sevsnp(report.signature):
            self._verify_sevsnp(report, binding, certificates)
        else:
            self._verify_registered_key(report, binding)

        # Spend the nonce so this proof cannot unlock anything twice.
        self._issued_nonces.pop(report.nonce, None)
        if not enclave_key:
            return self._secrets[resource]
        try:
            return self.identity.seal(
                self._secrets[resource].dsn, enclave_key=enclave_key,
                resource=resource, nonce=report.nonce,
            )
        except SealingError as exc:
            raise CredentialReleaseError(f"cannot seal to that key: {exc}") from exc

    # -- internals -------------------------------------------------------------

    def _verify_registered_key(self, report: AttestationReport, binding: str) -> None:
        """The development path: an Ed25519 key registered in advance."""
        public_key = self._trusted_chips.get(report.chip_id)
        if public_key is None:
            raise CredentialReleaseError(
                f"chip {report.chip_id!r} is not a trusted processor"
            )
        try:
            verify(
                report,
                verifier_from_public_key(public_key),
                approved_measurement=self.policy.approved_measurement,
                expected_nonce=report.nonce,
                min_tcb=self.policy.min_tcb,
                expected_report_data=binding,
            )
        except VerificationError as exc:
            raise CredentialReleaseError(f"attestation rejected: {exc}") from exc

    def _verify_sevsnp(
        self,
        report: AttestationReport,
        binding: str,
        certificates: dict[str, bytes] | None = None,
    ) -> None:
        """The hardware path: AMD's certificate chain, anchored to a pinned root.

        The chip registry is deliberately not consulted. A processor's identity
        comes from a VCEK that chains to AMD, not from a key someone remembered
        to add to a list, and consulting both would mean the weaker check could
        admit what the stronger one refuses.
        """
        certs = certificates if certificates is not None else self.sevsnp_certs

        verifier = self.sevsnp
        if verifier is None and self.sevsnp_factory is not None:
            # Remote broker: the certificates arrived with the report instead of
            # from a local host, so the verifier is built per request around them.
            try:
                verifier = self.sevsnp_factory(certs)  # type: ignore[operator]
            except Exception as exc:  # noqa: BLE001 - enclave-supplied, treat as hostile
                raise CredentialReleaseError(f"attestation rejected: {exc}") from exc
        if verifier is None:
            raise CredentialReleaseError(
                "a SEV-SNP report was presented but this broker has no verifier "
                "configured; refusing to release against a proof it cannot check"
            )

        leaf = certs.get("VCEK") or certs.get("VLEK")
        if leaf is None:
            raise CredentialReleaseError(
                "no VCEK available for this chip; the host provisioned no "
                "certificates and AMD's KDS was not consulted"
            )

        from cryptography import x509

        # The chip signs the canonical report, not the resource binding directly,
        # so REPORT_DATA holds SHA-512 of that JSON. `verify_signed_message`
        # recomputes it, which is what ties the signature to this exact nonce,
        # chip and binding rather than to any report the chip ever produced.
        try:
            verifier.verify_signed_message(
                report.canonical(),
                report.signature,
                vcek=x509.load_der_x509_certificate(leaf),
            )
        except VerificationError as exc:
            raise CredentialReleaseError(f"attestation rejected: {exc}") from exc

        # The signature proves the chip produced this report. It says nothing
        # about which secret the report was asking for, so check that separately:
        # otherwise a proof obtained for the analytics database would unlock the
        # payments one.
        if report.report_data != binding:
            raise CredentialReleaseError(
                "attestation is bound to a different resource or key"
            )

    def _verify_tdx(
        self, report: AttestationReport, binding: str, event_log: bytes | None
    ) -> None:
        """The Intel path: Intel's chain, approved firmware, and the boot policy.

        Like SEV-SNP, the chip registry is not consulted. Unlike SEV-SNP, the
        evidence of what booted is a separate event log, which the enclave sends
        and the verifier believes only once it replays to the signed registers.
        """
        if self.tdx is None:
            raise CredentialReleaseError(
                "a TDX quote was presented but this broker has no TDX verifier "
                "configured; refusing to release against a proof it cannot check"
            )
        if not event_log:
            raise CredentialReleaseError("TDX quote arrived without its event log")
        try:
            self.tdx.verify_signed_message(  # type: ignore[attr-defined]
                report.canonical(), report.signature, event_log
            )
        except VerificationError as exc:
            raise CredentialReleaseError(f"attestation rejected: {exc}") from exc
        if report.report_data != binding:
            raise CredentialReleaseError("attestation is bound to a different resource or key")

    def _expire_nonces(self) -> None:
        now = time.monotonic()
        for nonce, expiry in list(self._issued_nonces.items()):
            if now > expiry:
                del self._issued_nonces[nonce]

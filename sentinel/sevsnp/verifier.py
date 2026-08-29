"""
Verifying a real SEV-SNP attestation report.

Five checks, and a report has to pass all of them:

    1. the VCEK chains to AMD's root      — genuine silicon, not a simulator
    2. the report signature verifies      — these exact bytes came from that chip
    3. the measurement is approved        — the expected image booted
    4. the TCB is at or above the floor   — firmware is not known-vulnerable
    5. report_data matches the binding    — this proof is for THIS request

Failing any one raises `VerificationError`, the same exception the mock path
raises, so the Key Broker and the validator do not care which backend produced
the verdict. That is the seam the whole mock-first design was built around.

What is real here and what is not: the certificate chain is genuinely AMD's,
fetched from their Key Distribution Service and verified to a self-signed root,
and the signature checking is real ECDSA P-384. What is missing is hardware to
*produce* a report — that arrives with an EPYC confidential VM, and needs no
change to this file.
"""

from __future__ import annotations

import logging
import pathlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..attestation import VerificationError
from .certs import CertChain, CertificateError, fetch_cert_chain, fetch_vcek, verify_vcek
from .report import AttestationReportBlob, ReportParseError, parse_report

logger = logging.getLogger("sentinel.sevsnp")


@dataclass
class SevSnpPolicy:
    """What a report must prove before it is accepted."""

    approved_measurement: bytes
    #: Minimum acceptable TCB components. A report below any of these is
    #: refused: approved code on vulnerable firmware is still exploitable.
    min_bootloader: int = 0
    min_tee: int = 0
    min_snp: int = 0
    min_microcode: int = 0
    #: Guest policy bit 19 — debug enabled. A debuggable guest can be inspected
    #: by its host, so a report from one proves nothing about confidentiality.
    allow_debug: bool = False

    def check(self, report: AttestationReportBlob) -> None:
        if report.measurement != self.approved_measurement:
            raise VerificationError(
                f"launch measurement mismatch (code was tampered): "
                f"got {report.measurement.hex()[:32]}…"
            )
        tcb = report.reported_tcb
        for name, actual, floor in (
            ("bootloader", tcb.bootloader, self.min_bootloader),
            ("tee", tcb.tee, self.min_tee),
            ("snp", tcb.snp, self.min_snp),
            ("microcode", tcb.microcode, self.min_microcode),
        ):
            if actual < floor:
                raise VerificationError(
                    f"stale TCB: {name} {actual} < {floor} (vulnerable firmware)"
                )
        if not self.allow_debug and (report.policy >> 19) & 1:
            raise VerificationError(
                "guest policy permits debug; the host could inspect this enclave"
            )


class SevSnpVerifier:
    """Verifies reports for one EPYC product line."""

    def __init__(
        self,
        product: str,
        policy: SevSnpPolicy,
        *,
        cache_dir: pathlib.Path | None = None,
        chain: CertChain | None = None,
        offline: bool = False,
    ) -> None:
        self.product = product
        self.policy = policy
        self.cache_dir = cache_dir
        #: Injectable so tests can supply their own root, and so an air-gapped
        #: deployment can pin a vendored chain instead of reaching KDS.
        self._chain = chain
        self.offline = offline

    # -- chain ----------------------------------------------------------------

    def cert_chain(self) -> CertChain:
        if self._chain is None:
            if self.offline:
                raise CertificateError("offline verifier has no certificate chain")
            self._chain = fetch_cert_chain(self.product, cache_dir=self.cache_dir)
        return self._chain

    # -- the verdict ----------------------------------------------------------

    def verify(
        self,
        blob: bytes,
        *,
        expected_report_data: bytes | None = None,
        vcek: object | None = None,
    ) -> AttestationReportBlob:
        """Verify a raw report. Returns it parsed, or raises `VerificationError`.

        `vcek` may be supplied directly — a guest can hand out the certificate it
        was provisioned with, which lets a verifier work without reaching KDS.
        """
        try:
            report = parse_report(blob)
        except ReportParseError as exc:
            raise VerificationError(f"malformed report: {exc}") from exc

        # 1 + 2. Prove the bytes came from a genuine chip before believing a
        # single field inside them.
        if vcek is None:
            if self.offline:
                raise VerificationError("no VCEK supplied and verifier is offline")
            try:
                vcek = fetch_vcek(
                    self.product, report.chip_id_hex, report.reported_tcb,
                    cache_dir=self.cache_dir,
                )
            except CertificateError as exc:
                raise VerificationError(f"could not obtain VCEK: {exc}") from exc

        try:
            verify_vcek(vcek, self.cert_chain())  # type: ignore[arg-type]
        except CertificateError as exc:
            raise VerificationError(f"VCEK is not endorsed by AMD: {exc}") from exc

        self._verify_signature(report, vcek)  # type: ignore[arg-type]

        # 3 + 4. Only now is it worth asking what the report says.
        self.policy.check(report)

        # 5. And whether it is a proof for this particular request.
        if expected_report_data is not None:
            expected = expected_report_data.ljust(64, b"\x00")[:64]
            if report.report_data != expected:
                raise VerificationError(
                    "response binding mismatch (proof is for a different response)"
                )
        return report

    @staticmethod
    def _verify_signature(report: AttestationReportBlob, vcek: object) -> None:
        key = vcek.public_key()  # type: ignore[attr-defined]
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise VerificationError("VCEK does not carry an ECDSA key")
        try:
            key.verify(
                report.der_signature(),
                report.signed_bytes,
                ec.ECDSA(hashes.SHA384()),
            )
        except InvalidSignature as exc:
            raise VerificationError(
                "signature invalid (not signed by a genuine chip)"
            ) from exc

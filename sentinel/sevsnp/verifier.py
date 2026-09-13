"""
Verifying a real SEV-SNP attestation report.

Five checks, and a report has to pass all of them:

    1. the VCEK chains to AMD's root     , genuine silicon, not a simulator
    2. the report signature verifies     , these exact bytes came from that chip
    3. the measurement is approved       : the expected image booted
    4. the TCB is at or above the floor  , firmware is not known-vulnerable
    5. report_data matches the binding   : this proof is for THIS request

Failing any one raises `VerificationError`, the same exception the mock path
raises, so the Key Broker and the validator do not care which backend produced
the verdict. That is the seam the whole mock-first design was built around.

The chain is genuinely AMD's and is anchored to a *pinned* root, not merely to a
self-signed one. That distinction is the whole of the trust model: a chain can be
perfectly self-consistent and entirely forged, since an attacker who generates
the root can sign every link below it. Only comparing the root against a key
known in advance separates AMD's silicon from a convincing impostor.

Reports produced by real hardware verify through this file unchanged; a captured
one is a fixture in `tests/fixtures/`.
"""

from __future__ import annotations

import logging
import pathlib
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..attestation import VerificationError
from .certs import CertChain, CertificateError, fetch_cert_chain, fetch_vcek, verify_vcek
from .report import AttestationReportBlob, ReportParseError, parse_report

logger = logging.getLogger("sentinel.sevsnp")


#: Minimum firmware the subnet accepts, per EPYC product line.
#:
#: This is **protocol, not preference**. Two verifiers using different floors
#: would accept different miners, and on the validator side Yuma penalises
#: whoever ends up outside consensus. Both the Key Broker and the validator read
#: this same constant so they cannot drift apart.
#:
#: Why it exists: a correct launch measurement on vulnerable firmware is still
#: exploitable. CVE-2025-54510 ("Fabricked") lets a malicious host on unpatched
#: AMD firmware read guest memory and forge attestation reports, and
#: CVE-2025-29952 lets an admin-level host corrupt RMP memory. AMD's own guidance
#: is to verify the reported TCB before trusting a guest. Intel published
#: equivalents for TDX in the same year, so this is the industry answer rather
#: than an AMD workaround.
#:
#: **What a floor does and does not buy.** The VCEK is derived from chip secrets
#: *and* the TCB version, so a report cannot credibly claim firmware newer than
#: the key that signed it: downgrade is refused. It does **not** prove these
#: versions are patched against everything, and it cannot help once a host has
#: already compromised the TEE and can forge the report wholesale. It stops the
#: case that actually happens, which is an honest operator on stale firmware.
#:
#: Keyed by product because TCB components are not comparable across
#: generations. Only Milan is listed, which costs nothing today: `CertChain`
#: already fails closed for products with no pinned AMD root, so a Genoa miner
#: cannot participate either way. Adding a product means pinning its root *and*
#: establishing its floor.
#:
#: Observed on the reference miner, GCP n2d-standard-2, 2026-09-11.
#: The firmware floor, per product line, taken from AMD's security bulletins
#: rather than from whatever our own hosts happen to report. Those are two
#: different numbers and only the first one is a security boundary.
#:
#: Milan: AMD-SB-3030 (May 2026) requires TCB[SNP] >= 0x1D for EPYC 7003 to
#: mitigate CVE-2025-61971, where missing NBIO register lock bits let a
#: host-privileged attacker alter MMIO routing and break SEV-SNP guest
#: integrity. 0x1D is 29, which is what our own silicon reports, so the floor
#: is met with no margin rather than by luck.
#:
#: Only SNP is floored. AMD publishes TCB floors for the components where a
#: floor is meaningful, and for Milan that is SNP alone: TCB[BL] and TCB[TEE]
#: floors exist for Genoa and Turin respectively, not for this product.
#:
#: Microcode is deliberately not floored, and this is the subtle one. AMD
#: publishes Milan microcode fixes per stepping, B1 0x0A0011DE and B2
#: 0x0A001247, and the TCB field carries the low byte: 222 for B1 and 71 for
#: B2. Both are patched, and the numbers are not comparable. A single global
#: microcode floor of 222 would refuse every fully patched B2 part. Flooring
#: microcode correctly means reading CPUID stepping out of the report and
#: keeping a per-stepping table, which is a real feature and not a constant.
MIN_TCB: Final[dict[str, dict[str, int]]] = {
    "Milan": {
        "min_snp": 0x1D,
    },
}


def min_tcb_for(product: str) -> dict[str, int]:
    """The firmware floor for `product`, or empty if none is established.

    Empty means no floor rather than a refusal, because the refusal already
    happens earlier and more decisively: an unpinned product has no AMD root to
    verify its chain against, so it never reaches a policy check.
    """
    return dict(MIN_TCB.get(product, {}))


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
    #: Guest policy bit 19, debug enabled. A debuggable guest can be inspected
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

        `vcek` may be supplied directly, a guest can hand out the certificate it
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

    def verify_signed_message(
        self,
        message: bytes,
        report_hex: str,
        *,
        vcek: object | None = None,
    ) -> AttestationReportBlob:
        """Verify a report produced by `SevSnpSilicon.sign(message)`.

        The chip binds SHA-512 of the message into REPORT_DATA, so verification
        recomputes that digest and checks it matches. This is the counterpart to
        `Verifier.valid(message, signature)` in the mock path, same question,
        asked of real hardware.
        """
        import hashlib

        try:
            blob = bytes.fromhex(report_hex)
        except ValueError as exc:
            raise VerificationError(f"report is not valid hex: {exc}") from exc

        return self.verify(
            blob,
            expected_report_data=hashlib.sha512(message).digest(),
            vcek=vcek,
        )

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

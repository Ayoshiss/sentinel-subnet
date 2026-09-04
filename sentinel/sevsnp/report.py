"""
Parsing the SEV-SNP ATTESTATION_REPORT structure.

The report is a fixed 1184-byte block produced by the AMD Secure Processor. It
carries what the chip is willing to swear to about a running guest: which code
booted (MEASUREMENT), what firmware is underneath (TCB versions), which chip
produced it (CHIP_ID), and 64 caller-supplied bytes (REPORT_DATA) that bind the
report to a specific request. The last 512 bytes are an ECDSA P-384 signature by
the chip's VCEK over everything preceding it.

Layout follows the AMD SEV Secure Nested Paging Firmware ABI Specification
(table "ATTESTATION_REPORT Structure"). Offsets are asserted in the tests rather
than trusted, because a silently wrong offset would parse without error and
verify against the wrong bytes, the worst possible failure mode here.

Two details that are easy to get wrong and fatal if you do:

    * the signature covers bytes [0, 0x2A0), not the whole blob
    * R and S are little-endian in the report, but DER wants big-endian ints
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

#: Total size of the report structure.
REPORT_SIZE: Final = 0x4A0  # 1184

#: The signature covers everything before the SIGNATURE field.
SIGNATURE_OFFSET: Final = 0x2A0
SIGNED_LENGTH: Final = SIGNATURE_OFFSET

#: ECDSA P-384 component width inside the report's signature field.
_SIG_COMPONENT_LEN: Final = 72

#: SIGNATURE_ALGO value for ECDSA P-384 with SHA-384.
SIG_ALGO_ECDSA_P384_SHA384: Final = 1


class ReportParseError(Exception):
    pass


@dataclass(frozen=True)
class TcbVersion:
    """A packed Trusted Computing Base version, the firmware floor.

    Verifying a measurement is not enough on its own: approved code running on
    vulnerable firmware is still exploitable, so a policy checks the TCB too.
    """

    bootloader: int
    tee: int
    snp: int
    microcode: int
    raw: int

    @classmethod
    def unpack(cls, value: int) -> "TcbVersion":
        return cls(
            bootloader=value & 0xFF,
            tee=(value >> 8) & 0xFF,
            snp=(value >> 48) & 0xFF,
            microcode=(value >> 56) & 0xFF,
            raw=value,
        )

    def __str__(self) -> str:
        return f"bl{self.bootloader}.tee{self.tee}.snp{self.snp}.ucode{self.microcode}"


@dataclass(frozen=True)
class AttestationReportBlob:
    """A parsed SEV-SNP report. Parsing proves nothing: verification does."""

    version: int
    guest_svn: int
    policy: int
    family_id: bytes
    image_id: bytes
    vmpl: int
    signature_algo: int
    current_tcb: TcbVersion
    platform_info: int
    report_data: bytes        # 64 caller-supplied bytes (our nonce binding)
    measurement: bytes        # 48 bytes: which code booted
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    report_id_ma: bytes
    reported_tcb: TcbVersion
    chip_id: bytes            # 64 bytes, identifies the physical processor
    committed_tcb: TcbVersion
    launch_tcb: TcbVersion
    signature_r: bytes
    signature_s: bytes
    raw: bytes

    @property
    def signed_bytes(self) -> bytes:
        """The region the VCEK signature covers."""
        return self.raw[:SIGNED_LENGTH]

    @property
    def measurement_hex(self) -> str:
        return self.measurement.hex()

    @property
    def chip_id_hex(self) -> str:
        """Uppercase hex, the form AMD's KDS expects in a VCEK request."""
        return self.chip_id.hex().upper()

    def der_signature(self) -> bytes:
        """Repack R and S into the DER sequence `cryptography` verifies with.

        The report stores each component little-endian and zero-padded to 72
        bytes; DER wants big-endian INTEGERs with no padding.
        """
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        r = int.from_bytes(self.signature_r[:48], "little")
        s = int.from_bytes(self.signature_s[:48], "little")
        return encode_dss_signature(r, s)


def parse_report(blob: bytes) -> AttestationReportBlob:
    """Parse a raw report. Raises `ReportParseError` on anything malformed."""
    if len(blob) < REPORT_SIZE:
        raise ReportParseError(
            f"report is {len(blob)} bytes, expected at least {REPORT_SIZE}"
        )
    # Longer inputs are tolerated: /dev/sev-guest returns the report inside a
    # larger response struct, so trailing bytes are normal and not an error.
    blob = blob[:REPORT_SIZE]

    u32 = lambda off: struct.unpack_from("<I", blob, off)[0]  # noqa: E731
    u64 = lambda off: struct.unpack_from("<Q", blob, off)[0]  # noqa: E731

    report = AttestationReportBlob(
        version=u32(0x000),
        guest_svn=u32(0x004),
        policy=u64(0x008),
        family_id=blob[0x010:0x020],
        image_id=blob[0x020:0x030],
        vmpl=u32(0x030),
        signature_algo=u32(0x034),
        current_tcb=TcbVersion.unpack(u64(0x038)),
        platform_info=u64(0x040),
        report_data=blob[0x050:0x090],
        measurement=blob[0x090:0x0C0],
        host_data=blob[0x0C0:0x0E0],
        id_key_digest=blob[0x0E0:0x110],
        author_key_digest=blob[0x110:0x140],
        report_id=blob[0x140:0x160],
        report_id_ma=blob[0x160:0x180],
        reported_tcb=TcbVersion.unpack(u64(0x180)),
        chip_id=blob[0x1A0:0x1E0],
        committed_tcb=TcbVersion.unpack(u64(0x1E0)),
        launch_tcb=TcbVersion.unpack(u64(0x1F0)),
        signature_r=blob[SIGNATURE_OFFSET:SIGNATURE_OFFSET + _SIG_COMPONENT_LEN],
        signature_s=blob[SIGNATURE_OFFSET + _SIG_COMPONENT_LEN:
                         SIGNATURE_OFFSET + 2 * _SIG_COMPONENT_LEN],
        raw=blob,
    )

    if report.version == 0:
        raise ReportParseError("report version is 0; this is not a SEV-SNP report")
    if report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384:
        raise ReportParseError(
            f"unsupported signature algorithm {report.signature_algo}; "
            f"only ECDSA P-384 with SHA-384 ({SIG_ALGO_ECDSA_P384_SHA384}) is defined"
        )
    return report

"""
Asking the chip for an attestation report.

Inside a SEV-SNP guest, `/dev/sev-guest` accepts an ioctl that hands 64 bytes of
caller data to the AMD Secure Processor and returns a report signed by the VCEK.
Those 64 bytes are the whole point: they are what binds a report to one specific
request, so a miner cannot produce an answer before being asked for it.

This is the half that needs hardware. It is deliberately thin — the request and
response encoding is pure and tested, and only the ioctl itself touches the
device, so everything except one syscall can be verified on a laptop.

Mapping onto the `Silicon` protocol takes one idea: a SEV-SNP chip does not sign
arbitrary messages, it produces a report bound to 64 bytes. So the message is
hashed to exactly 64 bytes with SHA-512 and used as `user_data`, and the whole
report becomes the "signature". Verification reverses it. The interface above
never changes.
"""

from __future__ import annotations

import logging
import pathlib
import struct
from typing import Final

from .report import REPORT_SIZE, parse_report

logger = logging.getLogger("sentinel.sevsnp.guest")

DEVICE: Final = "/dev/sev-guest"

#: _IOWR('S', 0x0, sizeof(struct snp_guest_request_ioctl)) — computed, not copied.
SNP_GET_REPORT: Final = 0xC0185300

#: struct snp_report_req { u8 user_data[64]; u32 vmpl; u8 rsvd[28]; }
REQ_SIZE: Final = 96
#: struct snp_report_resp { u8 data[4000]; }
RESP_SIZE: Final = 4000
#: The response opens with status, report_size and 24 reserved bytes; the
#: report itself starts after that header, not at offset zero.
RESP_HEADER_SIZE: Final = 32

MSG_VERSION: Final = 1


class GuestError(Exception):
    """The chip could not or would not produce a report."""


def available() -> bool:
    """Whether this machine is a SEV-SNP guest that can be asked for a report."""
    return pathlib.Path(DEVICE).exists()


def build_request(user_data: bytes, vmpl: int = 0) -> bytes:
    """Encode `struct snp_report_req`.

    `user_data` must be exactly 64 bytes: it lands verbatim in the report's
    REPORT_DATA field, and padding it silently would let two different requests
    produce the same binding.
    """
    if len(user_data) != 64:
        raise GuestError(f"user_data must be exactly 64 bytes, got {len(user_data)}")
    if not 0 <= vmpl <= 3:
        raise GuestError(f"vmpl must be 0-3, got {vmpl}")
    return user_data + struct.pack("<I", vmpl) + bytes(28)


def parse_response(resp: bytes) -> bytes:
    """Pull the raw report out of `struct snp_report_resp`."""
    if len(resp) < RESP_HEADER_SIZE + REPORT_SIZE:
        raise GuestError(
            f"response is {len(resp)} bytes, too short to contain a report"
        )
    status, report_size = struct.unpack_from("<II", resp, 0)
    if status != 0:
        raise GuestError(f"firmware returned status {status}")
    if report_size < REPORT_SIZE:
        raise GuestError(f"firmware reported {report_size} bytes, expected {REPORT_SIZE}")
    return resp[RESP_HEADER_SIZE:RESP_HEADER_SIZE + REPORT_SIZE]


def request_report(user_data: bytes, vmpl: int = 0, device: str = DEVICE) -> bytes:
    """Ask the chip for a report bound to `user_data`. Requires a SEV-SNP guest.

    The only function here that touches hardware. Everything it depends on is
    tested independently, so bringing this up on a confidential VM is a matter
    of confirming one syscall rather than debugging a stack.
    """
    import fcntl  # Linux-only; imported late so this module loads anywhere.

    req = build_request(user_data, vmpl)
    resp = bytearray(RESP_SIZE)

    # The ioctl struct holds pointers to the request and response buffers, so
    # both must stay alive and pinned for the duration of the call.
    req_buf = bytearray(req)
    req_addr = _address_of(req_buf)
    resp_addr = _address_of(resp)

    ioctl_struct = bytearray(struct.pack("<BxxxxxxxQQQ", MSG_VERSION, req_addr, resp_addr, 0))

    try:
        with open(device, "rb") as fd:
            fcntl.ioctl(fd, SNP_GET_REPORT, ioctl_struct, True)
    except FileNotFoundError as exc:
        raise GuestError(
            f"{device} not present; this is not a SEV-SNP guest"
        ) from exc
    except OSError as exc:
        _, _, _, exitinfo2 = struct.unpack("<BxxxxxxxQQQ", bytes(ioctl_struct))
        raise GuestError(f"ioctl failed: {exc} (exitinfo2=0x{exitinfo2:x})") from exc

    return parse_response(bytes(resp))


def _address_of(buf: bytearray) -> int:
    """Stable address of a mutable buffer, for the ioctl's pointer fields."""
    import ctypes

    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))


# --- Silicon protocol ---------------------------------------------------------

class SevSnpSilicon:
    """Real AMD silicon behind the same `Silicon` interface as `MockSilicon`.

    `sign()` returns a full attestation report as hex rather than a bare
    signature, because that is what a chip actually produces. The verifier
    understands both, so nothing upstream cares.
    """

    def __init__(self, vmpl: int = 0, device: str = DEVICE) -> None:
        if not pathlib.Path(device).exists():
            raise GuestError(
                f"{device} not present; SevSnpSilicon needs a SEV-SNP guest. "
                "Use MockSilicon for development."
            )
        self.vmpl = vmpl
        self.device = device
        self._chip_id: str | None = None

    @property
    def chip_id(self) -> str:
        """CHIP_ID from a report. Cached — it does not change."""
        if self._chip_id is None:
            blob = request_report(bytes(64), self.vmpl, self.device)
            self._chip_id = parse_report(blob).chip_id_hex
        return self._chip_id

    def sign(self, message: bytes) -> str:
        """A report bound to `message`, hex encoded.

        SHA-512 gives exactly the 64 bytes REPORT_DATA holds, so the binding is
        the full digest with no truncation or padding.
        """
        import hashlib

        user_data = hashlib.sha512(message).digest()
        return request_report(user_data, self.vmpl, self.device).hex()

    def public_verifier(self):  # pragma: no cover - needs hardware
        raise GuestError(
            "verify SEV-SNP reports with SevSnpVerifier, which checks the AMD "
            "certificate chain; a bare public key is not sufficient"
        )

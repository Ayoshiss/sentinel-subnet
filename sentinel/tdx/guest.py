"""
Asking a TDX guest for a quote.

Linux exposes TDX quote generation through configfs: make a directory under
`/sys/kernel/config/tsm/report`, write 64 bytes to `inblob`, read the quote from
`outblob`. The 64 bytes land in REPORT_DATA, and as on SEV-SNP they are what
binds a quote to one specific request.

Two TDX-specific details. The quote does not carry the boot story, only its
digest, so a miner also hands over the firmware's event log (the ACPI CCEL
table) for the verifier to replay. And there is no chip ID: TDX deliberately
does not expose one, so this uses a digest of the platform's PCK certificate,
which is stable for a machine and public anyway, since it travels in every
quote.

configfs-tsm is safe under concurrency in a way `/dev/sev-guest` is not: each
directory is its own request, and `generation` counts writes so a reader can
tell whether someone else wrote between its write and its read. One directory
per request, checked, is enough. There is no key to brick.
"""

from __future__ import annotations

import hashlib
import pathlib
import secrets
import threading
from typing import Final

from . import eventlog

TSM_REPORT: Final = "/sys/kernel/config/tsm/report"
CCEL: Final = "/sys/firmware/acpi/tables/data/CCEL"
PROVIDER: Final = "tdx_guest"

_PEM_BEGIN: Final = b"-----BEGIN CERTIFICATE-----"
_PEM_END: Final = b"-----END CERTIFICATE-----"


class GuestError(Exception):
    """The TDX module could not or would not produce a quote."""


def available(root: str = TSM_REPORT, ccel: str = CCEL) -> bool:
    """Whether this machine can produce TDX quotes and has an event log to send."""
    return pathlib.Path("/dev/tdx_guest").exists() and pathlib.Path(root).is_dir() and pathlib.Path(ccel).exists()


def request_quote(user_data: bytes, root: str = TSM_REPORT) -> bytes:
    """A quote with `user_data` in REPORT_DATA. Requires a TDX guest."""
    if len(user_data) != 64:
        raise GuestError(f"user_data must be exactly 64 bytes, got {len(user_data)}")
    entry = pathlib.Path(root) / f"sentinel-{secrets.token_hex(8)}"
    try:
        entry.mkdir()
    except OSError as exc:
        raise GuestError(f"cannot create {entry}: {exc}") from exc
    try:
        return read_quote(entry, user_data)
    finally:
        try:
            entry.rmdir()
        except OSError:
            pass


def read_quote(entry: pathlib.Path, user_data: bytes) -> bytes:
    """Write `user_data` to an existing report entry and read its quote back."""
    try:
        provider = (entry / "provider").read_text().strip()
        if provider != PROVIDER:
            raise GuestError(f"report provider is {provider!r}, not {PROVIDER}")
        (entry / "inblob").write_bytes(user_data)
        written = int((entry / "generation").read_text())
        quote = (entry / "outblob").read_bytes()
        if int((entry / "generation").read_text()) != written:
            raise GuestError("another writer changed this report entry mid-request")
    except OSError as exc:
        raise GuestError(f"quote request failed: {exc}") from exc

    start = eventlog.BODY + eventlog.REPORT_DATA
    if len(quote) < start + 64 or quote[start : start + 64] != user_data:
        # The cheapest check that this quote is the answer to this request.
        raise GuestError("quote does not carry the requested REPORT_DATA")
    return quote


def pck_leaf(quote: bytes) -> bytes:
    """The first certificate in the quote's PCK chain, PEM, which is the platform's."""
    start = quote.find(_PEM_BEGIN)
    end = quote.find(_PEM_END, start)
    if start < 0 or end < 0:
        raise GuestError("quote carries no PCK certificate")
    return quote[start : end + len(_PEM_END)]


class TdxSilicon:
    """Intel TDX behind the same `Silicon` interface as `MockSilicon`.

    `sign()` returns a whole quote as hex, as `SevSnpSilicon` returns a whole
    report. `event_log` is what the miner advertises for verifiers to replay.
    """

    def __init__(self, root: str = TSM_REPORT, ccel: str = CCEL) -> None:
        if not pathlib.Path(root).is_dir():
            raise GuestError(
                f"{root} not present; TdxSilicon needs a TDX guest with configfs-tsm. "
                "Use MockSilicon for development."
            )
        self.root = root
        self.ccel = ccel
        self._chip_id: str | None = None
        self._log: bytes | None = None
        self._lock = threading.Lock()

    @property
    def chip_id(self) -> str:
        """`TDX-` and a digest of this platform's PCK certificate. Cached."""
        if self._chip_id is None:
            leaf = pck_leaf(self._quote(bytes(64)))
            self._chip_id = "TDX-" + hashlib.sha256(leaf).hexdigest()[:16]
        return self._chip_id

    @property
    def event_log(self) -> bytes:
        """The firmware's event log. Fixed for the life of the boot, so read once."""
        if self._log is None:
            try:
                self._log = pathlib.Path(self.ccel).read_bytes()
            except OSError as exc:
                raise GuestError(f"cannot read the event log at {self.ccel}: {exc}") from exc
        return self._log

    @property
    def measurement(self) -> str:
        """The image the firmware loaded, as the event log records it.

        The Authenticode digest of the UKI, which is what the registry approves.
        Like `SevSnpSilicon.measurement`, read it to learn the value and pin it,
        never to fill in the policy that checks it. Empty if the log names no
        image; the first if it names several, which the verifier will refuse.
        """
        images = [
            e.digest.hex()
            for e in eventlog.events(self.event_log)
            if e.type == eventlog.EV_EFI_BOOT_SERVICES_APPLICATION
        ]
        return images[0] if images else ""

    @property
    def mrtd(self) -> str:
        """The TD firmware measurement, which validators must also approve."""
        return eventlog.registers(self._quote(bytes(64)))["MRTD"]

    def sign(self, message: bytes) -> str:
        """A quote bound to SHA-512 of `message`, hex encoded."""
        return self._quote(hashlib.sha512(message).digest()).hex()

    def _quote(self, user_data: bytes) -> bytes:
        # Not needed for safety, as it is on SEV-SNP. It keeps one miner's
        # requests from queueing inside the kernel behind each other.
        with self._lock:
            return request_quote(user_data, self.root)

    def public_verifier(self):  # pragma: no cover - needs hardware
        raise GuestError(
            "verify TDX quotes with TdxVerifier, which checks Intel's chain; "
            "a bare public key is not sufficient"
        )


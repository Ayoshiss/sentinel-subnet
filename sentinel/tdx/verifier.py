"""
Verifying a real Intel TDX quote.

Five checks, and a quote has to pass all of them:

    1. Intel signed it, at a current TCB   , genuine TDX, firmware not known-vulnerable
    2. the TD is not debuggable            : the host cannot read its memory
    3. MRTD is approved                    : the TD's own firmware is one we know
    4. the event log replays, and passes   : Secure Boot under our key, only the
       the boot policy                       approved image loaded
    5. REPORT_DATA matches the binding     : this proof is for THIS request

Failing any one raises `VerificationError`, the same exception the mock and
SEV-SNP paths raise, so the validator does not care which backend it is judging.

Check 1 is dcap-qvl, Phala's Intel DCAP verifier, with Intel's SGX root CA
pinned inside it. The pinned root was compared byte for byte with the root in
quotes from our own hardware. Intel's verification is not reimplemented here:
it is a certificate chain, two CRLs, signed TCB and QE identity documents and a
TCB level match, and a library that already passes Intel's cases is worth more
than one written to pass our own.

Check 3 is the one that is easy to leave out. The TD firmware (TDVF) is what
measures everything above it and what enforces Secure Boot, so a host that
supplies its own firmware could write any event log it liked. The log means
something only once MRTD says the firmware is one we approved. On GCP that
value is Google's firmware and was identical on every quote we have captured,
across several hosts, 3 to 6 November 2026.

Checks 4 and 5 are ours, because they are what Sentinel means by "approved
code": the boot policy from the 2026-11-06 Secure Boot experiment, checked over
a log that must first replay to exactly the registers Intel signed.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import logging
import time
import zlib
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Callable, Final, Iterable

from ..attestation import VerificationError
from . import eventlog

logger = logging.getLogger("sentinel.tdx")

#: Any PCCS works: everything it serves is signed by Intel and checked against
#: the pinned root, so it is a transport and not a trust anchor. Phala's is the
#: default because Intel's own PCS needs an API key for some endpoints.
PCCS_URL: Final = "https://pccs.phala.network"

#: The oldest dcap-qvl accepted. Releases before 0.3 did not check the QE
#: report against Intel's QE Identity (CVE-2026-22696). 0.7.1 is the version
#: these checks were built and tested against.
MIN_DCAP_QVL: Final = (0, 7, 1)

#: Intel TCB statuses the subnet accepts.
#:
#: **Protocol, not preference**, for the same reason as `sevsnp.MIN_TCB`: two
#: validators accepting different statuses would score the same miner
#: differently and Yuma would penalise whichever is out of consensus.
#:
#: Only UpToDate. Every quote we have captured on GCP reports it, so nothing
#: honest is refused today. The statuses that say a platform needs software
#: hardening or configuration are deliberately not accepted yet: each comes with
#: advisories that have to be read before deciding they do not matter for us.
ALLOWED_TCB_STATUS: Final = frozenset({"UpToDate"})

#: TD_ATTRIBUTES bit 0. A debug TD lets the host read and write its memory.
TD_DEBUG: Final = 1 << 0

#: Ceiling on a decompressed event log. The firmware's table is 256 KiB; this
#: leaves room and stops a miner from sending a decompression bomb.
MAX_EVENT_LOG: Final = 1 << 20


def _hexset(values: Iterable[str]) -> frozenset[str]:
    return frozenset(v.strip().lower() for v in values if v and v.strip())


def _dcap_qvl():
    """Import dcap-qvl, refusing versions older than `MIN_DCAP_QVL`.

    Imported lazily so the mock and SEV-SNP paths run without it installed.
    """
    try:
        import dcap_qvl

        installed = version("dcap-qvl")
    except (ImportError, PackageNotFoundError) as exc:
        raise VerificationError("dcap-qvl is not installed; cannot verify TDX") from exc
    parts = tuple(int(p) for p in installed.split(".")[:3] if p.isdigit())
    if parts < MIN_DCAP_QVL:
        raise VerificationError(
            f"dcap-qvl {installed} is older than {'.'.join(map(str, MIN_DCAP_QVL))}"
        )
    return dcap_qvl


def _run(fn, *args):
    """Await `fn(*args)` from sync code, even when called inside an event loop.

    The validator scores miners synchronously from inside its asyncio loop, so
    `asyncio.run` there would fail. A fresh thread gets its own loop. `fn` is
    called inside that loop rather than before it: dcap-qvl's Rust futures bind
    to the running loop when created, and fail with "no running event loop"
    otherwise, which is how this was found on hardware.
    """
    async def call():
        return await fn(*args)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, call()).result()


# -- the wire format for the event log ----------------------------------------

def encode_event_log(log: bytes) -> bytes:
    """Compress a CCEL table for transport. It is 256 KiB, nearly all zeros."""
    return zlib.compress(log, 9)


def decode_event_log(data: bytes) -> bytes:
    """Inverse of `encode_event_log`, bounded, for a log a miner sent us."""
    inflater = zlib.decompressobj()
    try:
        log = inflater.decompress(data, MAX_EVENT_LOG)
    except zlib.error as exc:
        raise VerificationError(f"event log is not valid zlib: {exc}") from exc
    if inflater.unconsumed_tail or not inflater.eof:
        raise VerificationError("event log is truncated or larger than any firmware table")
    return log


# -- collateral ---------------------------------------------------------------

def chain_key(quote: bytes) -> str:
    """Which machine a quote came from, for caching that machine's collateral.

    Collateral is per machine, not per CPU model: it carries the PCK certificate
    chain, and verifying one machine's quote with another's collateral fails.
    """
    dcap_qvl = _dcap_qvl()
    try:
        chain = dcap_qvl.Quote.parse(quote).cert_chain_pem_bytes()
    except Exception as exc:  # noqa: BLE001 - miner-supplied bytes
        raise VerificationError(f"malformed quote: {exc}") from exc
    if not chain:
        raise VerificationError("quote carries no PCK certificate chain")
    return hashlib.sha256(chain).hexdigest()[:16]


class CollateralCache:
    """Intel's collateral for each machine, fetched once and reused.

    There is no expiry timer. Collateral is used until a quote stops verifying
    against it, then fetched again once; Intel's own dates decide when it is
    stale, rather than a guess here.
    """

    def __init__(self, pccs_url: str = PCCS_URL, *, fetch: Callable[[bytes], Any] | None = None) -> None:
        self.pccs_url = pccs_url
        self._fetch = fetch or self._from_pccs
        self._by_machine: dict[str, Any] = {}

    def _from_pccs(self, quote: bytes) -> Any:
        return _run(_dcap_qvl().get_collateral, self.pccs_url, quote)

    def get(self, quote: bytes, *, refresh: bool = False) -> Any:
        key = chain_key(quote)
        if refresh or key not in self._by_machine:
            try:
                self._by_machine[key] = self._fetch(quote)
            except Exception as exc:  # noqa: BLE001 - network or PCCS failure
                raise VerificationError(f"could not obtain Intel collateral: {exc}") from exc
        return self._by_machine[key]


# -- policy -------------------------------------------------------------------

@dataclass
class TdxPolicy:
    """What a quote and its event log must prove before they are accepted."""

    #: Authenticode SHA-384 of each approved UKI. Computable from the file, so
    #: anyone can check an entry without booting it.
    approved_uki: Iterable[str]
    #: Approved TD firmware. See the module docstring for why this is needed.
    approved_mrtd: Iterable[str]
    #: The DER certificate in the image's Secure Boot db, or several during a
    #: key rotation. The boot must be signed under exactly one of them.
    db_cert: bytes | Iterable[bytes]
    allowed_tcb_status: frozenset[str] = field(default=ALLOWED_TCB_STATUS)

    def check(self, quote: bytes, log: bytes) -> str:
        """Checks 2 to 4. Returns the approved UKI digest that booted."""
        body = eventlog.BODY
        attributes = int.from_bytes(
            quote[body + eventlog.TD_ATTRIBUTES : body + eventlog.TD_ATTRIBUTES + 8], "little"
        )
        if attributes & TD_DEBUG:
            raise VerificationError("TD is debuggable; the host could read its memory")

        signed = eventlog.registers(quote)
        if signed["MRTD"] not in _hexset(self.approved_mrtd):
            raise VerificationError(f"TD firmware is not approved: MRTD {signed['MRTD'][:32]}…")

        # Hostile input from here on: the log is whatever the miner sent.
        try:
            evs = eventlog.events(log)
            replayed = eventlog.replay(evs)
        except Exception as exc:  # noqa: BLE001
            raise VerificationError(f"unreadable event log: {exc}") from exc
        for r in ("RTMR0", "RTMR1", "RTMR2"):
            if replayed[r] != signed[r]:
                raise VerificationError(f"event log does not replay to the signed {r}")

        images = [e.digest.hex() for e in evs if e.type == eventlog.EV_EFI_BOOT_SERVICES_APPLICATION]
        approved = _hexset(self.approved_uki)
        # The policy below insists this is the only image loaded; picking it out
        # first just lets a refusal say what else was there.
        uki = next((i for i in images if i in approved), None)
        if uki is None:
            raise VerificationError(
                f"booted image is not approved: {[i[:16] for i in images]}"
            )
        certs = [self.db_cert] if isinstance(self.db_cert, (bytes, bytearray)) else list(self.db_cert)
        if not certs:
            raise VerificationError("no Secure Boot certificate is approved")
        failures: list[str] = []
        for cert in certs:
            try:
                failures = eventlog.boot_policy(evs, uki=uki, db_cert=bytes(cert))
            except Exception as exc:  # noqa: BLE001
                raise VerificationError(f"unreadable event log: {exc}") from exc
            if not failures:
                return uki
        raise VerificationError("boot policy: " + "; ".join(failures))


@dataclass(frozen=True)
class TdxEvidence:
    """What a verified quote established."""

    uki: str
    mrtd: str
    tcb_status: str
    advisory_ids: tuple[str, ...]
    report_data: bytes


class TdxVerifier:
    """Verifies TDX quotes against one policy."""

    def __init__(
        self,
        policy: TdxPolicy,
        *,
        collateral: CollateralCache | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.policy = policy
        self.collateral = collateral or CollateralCache()
        self.clock = clock or time.time

    def verify(
        self,
        quote: bytes,
        log: bytes,
        *,
        expected_report_data: bytes | None = None,
    ) -> TdxEvidence:
        """Verify a raw quote and its event log, or raise `VerificationError`."""
        # 1. Prove the bytes came from genuine TDX before believing any field.
        report = self._intel(quote)
        if report.status not in self.policy.allowed_tcb_status:
            raise VerificationError(
                f"TCB status {report.status} is not accepted "
                f"(advisories: {', '.join(report.advisory_ids) or 'none'})"
            )

        # 2 to 4. Only now is it worth asking what the quote says.
        uki = self.policy.check(quote, log)

        # 5. And whether it is a proof for this particular request.
        start = eventlog.BODY + eventlog.REPORT_DATA
        report_data = quote[start : start + 64]
        if expected_report_data is not None:
            if report_data != expected_report_data.ljust(64, b"\x00")[:64]:
                raise VerificationError(
                    "response binding mismatch (proof is for a different response)"
                )
        return TdxEvidence(
            uki=uki,
            mrtd=eventlog.registers(quote)["MRTD"],
            tcb_status=report.status,
            advisory_ids=tuple(report.advisory_ids),
            report_data=report_data,
        )

    def verify_signed_message(self, message: bytes, quote_hex: str, log: bytes) -> TdxEvidence:
        """Verify a quote whose REPORT_DATA is SHA-512 of `message`.

        The TDX counterpart of `SevSnpVerifier.verify_signed_message`: same
        binding, so the miner side signs a report the same way on either chip.
        """
        try:
            quote = bytes.fromhex(quote_hex)
        except ValueError as exc:
            raise VerificationError(f"quote is not valid hex: {exc}") from exc
        return self.verify(quote, log, expected_report_data=hashlib.sha512(message).digest())

    def _intel(self, quote: bytes):
        """Check 1, retrying once with fresh collateral if the cached set fails."""
        dcap_qvl = _dcap_qvl()
        now = int(self.clock())
        last: Exception | None = None
        for refresh in (False, True):
            collateral = self.collateral.get(quote, refresh=refresh)
            try:
                return dcap_qvl.verify(quote, collateral, now)
            except Exception as exc:  # noqa: BLE001 - dcap-qvl raises ValueError
                last = exc
                logger.info("TDX quote failed Intel verification (refresh=%s): %s", refresh, exc)
        raise VerificationError(f"not a valid Intel TDX quote: {last}")

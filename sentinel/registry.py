"""
The approved measurement registry.

A validator has to know which launch measurements count as approved, and until
this existed the only way it found out was somebody typing a value into a chat
message. That works for one validator. It fails for two: hold different lists and
you score the same miner differently, and under Yuma the one that withheld weight
from an honest miner accrues no bond in it, so it collects none of the dividend
flowing from that column. Bonds are an EMA, so the loss outlives the mistake.

The shape here is a manifest, not a list. What goes on chain is small and fixed:
a version, the block the entry takes effect, and a digest of the list. The list
itself is served as a file. Validators fetch the file and check it against the
digest, so the chain is the authority on *which* list is current while the file
carries the detail. That sidesteps the 1536-byte ceiling on commitments, and a
bug in the SDK that silently drops the larger field type on read.

Two separate synchronisation problems, two separate mechanisms:

    effective_from   the publisher's timing. Everyone switches at one height
                     rather than whenever they happened to poll.
    block-pinned     the reader's timing. Pinning a read to one block gives
    reads            every validator identical bytes regardless of cadence.

Reading "at the epoch boundary" is not a substitute for either: the epoch fire
block is not deterministic in advance, since an owner can pull it earlier and a
per-block cap can defer it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

CURRENT_VERSION = 1


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class ApprovedImage:
    """One approved measurement, with the recipe that produced it.

    The recipe is not decoration. A bare list of hashes makes the publisher
    authoritative: nobody else can tell whether an entry is real. Publishing the
    image, machine type and firmware alongside means an operator can rebuild that
    configuration and check the value for themselves, which makes the list
    verifiable rather than merely signed.
    """

    measurement: str
    platform: str
    image: str
    machine_type: str
    #: Where it was measured. Recorded for reproduction, not as the cause: the
    #: digest varies with the host's firmware version, which rolls out unevenly,
    #: so two hosts in one zone can differ and two zones can match.
    observed_in: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        m = self.measurement
        if len(m) != 96 or any(c not in "0123456789abcdef" for c in m.lower()):
            raise RegistryError(
                f"measurement must be 96 hex characters (48 bytes), got {len(m)}"
            )


@dataclass(frozen=True)
class Registry:
    version: int
    netuid: int
    #: The block height from which these measurements apply. It is NOT part of
    #: the file and NOT covered by the digest: it comes from the chain.
    #:
    #: Keeping it out of the file removes a whole class of mistake. If the
    #: height lived in the file, republishing at a new height would change the
    #: digest, so the file and the commitment would have to be updated in
    #: lockstep, and getting the order wrong would point every validator at a
    #: digest that does not match what they fetch.
    effective_from: int
    images: tuple[ApprovedImage, ...]

    @property
    def measurements(self) -> frozenset[str]:
        return frozenset(i.measurement.lower() for i in self.images)

    def active_at(self, block: int) -> bool:
        return block >= self.effective_from


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """The exact bytes the digest is taken over.

    Sorted keys and no whitespace, so reformatting the file by hand cannot
    change the digest and silently orphan every validator. `effective_from` is
    stripped if present, because scheduling is the chain's business and the
    file should not change when only the schedule does.
    """
    body = {k: v for k, v in payload.items() if k != "effective_from"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def parse(
    raw: bytes | str,
    *,
    expect_digest: str | None = None,
    effective_from: int = 0,
) -> Registry:
    """Parse a registry file, optionally checking it against a known digest.

    `expect_digest` is the whole point of the design: it comes from the chain,
    so the file can be served from anywhere without that host being able to
    change which images are approved. Tamper with the file and every validator
    refuses it loudly, rather than one of them quietly scoring differently.
    """
    body = raw.decode() if isinstance(raw, bytes) else raw
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"registry is not valid JSON: {exc}") from exc

    if expect_digest is not None:
        actual = digest(payload)
        if actual != expect_digest.lower():
            raise RegistryError(
                f"registry digest mismatch: chain says {expect_digest[:16]}…, "
                f"file is {actual[:16]}…"
            )

    version = payload.get("version")
    if version != CURRENT_VERSION:
        raise RegistryError(f"unsupported registry version {version!r}")

    try:
        images = tuple(ApprovedImage(**entry) for entry in payload["measurements"])
    except (KeyError, TypeError) as exc:
        raise RegistryError(f"malformed registry entry: {exc}") from exc

    if not images:
        raise RegistryError("registry approves nothing; refusing rather than opening up")

    return Registry(
        version=version,
        netuid=int(payload["netuid"]),
        effective_from=effective_from,
        images=images,
    )


def manifest_line(reg_digest: str, effective_from: int, url: str) -> tuple[str, str]:
    """What goes on chain, as two fields.

    Commitment fields cap at 128 bytes each, so the pointer is split: the first
    field carries the version, the height and the digest, the second the URL.
    Both stay well inside the limit, and both use the smaller field type, which
    avoids an SDK bug that drops the larger one on read.
    """
    head = f"sentinel-measurements v{CURRENT_VERSION} eff={effective_from} sha256={reg_digest}"
    if len(head) > 128 or len(url) > 128:
        raise RegistryError("manifest does not fit in a 128 byte commitment field")
    return head, url


def parse_manifest(head: str, url: str) -> tuple[int, str, str]:
    """(effective_from, digest, url) from what a commitment carries."""
    parts = dict(
        p.split("=", 1) for p in head.split() if "=" in p
    )
    try:
        return int(parts["eff"]), parts["sha256"].lower(), url.strip()
    except (KeyError, ValueError) as exc:
        raise RegistryError(f"unreadable manifest: {head!r}") from exc


def approved_for(registries: Iterable[Registry], block: int) -> frozenset[str]:
    """Every measurement approved at `block`, across overlapping registries.

    Overlap is deliberate. When an image rotates, the new registry is published
    ahead of its effective height and both stay valid for a while, so miners
    migrate one at a time instead of every miner failing on the same day. That
    day already happened once in miniature, when a rebuild changed the
    measurement and an independent validator scored the miner zero until it was
    told the new value by hand.
    """
    active = [r for r in registries if r.active_at(block)]
    if not active:
        raise RegistryError(f"no registry is in effect at block {block}")
    out: set[str] = set()
    for r in active:
        out |= r.measurements
    return frozenset(out)

"""
Where a validator gets its approved measurements.

`registry.py` is pure: parsing, digests, heights. This is the part that talks to
the chain and the network, kept separate because the pure half must never be
wrong and the I/O half will regularly fail.

The order of preference, and the reasoning for each step:

    1. the chain, read at a pinned block   every validator sees the same bytes
    2. the last list that verified          an outage should not change scoring
    3. whatever --measurement was passed    an operator's explicit instruction

It never refuses to score. A validator that halts during a GitHub outage records
zero for honest miners, accrues no bond in them, and loses dividends for a
failure that is nobody's fault but the network's. Falling back is the lesser
harm, and it is loud: a warning on every fallback, an error once it has been
running on stale data long enough to be drifting out of consensus.

Two registries are held at once, `active` and `pending`. A manifest published
with a future effective height waits in `pending` and is promoted at that height,
not when it was noticed. That is what makes the publishing window real: every
validator switches at the same block regardless of when it polled.
"""

from __future__ import annotations

import json
import logging
import pathlib
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .registry import Registry, RegistryError, digest, parse, parse_manifest

logger = logging.getLogger("sentinel.registry")

#: Refuse a list larger than this. The digest makes tampering pointless, but a
#: verifier that downloads whatever it is handed before checking anything is a
#: denial of service waiting to happen.
MAX_REGISTRY_BYTES = 256 * 1024

FETCH_TIMEOUT_SECONDS = 15.0

#: How long on fallback before it stops being a warning. Long enough that a
#: transient outage is quiet, short enough that a validator does not spend days
#: scoring from a stale local list while the subnet has moved on.
STALE_AFTER_SECONDS = 24 * 60 * 60


@dataclass
class SourceStatus:
    using_fallback: bool
    last_success: float | None
    active_digest: str | None
    pending_digest: str | None
    pending_at: int | None

    @property
    def stale_for(self) -> float:
        return 0.0 if self.last_success is None else time.time() - self.last_success


def fetch(url: str) -> bytes:
    """Download a registry file, refusing anything oversized or not HTTPS."""
    if not url.startswith("https://"):
        raise RegistryError(f"registry URL must be https, got {url!r}")
    try:
        with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_REGISTRY_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RegistryError(f"could not fetch {url}: {exc}") from exc
    if len(body) > MAX_REGISTRY_BYTES:
        raise RegistryError(f"registry at {url} is larger than {MAX_REGISTRY_BYTES} bytes")
    return body


class RegistrySource:
    """Resolves approved measurements, from chain when it can and locally when it must."""

    def __init__(
        self,
        netuid: int,
        publisher_hotkey: str,
        *,
        fallback: frozenset[str] = frozenset(),
        cache_path: pathlib.Path | None = None,
        stale_after: float = STALE_AFTER_SECONDS,
    ) -> None:
        self.netuid = netuid
        self.publisher_hotkey = publisher_hotkey
        #: What --measurement supplied. Last resort, and an explicit one: the
        #: operator typed these, so using them is following an instruction
        #: rather than guessing.
        self.fallback = frozenset(m.lower() for m in fallback)
        self.cache_path = cache_path
        self.stale_after = stale_after

        self.active: Registry | None = None
        self.pending: Registry | None = None
        self.last_success: float | None = None
        self._warned_stale = False
        self._load_cache()

    # -- resolution ------------------------------------------------------------

    def approved_at(self, block: int) -> frozenset[str]:
        """The measurements to score against at `block`.

        Promotion happens here rather than at refresh, so a validator that read
        a pending manifest hours ago still switches at exactly the published
        height instead of whenever it last polled.
        """
        if self.pending is not None and self.pending.active_at(block):
            logger.info(
                "registry %s takes effect at block %d, switching",
                digest_of(self.pending)[:16], self.pending.effective_from,
            )
            self.active, self.pending = self.pending, None
            self._save_cache()

        if self.active is not None:
            return self.active.measurements

        if not self.fallback:
            raise RegistryError(
                "no registry from chain, nothing cached, and no --measurement "
                "given. A validator with no approved measurements would score "
                "every miner zero, so it refuses to run instead."
            )
        self._warn_fallback()
        return self.fallback

    def status(self) -> SourceStatus:
        return SourceStatus(
            using_fallback=self.active is None,
            last_success=self.last_success,
            active_digest=digest_of(self.active) if self.active else None,
            pending_digest=digest_of(self.pending) if self.pending else None,
            pending_at=self.pending.effective_from if self.pending else None,
        )

    # -- refresh ---------------------------------------------------------------

    async def refresh(self, subtensor) -> bool:
        """Read the manifest from chain and load the list it points at.

        Returns True if anything changed. Never raises for network trouble: the
        caller is a loop in a long-running daemon and an exception there means a
        validator that stops scoring because a web server was slow.
        """
        from .chain import read_manifest

        try:
            found = await read_manifest(subtensor, self.netuid, self.publisher_hotkey)
        except Exception as exc:  # noqa: BLE001 - chain trouble must not stop scoring
            logger.warning("could not read the registry manifest from chain: %s", exc)
            self._warn_fallback()
            return False

        if found is None:
            # No manifest published yet. Expected before the registry goes live,
            # and not an error: the operator's flags are still authoritative.
            logger.info("no registry manifest on netuid %d yet", self.netuid)
            self._warn_fallback()
            return False

        effective_from, expected, url = found
        known = {digest_of(r) for r in (self.active, self.pending) if r is not None}
        if expected in known:
            self.last_success = time.time()
            self._warned_stale = False
            return False

        try:
            body = fetch(url)
            registry = parse(body, expect_digest=expected, effective_from=effective_from)
        except RegistryError as exc:
            # A digest mismatch is louder than a fetch failure, because it means
            # the file changed without the chain changing, which is either a
            # mistake or someone tampering with what validators read.
            logger.error("rejecting the registry at %s: %s", url, exc)
            self._warn_fallback()
            return False

        self.last_success = time.time()
        self._warned_stale = False

        # Always pending, even when the height has already passed: promotion
        # happens in `approved_at`, which knows the current block. One place
        # decides when a list applies, so there is one rule rather than two.
        self.pending = registry
        logger.info(
            "registry %s fetched, %d measurements, effective at block %d",
            expected[:16], len(registry.images), effective_from,
        )
        return True

    # -- cache -----------------------------------------------------------------

    def _load_cache(self) -> None:
        """A restart during an outage should not drop to the flags."""
        if self.cache_path is None or not self.cache_path.exists():
            return
        try:
            cached = json.loads(self.cache_path.read_text())
            self.active = parse(
                cached["body"],
                expect_digest=cached["digest"],
                effective_from=int(cached["effective_from"]),
            )
            logger.info("loaded a cached registry, %d measurements", len(self.active.images))
        except Exception as exc:  # noqa: BLE001 - a bad cache is not fatal
            logger.warning("ignoring unreadable registry cache: %s", exc)

    def _save_cache(self) -> None:
        if self.cache_path is None or self.active is None:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps({
                "digest": digest_of(self.active),
                "effective_from": self.active.effective_from,
                "body": self.active.source,
            }))
        except OSError as exc:
            logger.warning("could not write the registry cache: %s", exc)

    # -- noise -----------------------------------------------------------------

    def _warn_fallback(self) -> None:
        status = self.status()
        if not status.using_fallback:
            return
        if self.last_success is not None and status.stale_for > self.stale_after:
            if not self._warned_stale:
                logger.error(
                    "scoring from a local measurement list for %.1f hours. This "
                    "validator may be out of consensus with the subnet.",
                    status.stale_for / 3600,
                )
                self._warned_stale = True
        else:
            logger.warning("scoring from the local --measurement list, not the registry")


def digest_of(registry: Registry) -> str:
    return digest(json.loads(registry.source))

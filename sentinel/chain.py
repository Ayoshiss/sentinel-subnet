"""
Chain-facing helpers: publish an endpoint, discover peers.

Bittensor v11 has no networking stack of its own, so the chain is used purely as
a directory. A miner writes its `ip:port` there with the ServeAxon intent, and a
validator reads the metagraph to find out who to challenge. Everything after
discovery happens over ordinary signed HTTP.

Isolated here so the serving and evaluation layers stay testable without a node.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

logger = logging.getLogger("sentinel.chain")

#: Anything published on-chain is a claim by the miner, not a fact. A miner can
#: advertise any endpoint it likes; attestation is what decides whether the
#: thing answering there is trustworthy.
DEFAULT_SCHEME = "http"


@dataclass
class DiscoveredMiner:
    uid: int
    hotkey_ss58: str
    base_url: str
    validator_permit: bool = False


async def fetch_metagraph(subtensor: Any, netuid: int) -> Any:
    """The typed metagraph. `Subtensor.read('metagraph')` returns subnet
    metadata only — neurons come from the module-level fetch."""
    import bittensor as bt

    return await bt.metagraph.fetch(subtensor, netuid)


async def publish_axon(
    subtensor: Any,
    signer: Any,
    netuid: int,
    ip: str,
    port: int,
    *,
    protocol: int = 4,
) -> Any:
    """Advertise this neuron's endpoint on-chain.

    Signed by the HOTKEY, so a miner can publish without the coldkey on the box.

    Two chain rules bite here. Loopback is rejected outright — an axon nobody can
    reach is not an axon — so `127.0.0.1` fails and a LAN or public address is
    required. And the subnet's `serving_rate_limit` (50 blocks by default)
    applies per neuron, so this belongs at startup and on change, never in the
    serving loop.
    """
    import bittensor as bt

    if _is_loopback(ip):
        raise ValueError(
            f"{ip} is loopback; the chain rejects it. Publish the address peers "
            "can actually reach, and map it locally if you are testing."
        )

    result = await subtensor.execute(
        bt.intents.ServeAxon(netuid=netuid, ip=ip, port=port, protocol=protocol), signer
    )
    logger.info("published axon %s:%d on netuid %d: success=%s", ip, port, netuid, result.success)
    return result


def _is_loopback(ip: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


async def discover_miners(
    subtensor: Any,
    netuid: int,
    *,
    exclude_hotkeys: Sequence[str] = (),
    scheme: str = DEFAULT_SCHEME,
    require_axon: bool = True,
) -> list[DiscoveredMiner]:
    """Everyone on the subnet worth challenging.

    Neurons without a published endpoint are skipped: there is nowhere to send a
    challenge, and scoring them zero would punish a miner for a chain read that
    simply has not propagated yet. Validators are excluded by hotkey rather than
    by permit, since a permit only says a neuron *may* set weights, not that it
    is not also serving.
    """
    metagraph = await fetch_metagraph(subtensor, netuid)
    excluded = set(exclude_hotkeys)
    found: list[DiscoveredMiner] = []

    for neuron in metagraph.neurons:
        if neuron.hotkey in excluded:
            continue
        endpoint = _endpoint(neuron)
        if endpoint is None:
            if require_axon:
                logger.debug("uid %s has no published axon; skipping", neuron.uid)
                continue
            continue
        found.append(
            DiscoveredMiner(
                uid=neuron.uid,
                hotkey_ss58=neuron.hotkey,
                base_url=f"{scheme}://{endpoint}",
                validator_permit=bool(neuron.validator_permit),
            )
        )

    logger.info("discovered %d serving miners on netuid %d", len(found), netuid)
    return found


def _endpoint(neuron: Any) -> str | None:
    """`ip:port` for a neuron, or None when it is not serving."""
    axon = getattr(neuron, "axon", None)
    if not axon:
        return None
    if isinstance(axon, str):
        return axon or None
    # Defensive: some views hand back a mapping rather than a formatted string.
    ip, port = axon.get("ip"), axon.get("port")
    return f"{ip}:{port}" if ip and port else None


async def has_validator_permit(subtensor: Any, netuid: int, hotkey_ss58: str) -> bool:
    """Whether this hotkey may set weights.

    Permits go to the top validators by stake, so a freshly registered hotkey
    has none. Weight submission from a neuron without a permit is rejected
    on-chain, which is worth checking before a round rather than after.
    """
    metagraph = await fetch_metagraph(subtensor, netuid)
    for neuron in metagraph.neurons:
        if neuron.hotkey == hotkey_ss58:
            return bool(neuron.validator_permit)
    return False

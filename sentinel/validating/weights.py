"""
Submitting weights to Yuma Consensus.

On a subnet with commit-reveal enabled (Sentinel's is), `set_weights` already
takes the commit path: the weights are timelock-encrypted with drand and stay
hidden until the chain auto-decrypts them at the reveal round. There is no
separate reveal call in v4, committing is the whole operation.

That hiding is the point. Published weights are copyable, and a validator that
copies earns dividends for work it never did. If nobody can see your weights
until the round closes, there is nothing to copy while it matters.

Two things worth knowing before changing anything here:

    * weights are floats; the SDK normalises and quantises them, so do not
      pre-scale to u16 or the distribution ends up squared
    * weight extrinsics are signed by the HOTKEY, not the coldkey, so a
      validator can run unattended without the coldkey on the box

Chain calls live here and nowhere else, so evaluation stays testable offline.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

logger = logging.getLogger("sentinel.validating.weights")


def to_uids_and_weights(weights: Mapping[int, float]) -> tuple[list[int], list[float]]:
    """Split a uid->weight map into the parallel lists the intents take.

    Negative weights are clamped to zero rather than dropped, so a uid the
    validator scored stays visible in the submission as an explicit zero
    instead of silently vanishing from the round.
    """
    uids = sorted(weights)
    return uids, [max(0.0, float(weights[uid])) for uid in uids]


async def set_weights(
    subtensor: Any,
    signer: Any,
    netuid: int,
    weights: Mapping[int, float],
    *,
    version_key: int = 0,
) -> Any:
    """Submit weights, following the subnet's own commit-reveal setting.

    This is the normal path. Where commit-reveal is enabled the SDK routes it
    through the encrypted commit automatically.
    """
    import bittensor as bt

    uids, values = to_uids_and_weights(weights)
    result = await subtensor.execute(
        bt.intents.SetWeights(netuid=netuid, uids=uids, weights=values, version_key=version_key),
        signer,
    )
    logger.info("set %d weights on netuid %d: success=%s", len(uids), netuid, result.success)
    return result


async def commit_weights(
    subtensor: Any,
    signer: Any,
    netuid: int,
    weights: Mapping[int, float],
    *,
    version_key: int = 0,
) -> Any:
    """Force the timelock-encrypted commit path regardless of subnet settings.

    Prefer `set_weights` unless you specifically need the commit path on a
    subnet where commit-reveal is off.
    """
    import bittensor as bt

    uids, values = to_uids_and_weights(weights)
    result = await subtensor.execute(
        bt.intents.CommitWeights(netuid=netuid, uids=uids, weights=values, version_key=version_key),
        signer,
    )
    logger.info("committed %d weights on netuid %d: success=%s", len(uids), netuid, result.success)
    return result

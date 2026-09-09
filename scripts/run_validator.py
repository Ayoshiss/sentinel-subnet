"""
A Sentinel validator, running continuously against a live subnet.

    python scripts/run_validator.py --netuid 554 --wallet sentinel --hotkey validator

Once per tempo it reads the metagraph, challenges every miner advertising an
endpoint, verifies each attestation, scores five axes, and submits weights.

Nothing is told to it. Miners are discovered on-chain, the nonce is chosen here
so a miner cannot answer before being asked, and correctness is decided by
agreement across miners rather than by trusting any one of them. A validator
that cannot verify a proof scores that miner zero rather than giving it the
benefit of the doubt.

`run_epoch.py` does one round and starts its own miner, which is a demonstration.
This is the thing you leave running.
"""

import argparse
import asyncio
import logging
import pathlib
import signal
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.chain import discover_miners, has_validator_permit
from sentinel.validating import MinerEvaluator, MinerTarget
from sentinel.validating.weights import set_weights

logger = logging.getLogger("sentinel.validator")

#: How long to wait after a round before starting the next one.
#:
#: The binding constraint is `weights_rate_limit`, 100 blocks on 554, which at
#: ~12s blocks is exactly 20 minutes. Defaulting to 20 minutes would sit on that
#: boundary and lose submissions to any block-time jitter, so this leaves a
#: margin. Check the subnet's own value rather than assuming this one:
#:
#:     btcli subnet hyperparameters 554 --network test
DEFAULT_INTERVAL_SECONDS = 22 * 60


async def one_round(st, args, wallet, evaluator) -> None:
    """Discover, challenge, score, submit. Any failure ends this round, not the run."""
    import bittensor as bt

    val_hotkey = wallet.hotkey.ss58_address

    miners = await discover_miners(st, args.netuid, exclude_hotkeys=[val_hotkey])
    if not miners:
        logger.info("no miners advertising an endpoint yet")
        return

    outcomes = evaluator.evaluate_round([
        MinerTarget(uid=m.uid, hotkey_ss58=m.hotkey_ss58, base_url=m.base_url)
        for m in miners
    ])

    for o in outcomes:
        s = o.scores
        logger.info(
            "uid=%-3d attest=%.2f latency=%.2f correct=%.2f cache=%.2f nonce=%.2f weight=%.4f%s",
            o.uid, s.attestation, s.latency, s.correctness, s.cache_hygiene,
            s.nonce_discipline, o.weight, f"  error={o.error}" if o.error else "",
        )

    weights = MinerEvaluator.weights_from(outcomes)
    if not any(weights.values()):
        # Every miner failed. Submitting a uniform distribution would reward
        # them all equally for failing, which is worse than submitting nothing.
        logger.warning("every miner scored zero; not submitting weights")
        return

    if not await has_validator_permit(st, args.netuid, val_hotkey):
        # Worth checking each round rather than once at startup: permits move
        # with stake, so one can be lost between rounds.
        logger.warning("no validator permit, weights would be rejected on-chain")
        return

    if args.dry_run:
        logger.info("dry run, not submitting: %s", weights)
        return

    result = await set_weights(st, bt.resolve_signer(wallet, "hotkey"), args.netuid, weights)
    logger.info("weights submitted: success=%s", getattr(result, "success", result))
    reveal = getattr(result, "data", {}).get("reveal_round") if hasattr(result, "data") else None
    if reveal:
        # Timelocked, so no other validator can copy this round's weights before
        # the reveal. Copying is the cheapest attack on any subnet.
        logger.info("timelock reveal_round=%s", reveal)


async def main(args) -> int:
    import bittensor as bt

    wallet = bt.Wallet(name=args.wallet, hotkey=args.hotkey)
    evaluator = MinerEvaluator(
        wallet.hotkey,
        args.measurement,
        latency_ceiling_ms=args.latency_ceiling_ms,
        product=args.product,
    )
    logger.info(
        "validator %s on netuid %d, every %ds",
        wallet.hotkey.ss58_address, args.netuid, args.interval,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    while not stop.is_set():
        try:
            async with bt.Subtensor(args.endpoint) as st:
                await one_round(st, args, wallet, evaluator)
        except Exception as exc:  # noqa: BLE001 - one bad round must not end the run
            logger.warning("round failed: %s", exc)

        if args.once:
            break
        try:
            await asyncio.wait_for(stop.wait(), timeout=args.interval)
        except asyncio.TimeoutError:
            pass

    logger.info("shutting down")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--netuid", type=int, default=554)
    # 554 is a testnet subnet. Pointing at finney would read the wrong chain and
    # find no miners, with nothing in the logs to say why.
    p.add_argument("--endpoint", "--network", dest="endpoint", default="test")
    p.add_argument("--wallet", default="sentinel")
    p.add_argument("--hotkey", default="validator")
    p.add_argument("--measurement", required=True,
                   help="the approved launch measurement miners must prove")
    p.add_argument("--product", default="Milan", help="EPYC product line")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS)
    p.add_argument("--latency-ceiling-ms", type=float, default=60_000.0)
    p.add_argument("--once", action="store_true", help="run one round and exit")
    p.add_argument("--dry-run", action="store_true",
                   help="score and print, but do not submit weights")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    )
    raise SystemExit(asyncio.run(main(args)))

"""
Sentinel validator neuron — challenge / verify / score loop (skeleton).

Every ~360 blocks the validator challenges each miner with a fresh nonce,
verifies the returned SEV-SNP attestation against the AMD certificate chain and
the approved launch measurement, scores the miner on the five-axis rubric, and
submits Yuma weights under commit-reveal. Miners that fail attestation are
slashed via the on-chain collateral contract.
"""

from __future__ import annotations

import logging

from .challenge import new_nonce
from .scoring import MinerScores

logger = logging.getLogger("sentinel.validator")


class SentinelValidator:
    def __init__(self, netuid: int) -> None:
        self.netuid = netuid

    def challenge_miner(self, miner_uid: int) -> MinerScores:
        """Issue a challenge and score the response."""
        nonce = new_nonce()
        # report = query_miner(miner_uid, nonce)
        # verified = verify_attestation(report, nonce, approved_measurement)
        raise NotImplementedError("Verification lands in testnet phase.")

    def verify_attestation(self, report: dict, nonce: bytes, approved_measurement: str) -> bool:
        """Verify VCEK signature chain, launch measurement, TCB, and nonce binding."""
        raise NotImplementedError("Attestation verification lands in testnet phase.")

    def set_weights(self, weights: dict[int, float]) -> None:
        """Submit Yuma weights under commit-reveal (v3)."""
        raise NotImplementedError("Weight submission lands in testnet phase.")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logger.info("Sentinel validator initialised (skeleton).")


if __name__ == "__main__":
    main()

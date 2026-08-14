"""
Miner scoring rubric.

Final score is a weighted sum over five axes, each in [0, 1]:

    attestation validity  40%
    response latency      30%
    correctness           20%
    cache hygiene          5%
    nonce discipline       5%

The scalar produced here is the weight a validator submits to Yuma Consensus.
"""

from __future__ import annotations

from dataclasses import dataclass

WEIGHTS = {
    "attestation": 0.40,
    "latency": 0.30,
    "correctness": 0.20,
    "cache_hygiene": 0.05,
    "nonce_discipline": 0.05,
}


@dataclass
class MinerScores:
    attestation: float = 0.0
    latency: float = 0.0
    correctness: float = 0.0
    cache_hygiene: float = 0.0
    nonce_discipline: float = 0.0

    def weight(self) -> float:
        """Aggregate the five axes into a single [0, 1] weight."""
        return (
            WEIGHTS["attestation"] * self.attestation
            + WEIGHTS["latency"] * self.latency
            + WEIGHTS["correctness"] * self.correctness
            + WEIGHTS["cache_hygiene"] * self.cache_hygiene
            + WEIGHTS["nonce_discipline"] * self.nonce_discipline
        )

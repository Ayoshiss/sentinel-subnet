"""
Miner scoring rubric.

A miner's weight is a weighted sum over five axes, each in [0, 1]:

    attestation validity  40%   did it prove genuine hardware running approved code
    response latency      30%   how fast, relative to a target and a ceiling
    correctness           20%   did it agree with the other miners on the same query
    cache hygiene          5%   did it forbid caching of an attested response
    nonce discipline       5%   did it bind OUR nonce rather than a pre-computed one

The scalar produced here is what the validator submits to Yuma Consensus.

Attestation is a gate rather than merely the heaviest axis. The other four
measure how *good* a miner is; attestation decides whether it is a Sentinel
miner at all. Fail it and the weight is zero regardless of the rest — the
network exists to make exactly that one check, so a miner that fails it must
earn nothing rather than four fifths of a full score.
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

#: Answer within this and latency scores full marks.
DEFAULT_LATENCY_TARGET_MS = 250.0
#: At or beyond this, latency scores zero.
DEFAULT_LATENCY_CEILING_MS = 5_000.0


def latency_score(
    latency_ms: float,
    target_ms: float = DEFAULT_LATENCY_TARGET_MS,
    ceiling_ms: float = DEFAULT_LATENCY_CEILING_MS,
) -> float:
    """1.0 at or under `target_ms`, 0.0 at or over `ceiling_ms`, linear between.

    Linear rather than exponential so the difference between a good miner and a
    mediocre one stays visible in the weights; an exponential curve flattens
    everything slower than the target into indistinguishable near-zero.
    """
    if ceiling_ms <= target_ms:
        raise ValueError("ceiling_ms must exceed target_ms")
    if latency_ms <= target_ms:
        return 1.0
    if latency_ms >= ceiling_ms:
        return 0.0
    return 1.0 - (latency_ms - target_ms) / (ceiling_ms - target_ms)


@dataclass
class MinerScores:
    attestation: float = 0.0
    latency: float = 0.0
    correctness: float = 0.0
    cache_hygiene: float = 0.0
    nonce_discipline: float = 0.0

    def weight(self) -> float:
        """Aggregate the five axes into a single [0, 1] weight.

        Attestation is a gate, not merely the heaviest axis. A miner that cannot
        prove it is running the approved image inside genuine silicon earns
        nothing, however fast and well-behaved it otherwise looks.

        Without this, the weighted sum alone leaves a backdoored miner on 0.40 —
        it still collects full marks for latency, cache hygiene and nonce
        discipline — which would pay roughly a sixth of emissions to code that
        failed the one check the subnet exists to make.
        """
        if self.attestation <= 0.0:
            return 0.0
        total = sum(WEIGHTS[axis] * getattr(self, axis) for axis in WEIGHTS)
        return max(0.0, min(1.0, total))

    def as_dict(self) -> dict[str, float]:
        return {axis: getattr(self, axis) for axis in WEIGHTS} | {"weight": self.weight()}

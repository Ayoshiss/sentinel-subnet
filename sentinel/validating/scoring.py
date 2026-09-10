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
miner at all. Fail it and the weight is zero regardless of the rest, the
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

    def weight(self, *, gate_correctness: bool = False) -> float:
        """Aggregate the five axes into a single [0, 1] weight.

        **Integrity gates. Quality scores.** The axes split into two kinds of
        question, and mixing them was the original mistake. Whether a miner
        cheated is a yes or no; how good it is is a matter of degree. Averaging
        the two means a cheat forfeits only the points for the axis that caught
        it and keeps everything else, so being dishonest cost less than being
        slow: a caching cheat scored 0.95 against an honest slow miner's 0.887.

        So attestation, cache hygiene and nonce discipline are gates. Each is a
        deterministic fact about one response, measured directly rather than
        voted on, so there is no noise to average and nothing to smooth. Fail
        any and the miner earns nothing.

        Correctness is different. It is decided by agreement between miners,
        which is a vote, and votes are noisy: gating it would punish an honest
        miner for one unlucky epoch. It is also meaningless when a round has too
        few miners, since one miner is its own majority. So it only gates when
        the caller says the round had enough participants to make a majority
        mean something, and otherwise stays as points.
        """
        if self.attestation <= 0.0:
            return 0.0
        if self.cache_hygiene <= 0.0:
            return 0.0
        if self.nonce_discipline <= 0.0:
            return 0.0
        if gate_correctness and self.correctness <= 0.0:
            return 0.0
        total = sum(WEIGHTS[axis] * getattr(self, axis) for axis in WEIGHTS)
        return max(0.0, min(1.0, total))

    def legacy_weight(self) -> float:
        """What this miner would have scored under the original rubric.

        Kept so the fix can be shown to have done something rather than argued
        about in the abstract. Every round logs both, so a miner that behaves in
        a way the old rubric rewarded and the new one refuses shows up in the
        record with a number attached.

        Delete this once there is enough history to make the point.
        """
        if self.attestation <= 0.0:
            return 0.0
        total = sum(WEIGHTS[axis] * getattr(self, axis) for axis in WEIGHTS)
        return max(0.0, min(1.0, total))

    def as_dict(self, *, gate_correctness: bool = False) -> dict[str, float]:
        return {axis: getattr(self, axis) for axis in WEIGHTS} | {
            "weight": self.weight(gate_correctness=gate_correctness),
            "legacy_weight": self.legacy_weight(),
        }

"""Validator-side evaluation: challenge miners, verify proofs, score them."""

from .evaluator import ChallengeOutcome, MinerEvaluator, MinerTarget
from .scoring import WEIGHTS, MinerScores, latency_score

__all__ = [
    "ChallengeOutcome",
    "MinerEvaluator",
    "MinerTarget",
    "MinerScores",
    "WEIGHTS",
    "latency_score",
]

"""
Miner scoring rubric — re-exported from the implementation in `sentinel`.

The rubric used to be defined here as a standalone dataclass. It now lives in
`sentinel/validating/scoring.py` alongside the evaluator that produces it and
the tests that cover it, so there is one definition of what a miner is worth
rather than two that can drift apart.
"""

from __future__ import annotations

from sentinel.validating.scoring import (
    DEFAULT_LATENCY_CEILING_MS,
    DEFAULT_LATENCY_TARGET_MS,
    WEIGHTS,
    MinerScores,
    latency_score,
)

__all__ = [
    "WEIGHTS",
    "MinerScores",
    "latency_score",
    "DEFAULT_LATENCY_TARGET_MS",
    "DEFAULT_LATENCY_CEILING_MS",
]

"""
Challenge miners, verify their proofs, score them.

The validator trusts nothing a miner says about itself. It picks the nonce, so
the miner cannot answer before being asked; it checks the attestation against
the approved launch measurement, so modified code cannot pass; and it decides
correctness by agreement across miners rather than by asking any one of them.

Correctness by consensus is the important part. A validator cannot know the
right answer to a query against a customer's private database, that is the
whole point of the product. What it can do is send the same query to every
miner and notice who disagrees with the majority. A miner returning fabricated
rows is visible without the validator ever seeing the real data.

No chain access here. This module challenges over HTTP and produces weights;
submitting them is `weights.py`.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..attestation import (
    AttestationReport,
    VerificationError,
    bind_response,
    new_nonce,
    verify,
    verifier_from_public_key,
)
from ..serving.client import MinerClient, MinerClientError
from .scoring import (
    DEFAULT_LATENCY_CEILING_MS,
    DEFAULT_LATENCY_TARGET_MS,
    MinerScores,
    latency_score,
)

logger = logging.getLogger("sentinel.validating")

#: Deterministic probe sent to every miner in a round. Read-only by design,
#: a validator must never mutate a customer's data while measuring.
PROBE_TOOL = "postgres.query"
PROBE_ARGUMENTS: dict[str, Any] = {"sql": "SELECT id, email, plan FROM customers ORDER BY id"}


@dataclass
class MinerTarget:
    uid: int
    hotkey_ss58: str
    base_url: str


@dataclass
class ChallengeOutcome:
    uid: int
    hotkey_ss58: str
    scores: MinerScores = field(default_factory=MinerScores)
    verified: bool = False
    latency_ms: float = 0.0
    response_hash: str | None = None
    error: str | None = None

    @property
    def weight(self) -> float:
        return self.scores.weight()


class MinerEvaluator:
    """Runs one evaluation round against a set of miners."""

    def __init__(
        self,
        wallet: Any,
        approved_measurement: str,
        *,
        min_tcb: int = 7,
        latency_target_ms: float = DEFAULT_LATENCY_TARGET_MS,
        latency_ceiling_ms: float = DEFAULT_LATENCY_CEILING_MS,
        timeout: float = 30.0,
    ) -> None:
        self.wallet = wallet
        self.approved_measurement = approved_measurement
        self.min_tcb = min_tcb
        self.latency_target_ms = latency_target_ms
        self.latency_ceiling_ms = latency_ceiling_ms
        self.timeout = timeout

    # -- one round ------------------------------------------------------------

    def evaluate_round(self, targets: Iterable[MinerTarget]) -> list[ChallengeOutcome]:
        """Probe every miner, then score correctness against the majority answer."""
        outcomes = [self._probe(t) for t in targets]

        # Consensus over miners that actually produced a verified answer. An
        # unverified miner does not get a vote on what the truth is, otherwise
        # a group of fakes could outvote the honest ones.
        votes = Counter(o.response_hash for o in outcomes if o.verified and o.response_hash)
        majority = votes.most_common(1)[0][0] if votes else None

        for outcome in outcomes:
            if majority is not None and outcome.verified:
                outcome.scores.correctness = 1.0 if outcome.response_hash == majority else 0.0
            logger.info(
                "uid=%s verified=%s weight=%.4f%s",
                outcome.uid, outcome.verified, outcome.weight,
                f" error={outcome.error}" if outcome.error else "",
            )
        return outcomes

    @staticmethod
    def weights_from(outcomes: Iterable[ChallengeOutcome]) -> dict[int, float]:
        """uid -> weight, normalised so the round sums to 1.0.

        Yuma expects a distribution. If every miner failed, an all-zero map is
        returned rather than a uniform one: rewarding everyone equally for
        failing is worse than rewarding no one.
        """
        raw = {o.uid: o.weight for o in outcomes}
        total = sum(raw.values())
        if total <= 0:
            return {uid: 0.0 for uid in raw}
        return {uid: w / total for uid, w in raw.items()}

    # -- per miner ------------------------------------------------------------

    def _probe(self, target: MinerTarget) -> ChallengeOutcome:
        outcome = ChallengeOutcome(uid=target.uid, hotkey_ss58=target.hotkey_ss58)
        client = MinerClient(target.base_url, self.wallet, target.hotkey_ss58, timeout=self.timeout)

        try:
            health = client.health()
            public_key = health.get("public_key")
            if not public_key:
                outcome.error = "health did not advertise a public key"
                return outcome

            nonce = new_nonce()
            request_id = f"probe-{nonce[:12]}"
            response = client.call_full(PROBE_TOOL, PROBE_ARGUMENTS, nonce, request_id=request_id)
        except MinerClientError as exc:
            outcome.error = str(exc)
            return outcome

        outcome.latency_ms = response.latency_ms
        outcome.scores.latency = latency_score(
            response.latency_ms, self.latency_target_ms, self.latency_ceiling_ms
        )

        # An attested reply must not be cacheable: a cached body would be served
        # to someone else without the proof that belongs to it.
        cache_control = response.header("Cache-Control").lower()
        outcome.scores.cache_hygiene = 1.0 if "no-store" in cache_control else 0.0

        payload = response.payload
        outcome.response_hash = payload.get("response_hash")

        try:
            report = AttestationReport(**payload["attestation"])
        except (KeyError, TypeError) as exc:
            outcome.error = f"malformed attestation: {exc}"
            return outcome

        # Nonce discipline is scored separately from attestation validity so a
        # miner replaying an old report is distinguishable from one with no
        # valid report at all.
        outcome.scores.nonce_discipline = 1.0 if report.nonce == nonce else 0.0

        try:
            verify(
                report,
                verifier_from_public_key(public_key),
                approved_measurement=self.approved_measurement,
                expected_nonce=nonce,
                min_tcb=self.min_tcb,
                expected_report_data=bind_response(request_id, outcome.response_hash or ""),
            )
        except VerificationError as exc:
            outcome.error = f"attestation rejected: {exc}"
            return outcome

        outcome.verified = True
        outcome.scores.attestation = 1.0
        return outcome

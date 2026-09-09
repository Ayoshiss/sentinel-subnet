"""The validator daemon's guard rails, exercised rather than read.

Three of the four branches below decide *not* to submit weights. They matter
more than the happy path: a validator that submits the wrong thing is worse than
one that submits nothing, and each of these guards was a single line that was
easy to write and easy to get backwards.

The chain is faked here on purpose. Testing "no validator permit" against the
live subnet would mean unstaking, and testing "no miners" would mean taking a
live miner down.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib
from types import SimpleNamespace

import bittensor
import pytest

from sentinel.validating import ChallengeOutcome
from sentinel.validating.scoring import MinerScores

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture(scope="module")
def rv():
    spec = importlib.util.spec_from_file_location("run_validator", SCRIPTS / "run_validator.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def args(**over):
    base = dict(netuid=554, dry_run=False)
    base.update(over)
    return SimpleNamespace(**base)


WALLET = SimpleNamespace(hotkey=SimpleNamespace(ss58_address="5Validator"))


def miner(uid=1):
    return SimpleNamespace(uid=uid, hotkey_ss58=f"5Miner{uid}",
                           base_url=f"http://10.0.0.{uid}:8091")


def outcome(uid=1, attestation=1.0):
    return ChallengeOutcome(
        uid=uid, hotkey_ss58=f"5Miner{uid}",
        scores=MinerScores(attestation=attestation, latency=1.0, correctness=1.0,
                           cache_hygiene=1.0, nonce_discipline=1.0),
        verified=attestation > 0,
    )


class Spy:
    """Records whether weights were submitted, and what."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, st, signer, netuid, weights, **kw):
        self.calls.append({"netuid": netuid, "weights": weights})
        return SimpleNamespace(success=True, data={})


def run(rv, monkeypatch, *, miners, outcomes, permit) -> Spy:
    """Drive one round with the chain and the evaluator faked out."""
    spy = Spy()

    async def fake_discover(st, netuid, exclude_hotkeys=None):
        return miners

    async def fake_permit(st, netuid, hotkey):
        return permit

    monkeypatch.setattr(rv, "discover_miners", fake_discover)
    monkeypatch.setattr(rv, "has_validator_permit", fake_permit)
    monkeypatch.setattr(rv, "set_weights", spy)
    # one_round resolves a signer from the wallet before submitting; the fake
    # wallet is not one, and signing is not what these tests are about.
    monkeypatch.setattr(bittensor, "resolve_signer", lambda w, role: "signer")

    evaluator = SimpleNamespace(evaluate_round=lambda targets: outcomes)
    asyncio.run(rv.one_round(object(), args(), WALLET, evaluator))
    return spy


def test_no_miners_means_no_submission(rv, monkeypatch):
    """An empty subnet is not an occasion to write anything on-chain."""
    spy = run(rv, monkeypatch, miners=[], outcomes=[], permit=True)
    assert spy.calls == []


def test_without_a_permit_it_does_not_submit(rv, monkeypatch):
    """Weights from a hotkey with no permit are rejected on-chain anyway.

    Checked every round rather than once at startup, because permits follow
    stake and can be lost while the daemon is running.
    """
    spy = run(rv, monkeypatch, miners=[miner()], outcomes=[outcome()], permit=False)
    assert spy.calls == []


def test_every_miner_failing_submits_nothing_rather_than_a_flat_distribution(rv, monkeypatch):
    """Rewarding everyone equally for failing is worse than rewarding no one."""
    spy = run(rv, monkeypatch, miners=[miner(1), miner(2)],
              outcomes=[outcome(1, attestation=0.0), outcome(2, attestation=0.0)],
              permit=True)
    assert spy.calls == []


def test_a_good_round_submits_normalised_weights(rv, monkeypatch):
    """And the happy path still reaches the chain, with weights summing to one."""
    spy = run(rv, monkeypatch, miners=[miner(1), miner(2)],
              outcomes=[outcome(1), outcome(2)], permit=True)

    assert len(spy.calls) == 1
    weights = spy.calls[0]["weights"]
    assert spy.calls[0]["netuid"] == 554
    assert set(weights) == {1, 2}
    assert sum(weights.values()) == pytest.approx(1.0)


def test_dry_run_scores_but_never_writes(rv, monkeypatch):
    """The flag operators are told to try first must not touch the chain."""
    spy = Spy()

    async def fake_discover(st, netuid, exclude_hotkeys=None):
        return [miner()]

    async def fake_permit(st, netuid, hotkey):
        return True

    monkeypatch.setattr(rv, "discover_miners", fake_discover)
    monkeypatch.setattr(rv, "has_validator_permit", fake_permit)
    monkeypatch.setattr(rv, "set_weights", spy)

    evaluator = SimpleNamespace(evaluate_round=lambda targets: [outcome()])
    asyncio.run(rv.one_round(object(), args(dry_run=True), WALLET, evaluator))
    assert spy.calls == []

"""
Chain discovery: reading the metagraph, publishing an endpoint.

The chain is only a directory here, it says where a miner claims to be, never
whether that miner is trustworthy. These tests cover the parsing and filtering
around that, plus the two rules the chain enforced on us in practice: loopback
axons are rejected, and a neuron that publishes nothing is not challengeable.

Metagraph responses are faked rather than mocked against a node, so the suite
stays fast and offline. The live path is exercised by scripts/run_epoch.py.
"""

import asyncio
from dataclasses import dataclass

import pytest

from sentinel.chain import (
    _endpoint,
    _is_loopback,
    discover_miners,
    has_validator_permit,
    publish_axon,
)


def run(coro):
    """Drive a coroutine from a sync test, so the suite needs no async plugin."""
    return asyncio.run(coro)


@dataclass
class FakeNeuron:
    uid: int
    hotkey: str
    axon: object = None
    validator_permit: bool = False


class FakeMetagraph:
    def __init__(self, neurons):
        self.neurons = neurons


class FakeSubtensor:
    """Stands in for a node; only the metagraph read is used by discovery."""

    def __init__(self, neurons):
        self._mg = FakeMetagraph(neurons)

    async def execute(self, intent, signer):  # pragma: no cover
        raise AssertionError("discovery must not submit extrinsics")


@pytest.fixture(autouse=True)
def patch_fetch(monkeypatch):
    async def _fetch(subtensor, netuid, **kw):
        return subtensor._mg

    monkeypatch.setattr("sentinel.chain.fetch_metagraph", _fetch)


# --- endpoint parsing ---------------------------------------------------------

def test_endpoint_from_string():
    assert _endpoint(FakeNeuron(1, "hk", "10.0.0.4:8091")) == "10.0.0.4:8091"


def test_endpoint_from_mapping():
    """Some views hand back a mapping rather than a formatted string."""
    assert _endpoint(FakeNeuron(1, "hk", {"ip": "10.0.0.4", "port": 8091})) == "10.0.0.4:8091"


@pytest.mark.parametrize("axon", [None, "", {}, {"ip": "10.0.0.4"}, {"port": 8091}])
def test_endpoint_absent_or_incomplete(axon):
    assert _endpoint(FakeNeuron(1, "hk", axon)) is None


@pytest.mark.parametrize("ip,expected", [
    ("127.0.0.1", True), ("127.1.2.3", True), ("::1", True),
    ("192.168.1.50", False), ("8.8.8.8", False), ("not-an-ip", False),
])
def test_loopback_detection(ip, expected):
    assert _is_loopback(ip) is expected


# --- discovery ----------------------------------------------------------------

def test_discovers_only_serving_neurons():
    st = FakeSubtensor([
        FakeNeuron(0, "validator-hk", None, validator_permit=True),   # not serving
        FakeNeuron(1, "miner-a", "10.0.0.4:8091"),
        FakeNeuron(2, "miner-b", "10.0.0.5:8091"),
    ])
    found = run(discover_miners(st, netuid=2))
    assert [m.uid for m in found] == [1, 2]
    assert found[0].base_url == "http://10.0.0.4:8091"


def test_excluded_hotkeys_are_skipped():
    """A validator should not challenge itself."""
    st = FakeSubtensor([
        FakeNeuron(0, "self-hk", "10.0.0.1:8091"),
        FakeNeuron(1, "miner-a", "10.0.0.4:8091"),
    ])
    found = run(discover_miners(st, netuid=2, exclude_hotkeys=["self-hk"]))
    assert [m.uid for m in found] == [1]


def test_unserved_neuron_is_skipped_not_scored_zero():
    """A neuron with no endpoint has nowhere to receive a challenge.

    Scoring it zero would punish a miner for a chain read that has not
    propagated yet, so it is left out of the round entirely.
    """
    st = FakeSubtensor([FakeNeuron(1, "miner-a", None)])
    assert run(discover_miners(st, netuid=2)) == []


def test_permit_flag_is_carried_through():
    st = FakeSubtensor([FakeNeuron(1, "hk", "10.0.0.4:8091", validator_permit=True)])
    found = run(discover_miners(st, netuid=2))
    assert found[0].validator_permit is True


def test_has_validator_permit():
    st = FakeSubtensor([
        FakeNeuron(0, "with-permit", None, validator_permit=True),
        FakeNeuron(1, "without", None, validator_permit=False),
    ])
    assert run(has_validator_permit(st, 2, "with-permit")) is True
    assert run(has_validator_permit(st, 2, "without")) is False
    assert run(has_validator_permit(st, 2, "unregistered")) is False


# --- publishing ---------------------------------------------------------------

def test_publish_rejects_loopback_before_submitting():
    """Fail locally with a useful message rather than burning a rate-limited
    call to learn the chain dislikes 127.0.0.1."""
    st = FakeSubtensor([])
    with pytest.raises(ValueError, match="loopback"):
        run(publish_axon(st, signer=None, netuid=2, ip="127.0.0.1", port=8091))

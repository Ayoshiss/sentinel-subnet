"""
Validator evaluation: challenge, verify, score.

The tests that matter run a round against a mix of honest and dishonest miners
on real sockets, and check the dishonest ones are caught:

    * a miner running modified code            -> fails attestation
    * a miner replaying an old attestation     -> fails nonce discipline
    * a miner fabricating rows                 -> fails correctness by consensus
    * a miner allowing its reply to be cached  -> fails cache hygiene

Consensus correctness is the subtle one. The validator cannot know the right
answer to a query against a private database, so it never tries to: it asks
every miner the same thing and notices who disagrees with the majority.
"""

import threading

import pytest
from bittensor.sp_core import Keypair

from sentinel.attestation import MockSilicon, sha384
from sentinel.database import Credentials, MockDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.serving import MinerHandler
from sentinel.serving.server import make_server
from sentinel.validating import ChallengeOutcome, MinerEvaluator, MinerScores, MinerTarget
from sentinel.validating.scoring import latency_score
from sentinel.validating.weights import to_uids_and_weights

APPROVED = sha384(b"sentinel-miner-image-v0.1")
RESOURCE = "customer-db"
DSN = "postgres://app:secret@customer-db:5432/prod"

HONEST_ROWS = [[1, "ada@example.com", "enterprise"],
               [2, "grace@example.com", "pro"],
               [3, "alan@example.com", "free"]]


# --- scoring units ------------------------------------------------------------

def test_weights_sum_to_one():
    from sentinel.validating.scoring import WEIGHTS
    assert sum(WEIGHTS.values()) == pytest.approx(1.0)


def test_perfect_and_zero_scores():
    assert MinerScores(1, 1, 1, 1, 1).weight() == pytest.approx(1.0)
    assert MinerScores().weight() == 0.0


def test_attestation_failure_costs_everything():
    """Attestation gates the whole score rather than costing only its 40% axis.

    Scored as a plain weighted sum a backdoored miner would keep 0.60, still
    collecting emissions for being fast and tidy while failing the one check
    the subnet exists to perform.
    """
    assert MinerScores(1, 1, 1, 1, 1).weight() == pytest.approx(1.0)
    assert MinerScores(0, 1, 1, 1, 1).weight() == 0.0


def test_other_axes_still_separate_verified_miners():
    """The gate must not flatten the field: verified miners are still ranked."""
    fast = MinerScores(1, 1.0, 1, 1, 1).weight()
    slow = MinerScores(1, 0.2, 1, 1, 1).weight()
    assert fast > slow
    assert fast - slow == pytest.approx(0.30 * 0.8)


@pytest.mark.parametrize("ms,expected", [(0, 1.0), (250, 1.0), (5000, 0.0), (9999, 0.0)])
def test_latency_score_bounds(ms, expected):
    assert latency_score(ms) == pytest.approx(expected)


def test_latency_score_is_linear_between():
    mid = latency_score((250 + 5000) / 2)
    assert mid == pytest.approx(0.5)


def test_latency_rejects_impossible_bounds():
    with pytest.raises(ValueError):
        latency_score(100, target_ms=500, ceiling_ms=500)


# --- weight submission shaping ------------------------------------------------

def test_uids_and_weights_are_sorted_and_clamped():
    uids, values = to_uids_and_weights({3: 0.5, 1: -0.2, 2: 0.25})
    assert uids == [1, 2, 3]
    assert values == [0.0, 0.25, 0.5]  # negative clamped, not dropped


def test_zero_round_stays_zero():
    outcomes = [ChallengeOutcome(uid=1, hotkey_ss58="a"), ChallengeOutcome(uid=2, hotkey_ss58="b")]
    assert MinerEvaluator.weights_from(outcomes) == {1: 0.0, 2: 0.0}


def test_weights_normalise_to_one():
    a = ChallengeOutcome(uid=1, hotkey_ss58="a", scores=MinerScores(1, 1, 1, 1, 1))
    b = ChallengeOutcome(uid=2, hotkey_ss58="b", scores=MinerScores(1, 0, 1, 1, 1))
    w = MinerEvaluator.weights_from([a, b])
    assert sum(w.values()) == pytest.approx(1.0)
    assert w[1] > w[2]


# --- live miners, honest and otherwise ----------------------------------------

def build_miner(measurement=APPROVED, rows=None, replay_nonce=False, allow_cache=False):
    """A running miner. Knobs make it dishonest in one specific way."""
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=measurement))
    broker.store_secret(RESOURCE, DSN)
    enclave = Enclave(MockSilicon(), launch_measurement=measurement)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    credentials = enclave.unlock(broker, RESOURCE)

    mcp = MCPServer()
    mcp.register(PostgresQueryTool(MockDatabase(
        credentials, columns=["id", "email", "plan"], rows=rows or HONEST_ROWS)))

    hotkey = Keypair.create_from_uri(f"//Miner{id(enclave)}")
    handler = MinerHandler(enclave, mcp, hotkey_ss58=hotkey.ss58_address)

    if replay_nonce:
        # Ignores the validator's nonce and reuses a stale one.
        stale = "00" * 32
        original = handler.enclave.run_attested
        handler.enclave.run_attested = lambda rid, nonce, work: original(rid, stale, work)

    server = make_server(handler, "127.0.0.1", 0)
    if allow_cache:
        server.RequestHandlerClass = _cacheable(server.RequestHandlerClass)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hotkey, f"http://127.0.0.1:{server.server_port}"


def _cacheable(cls):
    """A miner that lets its attested replies be cached."""
    class _C(cls):
        def _write(self, status, payload):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "public, max-age=300")
            self.end_headers()
            self.wfile.write(payload)
    return _C


@pytest.fixture
def validator_wallet():
    return Keypair.create_from_uri("//Validator")


@pytest.fixture
def evaluator(validator_wallet):
    return MinerEvaluator(validator_wallet, APPROVED, latency_ceiling_ms=60_000)


def run_round(evaluator, miners):
    targets = [MinerTarget(uid=i, hotkey_ss58=hk.ss58_address, base_url=url)
               for i, (_, hk, url) in enumerate(miners)]
    try:
        return {o.uid: o for o in evaluator.evaluate_round(targets)}
    finally:
        for server, _, _ in miners:
            server.shutdown()


def test_honest_miner_scores_full_marks(evaluator):
    miners = [build_miner()]
    out = run_round(evaluator, miners)[0]
    assert out.verified
    assert out.scores.attestation == 1.0
    assert out.scores.correctness == 1.0
    assert out.scores.cache_hygiene == 1.0
    assert out.scores.nonce_discipline == 1.0
    assert out.weight > 0.95


def test_modified_code_fails_attestation(evaluator):
    """The core guarantee: a miner not running the approved image scores zero on it."""
    miners = [build_miner(), build_miner(measurement=sha384(b"backdoored"))]
    out = run_round(evaluator, miners)
    assert out[0].verified and out[0].scores.attestation == 1.0
    assert not out[1].verified
    assert out[1].scores.attestation == 0.0
    assert "launch measurement" in out[1].error


def test_replayed_attestation_fails_nonce_discipline(evaluator):
    miners = [build_miner(), build_miner(replay_nonce=True)]
    out = run_round(evaluator, miners)
    assert out[1].scores.nonce_discipline == 0.0
    assert not out[1].verified  # a stale nonce also fails verification outright


def test_fabricated_rows_lose_correctness_by_consensus(evaluator):
    """Two honest miners agree; the liar is outvoted without the validator
    ever knowing the real data."""
    liar_rows = [[1, "attacker@evil.com", "enterprise"]]
    miners = [build_miner(), build_miner(), build_miner(rows=liar_rows)]
    out = run_round(evaluator, miners)

    assert out[0].scores.correctness == 1.0
    assert out[1].scores.correctness == 1.0
    assert out[2].scores.correctness == 0.0
    assert out[2].verified  # its attestation is genuine, it just lied about the data
    assert out[2].weight < out[0].weight


def test_cacheable_response_loses_hygiene(evaluator):
    miners = [build_miner(), build_miner(allow_cache=True)]
    out = run_round(evaluator, miners)
    assert out[0].scores.cache_hygiene == 1.0
    assert out[1].scores.cache_hygiene == 0.0


def test_unreachable_miner_scores_zero(evaluator):
    targets = [MinerTarget(uid=9, hotkey_ss58="5Fake", base_url="http://127.0.0.1:1")]
    out = evaluator.evaluate_round(targets)[0]
    assert out.weight == 0.0
    assert not out.verified
    assert "unreachable" in out.error


def test_unverified_miners_do_not_vote_on_truth(evaluator):
    """Two fakes agreeing with each other must not outvote one honest miner."""
    fake_rows = [[1, "attacker@evil.com", "enterprise"]]
    miners = [
        build_miner(),
        build_miner(measurement=sha384(b"backdoored"), rows=fake_rows),
        build_miner(measurement=sha384(b"backdoored"), rows=fake_rows),
    ]
    out = run_round(evaluator, miners)
    assert out[0].scores.correctness == 1.0  # honest miner still sets the majority
    assert not out[1].verified and not out[2].verified
    assert out[0].weight > out[1].weight and out[0].weight > out[2].weight


# --- attestation as a gate ----------------------------------------------------

def test_failed_attestation_zeroes_the_weight():
    """Admission control: perfect on every other axis still earns nothing."""
    s = MinerScores(attestation=0.0, latency=1.0, correctness=1.0,
                    cache_hygiene=1.0, nonce_discipline=1.0)
    assert s.weight() == 0.0


def test_gate_applies_in_a_live_round(evaluator):
    """A backdoored miner must not collect emissions for being fast and tidy."""
    miners = [build_miner(), build_miner(measurement=sha384(b"backdoored"))]
    out = run_round(evaluator, miners)
    assert out[1].scores.latency == 1.0          # it answered promptly
    assert out[1].scores.cache_hygiene == 1.0    # and behaved well otherwise
    assert out[1].weight == 0.0                  # and still earns nothing

    weights = MinerEvaluator.weights_from(list(out.values()))
    assert weights[0] == pytest.approx(1.0)
    assert weights[1] == 0.0

"""
A real TDX miner, scored by the validator, checked offline from the exchange.

Captured 2026-11-06 from `scripts/run_miner.py` on a GCP TDX VM booted from a
signed UKI under our own Secure Boot keys. The validator chose the nonce and
request id, the miner answered with rows and a quote, and the quote's
REPORT_DATA is the real response binding rather than a test nonce. So unlike the
earlier fixtures, this one exercises every check including the binding.

The root filesystem was not measured in this run (meta.json): it proves the TDX
path end to end, not that T23 is closed.
"""

import json
import pathlib

import pytest

dcap_qvl = pytest.importorskip("dcap_qvl")

from sentinel.attestation import AttestationReport, VerificationError, bind_response, sha384  # noqa: E402
from sentinel.database import canonical  # noqa: E402
from sentinel.tdx import CollateralCache, verifier as tdx_verifier  # noqa: E402
from sentinel.validating import MinerEvaluator  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-miner-2026-11-06"
COLLATERAL = ROOT / "tests" / "fixtures" / "tdx" / "collateral"

META = json.loads((EVIDENCE / "meta.json").read_text())
PROBE = json.loads((EVIDENCE / "probe.json").read_text())
DB = (EVIDENCE / "test-db.der").read_bytes()
UKI = META["uki"]["authenticode_sha384"]
MRTD = META["mrtd"]


def fixture_collateral(quote: bytes):
    data = json.loads((COLLATERAL / f"{tdx_verifier.chain_key(quote)}.json").read_text())
    return dcap_qvl.QuoteCollateralV3.from_json(json.dumps(data["collateral"]))


@pytest.fixture
def evaluator(monkeypatch):
    monkeypatch.setattr(tdx_verifier.time, "time", lambda: PROBE["captured_at"])
    return MinerEvaluator(
        None, [UKI], tdx_mrtd=[MRTD], tdx_db_cert=DB,
        tdx_collateral=CollateralCache(fetch=fixture_collateral),
    )


def report() -> AttestationReport:
    return AttestationReport(**PROBE["response"]["attestation"])


def binding(response_hash: str | None = None) -> str:
    return bind_response(PROBE["request_id"], response_hash or PROBE["response"]["response_hash"])


def test_the_miner_advertised_tdx_and_the_approved_image():
    assert PROBE["health"]["attestation"] == "tdx"
    assert PROBE["health"]["launch_measurement"] == UKI
    assert report().nonce == PROBE["nonce"]


def test_a_real_tdx_miner_passes_every_check_including_the_binding(evaluator):
    evaluator._verify_tdx(report(), PROBE["health"], binding(), expected_nonce=PROBE["nonce"])


def test_the_attested_hash_is_the_hash_of_the_rows_returned():
    """What the binding covers: these exact rows, not just some answer."""
    assert sha384(canonical(PROBE["response"]["result"])) == PROBE["response"]["response_hash"]


def test_changed_rows_break_the_binding(evaluator):
    rows = json.loads(json.dumps(PROBE["response"]["result"]))
    rows["rows"][0][1] = "mallory@example.com"
    with pytest.raises(VerificationError, match="binding"):
        evaluator._verify_tdx(
            report(), PROBE["health"], binding(sha384(canonical(rows))), expected_nonce=PROBE["nonce"]
        )


def test_replaying_this_reply_to_a_new_challenge_is_refused(evaluator):
    with pytest.raises(VerificationError, match="replay"):
        evaluator._verify_tdx(report(), PROBE["health"], binding(), expected_nonce="0" * 64)


def test_a_validator_that_has_not_approved_this_image_refuses_it(evaluator):
    evaluator.approved_measurement = frozenset({"00" * 48})
    with pytest.raises(VerificationError, match="booted image is not approved"):
        evaluator._verify_tdx(report(), PROBE["health"], binding(), expected_nonce=PROBE["nonce"])

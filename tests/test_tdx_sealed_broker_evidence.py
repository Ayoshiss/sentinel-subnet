"""
Sealed credential release on GCP TDX, checked offline from what it produced.

The measured miner reached the customer's broker only through a relay the
operator controls, over plain HTTP, with every byte recorded. Then the operator
pointed the miner at a broker of their own. meta.json has the setup.
"""

import json
import pathlib

import pytest

dcap_qvl = pytest.importorskip("dcap_qvl")

from sentinel.attestation import AttestationReport, VerificationError, bind_response  # noqa: E402
from sentinel.tdx import CollateralCache, verifier as tdx_verifier  # noqa: E402
from sentinel.validating import MinerEvaluator  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-sealed-broker-2026-11-07"
COLLATERAL = ROOT / "tests" / "fixtures" / "tdx" / "collateral"

META = json.loads((EVIDENCE / "meta.json").read_text())
CUSTOMER = json.loads((EVIDENCE / "probe-customer-broker.json").read_text())
OPERATOR = json.loads((EVIDENCE / "probe-operator-broker.json").read_text())
RELAY = (EVIDENCE / "relay.log").read_bytes()
BOOT = (EVIDENCE / "boot.log").read_text()
DB = (EVIDENCE / "test-db.der").read_bytes()
UKI = META["miner"]["uki_authenticode_sha384"]
CUSTOMER_FP = META["customer_broker"]["fingerprint"]
OPERATOR_FP = META["operator_broker"]["fingerprint"]


def fixture_collateral(quote: bytes):
    data = json.loads((COLLATERAL / f"{tdx_verifier.chain_key(quote)}.json").read_text())
    return dcap_qvl.QuoteCollateralV3.from_json(json.dumps(data["collateral"]))


def verify(probe, broker):
    """What the validator does with a reply, naming `broker` in the binding."""
    import unittest.mock

    evaluator = MinerEvaluator(
        None, [UKI], tdx_mrtd=[META["miner"]["mrtd"]], tdx_db_cert=DB,
        tdx_collateral=CollateralCache(fetch=fixture_collateral),
    )
    with unittest.mock.patch.object(tdx_verifier.time, "time", lambda: probe["captured_at"]):
        evaluator._verify_tdx(
            AttestationReport(**probe["response"]["attestation"]), probe["health"],
            bind_response(probe["request_id"], probe["response"]["response_hash"], broker),
            expected_nonce=probe["nonce"],
        )


def test_the_relay_carried_the_release_and_never_saw_the_credential():
    assert b">>> POST /release" in RELAY and b'"sealed"' in RELAY
    assert b"customer-7f3a9c41" not in RELAY
    assert b"sqlite" not in RELAY


def test_both_boots_unlocked_sealed_and_logged_which_broker():
    """First through the relay (port 8200) from the customer's broker, then
    from the operator's own broker (8100) after the operator changed the URL."""
    relay = BOOT.index("brokering to http://10.128.0.24:8200")
    customer = BOOT.index(f"sealed, by broker {CUSTOMER_FP}")
    own = BOOT.index("brokering to http://10.128.0.24:8100")
    operator = BOOT.index(f"sealed, by broker {OPERATOR_FP}")
    assert relay < customer < own < operator


def test_answers_from_the_customers_broker_verify_and_name_it():
    assert CUSTOMER["health"]["broker"] == CUSTOMER_FP
    assert CUSTOMER["response"]["broker"] == CUSTOMER_FP
    verify(CUSTOMER, CUSTOMER_FP)


def test_the_operators_own_broker_is_named_in_every_answer():
    """Honest, so it verifies; and it names a broker the customer never ran."""
    assert OPERATOR["response"]["broker"] == OPERATOR_FP != CUSTOMER_FP
    verify(OPERATOR, OPERATOR_FP)


def test_claiming_the_customers_broker_for_the_operators_answer_fails():
    """The broker is inside the signed binding, so the claim cannot be swapped."""
    with pytest.raises(VerificationError, match="binding"):
        verify(OPERATOR, CUSTOMER_FP)

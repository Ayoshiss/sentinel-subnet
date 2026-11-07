"""TDX values in the registry: firmware, Secure Boot certificate, rotation."""

import json
import pathlib

import pytest

from sentinel.registry import RegistryError, parse

pytest.importorskip("dcap_qvl")

from tests.test_tdx_verity_evidence import (  # noqa: E402
    DB, META, PROBE, UKI, binding, fixture_collateral, report,
)
from sentinel.tdx import CollateralCache  # noqa: E402
from sentinel.tdx import verifier as tdx_verifier  # noqa: E402
from sentinel.validating import MinerEvaluator  # noqa: E402
from sentinel.validating.evaluator import VerificationError  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
OTHER_DB = (ROOT / "docs/evidence/tdx-sealed-broker-2026-11-07/test-db.der").read_bytes()


def payload(tdx=None):
    body = {
        "version": 1,
        "netuid": 554,
        "measurements": [{
            "measurement": UKI, "platform": "gcp-tdx",
            "image": "sentinel-miner", "machine_type": "c3-standard-4",
        }],
    }
    if tdx is not None:
        body["tdx"] = tdx
    return json.dumps(body)


def test_a_registry_without_a_tdx_section_still_parses():
    reg = parse(payload())
    assert reg.tdx_mrtd == frozenset() and reg.tdx_db_certs == ()


def test_the_tdx_section_carries_firmware_and_certificate():
    reg = parse(payload({"mrtd": [META["mrtd"].upper()], "secure_boot_db": [DB.hex()]}))
    assert reg.tdx_mrtd == {META["mrtd"].lower()}
    assert reg.tdx_db_certs == (DB,)


@pytest.mark.parametrize("tdx", [
    {"mrtd": [META["mrtd"]]},
    {"secure_boot_db": [DB.hex()]},
    {"mrtd": ["ab" * 10], "secure_boot_db": [DB.hex()]},
    {"mrtd": [META["mrtd"]], "secure_boot_db": ["00" * 32]},
    ["not", "an", "object"],
])
def test_half_or_malformed_tdx_sections_are_refused(tdx):
    with pytest.raises(RegistryError):
        parse(payload(tdx))


def evaluator_with(certs, monkeypatch):
    monkeypatch.setattr(tdx_verifier.time, "time", lambda: PROBE["captured_at"])
    return MinerEvaluator(
        None, [UKI], tdx_mrtd=[META["mrtd"]], tdx_db_cert=certs,
        tdx_collateral=CollateralCache(fetch=fixture_collateral),
    )


def verify(evaluator):
    evaluator._verify_tdx(report(), PROBE["health"], binding(), expected_nonce=PROBE["nonce"])


def test_during_a_key_rotation_either_certificate_is_accepted(monkeypatch):
    assert OTHER_DB != DB
    verify(evaluator_with([OTHER_DB, DB], monkeypatch))


def test_an_image_signed_under_a_retired_key_is_refused(monkeypatch):
    with pytest.raises(VerificationError, match="boot policy"):
        verify(evaluator_with([OTHER_DB], monkeypatch))


def test_no_approved_certificate_means_no_tdx(monkeypatch):
    with pytest.raises(VerificationError, match="not configured"):
        verify(evaluator_with([], monkeypatch))


def test_the_source_hands_out_the_tdx_section_of_the_registry_in_force():
    from sentinel.registry_source import RegistrySource

    source = RegistrySource(554, "5x", fallback=frozenset({UKI}))
    assert source.tdx() is None
    source.active = parse(payload({"mrtd": [META["mrtd"]], "secure_boot_db": [DB.hex()]}))
    assert source.tdx() == (frozenset({META["mrtd"].lower()}), (DB,))

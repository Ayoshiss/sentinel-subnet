"""
The TDX verifier, run against quotes and event logs from real hardware.

Everything here is offline. Intel's collateral for the two machines involved
was fetched once and committed, and verification runs at the time it was
fetched, so CI checks Intel's real signatures without reaching Intel.

The quotes are from the 2026-11-06 Secure Boot experiment on GCP TDX. Their
REPORT_DATA is a random nonce rather than a response binding, so each is
verified against its own nonce.
"""

import hashlib
import json
import pathlib
import zlib

import pytest

dcap_qvl = pytest.importorskip("dcap_qvl")

from sentinel.attestation import VerificationError  # noqa: E402
from sentinel.tdx import (  # noqa: E402
    CollateralCache,
    TdxPolicy,
    TdxVerifier,
    decode_event_log,
    encode_event_log,
)
from sentinel.tdx import eventlog, verifier as tdx_verifier  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-uki-secureboot-2026-11-06"
COLLATERAL = pathlib.Path(__file__).parent / "fixtures" / "tdx" / "collateral"

META = json.loads((EVIDENCE / "meta.json").read_text())
UKI = META["signed_uki"]["authenticode_sha384"]
DB = (EVIDENCE / "test-db.der").read_bytes()
MRTD = eventlog.registers((EVIDENCE / "sb-A.quote").read_bytes())["MRTD"]
FETCHED_AT = json.loads(next(COLLATERAL.glob("*.json")).read_text())["fetched_at"]


def quote(label: str) -> bytes:
    return (EVIDENCE / f"{label}.quote").read_bytes()


def log(label: str) -> bytes:
    return (EVIDENCE / f"{label}.ccel").read_bytes()


def nonce(label: str) -> bytes:
    return (EVIDENCE / f"{label}.nonce").read_bytes()


class Fixtures:
    """Serves committed collateral by machine, counting fetches."""

    def __init__(self):
        self.fetches = 0

    def __call__(self, q: bytes):
        self.fetches += 1
        key = tdx_verifier.chain_key(q)
        data = json.loads((COLLATERAL / f"{key}.json").read_text())["collateral"]
        return dcap_qvl.QuoteCollateralV3.from_json(json.dumps(data))


def make(**overrides) -> TdxVerifier:
    policy = dict(approved_uki=[UKI], approved_mrtd=[MRTD], db_cert=DB)
    policy.update(overrides)
    return TdxVerifier(
        TdxPolicy(**policy),
        collateral=CollateralCache(fetch=Fixtures()),
        clock=lambda: FETCHED_AT,
    )


def flip(data: bytes, offset: int) -> bytes:
    out = bytearray(data)
    out[offset] ^= 1
    return bytes(out)


@pytest.mark.parametrize("label", ["sb-A", "sb-evil", "sb-after-tests"])
def test_secure_boot_quotes_verify_end_to_end(label):
    """Intel's signature, MRTD, the replayed log, the boot policy and the nonce."""
    evidence = make().verify(quote(label), log(label), expected_report_data=nonce(label))
    assert evidence.uki == UKI
    assert evidence.mrtd == MRTD
    assert evidence.tcb_status == "UpToDate"
    assert evidence.report_data == nonce(label)


def test_secure_boot_turned_off_is_refused():
    """A genuine, up-to-date quote, refused for what booted rather than who signed."""
    with pytest.raises(VerificationError, match="Secure Boot is off"):
        make().verify(quote("sb-off-evil"), log("sb-off-evil"))


def test_a_proof_for_another_request_is_refused():
    with pytest.raises(VerificationError, match="binding"):
        make().verify(quote("sb-A"), log("sb-A"), expected_report_data=nonce("sb-evil"))


def test_one_bit_in_rtmr1_breaks_intels_signature():
    q = flip(quote("sb-A"), eventlog.BODY + eventlog.REGISTERS["RTMR1"])
    with pytest.raises(VerificationError, match="not a valid Intel TDX quote"):
        make().verify(q, log("sb-A"))


def test_one_bit_in_report_data_breaks_intels_signature():
    q = flip(quote("sb-A"), eventlog.BODY + eventlog.REPORT_DATA)
    with pytest.raises(VerificationError, match="not a valid Intel TDX quote"):
        make().verify(q, log("sb-A"))


def test_an_event_log_from_another_boot_is_refused():
    """The log has to explain this quote, not merely a good boot."""
    with pytest.raises(VerificationError, match="does not replay"):
        make().verify(quote("sb-A"), log("sb-after-tests"))


def test_an_edited_event_log_is_refused():
    edited = log("sb-A").replace(bytes.fromhex(UKI), bytes(48), 1)
    assert edited != log("sb-A")
    with pytest.raises(VerificationError, match="does not replay"):
        make().verify(quote("sb-A"), edited)


def test_garbage_in_place_of_an_event_log_is_refused_not_crashed():
    with pytest.raises(VerificationError):
        make().verify(quote("sb-A"), b"\xff" * 100)


def test_an_unapproved_image_is_refused():
    with pytest.raises(VerificationError, match="booted image is not approved"):
        make(approved_uki=["00" * 48]).verify(quote("sb-A"), log("sb-A"))


def test_unapproved_td_firmware_is_refused():
    with pytest.raises(VerificationError, match="TD firmware is not approved"):
        make(approved_mrtd=["00" * 48]).verify(quote("sb-A"), log("sb-A"))


def test_an_image_verified_by_someone_elses_key_is_refused():
    kek = (EVIDENCE / "test-KEK.der").read_bytes()
    with pytest.raises(VerificationError, match="key other than ours"):
        make(db_cert=kek).verify(quote("sb-A"), log("sb-A"))


def test_a_status_the_subnet_does_not_accept_is_refused():
    with pytest.raises(VerificationError, match="TCB status UpToDate"):
        make(allowed_tcb_status=frozenset({"OutOfDate"})).verify(quote("sb-A"), log("sb-A"))


def test_a_debuggable_td_is_refused():
    """Checked by the policy, since a debug quote cannot be forged to test it."""
    q = flip(quote("sb-A"), eventlog.BODY + eventlog.TD_ATTRIBUTES)
    policy = TdxPolicy(approved_uki=[UKI], approved_mrtd=[MRTD], db_cert=DB)
    with pytest.raises(VerificationError, match="debuggable"):
        policy.check(q, log("sb-A"))


def test_expired_collateral_is_refused_after_one_refetch():
    fixtures = Fixtures()
    v = TdxVerifier(
        TdxPolicy(approved_uki=[UKI], approved_mrtd=[MRTD], db_cert=DB),
        collateral=CollateralCache(fetch=fixtures),
        clock=lambda: FETCHED_AT + 5 * 365 * 86400,
    )
    with pytest.raises(VerificationError, match="not a valid Intel TDX quote"):
        v.verify(quote("sb-A"), log("sb-A"))
    assert fixtures.fetches == 2


def test_collateral_is_cached_per_machine():
    """sb-off-evil came back on another host after a stop, so it has its own."""
    fixtures = Fixtures()
    v = TdxVerifier(
        TdxPolicy(approved_uki=[UKI], approved_mrtd=[MRTD], db_cert=DB),
        collateral=CollateralCache(fetch=fixtures),
        clock=lambda: FETCHED_AT,
    )
    for label in ("sb-A", "sb-evil", "sb-after-tests"):
        v.verify(quote(label), log(label))
    assert fixtures.fetches == 1
    with pytest.raises(VerificationError):
        v.verify(quote("sb-off-evil"), log("sb-off-evil"))
    assert fixtures.fetches == 2
    assert tdx_verifier.chain_key(quote("sb-A")) != tdx_verifier.chain_key(quote("sb-off-evil"))


def test_another_machines_collateral_does_not_verify():
    other = json.loads((COLLATERAL / f"{tdx_verifier.chain_key(quote('sb-off-evil'))}.json").read_text())
    col = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(other["collateral"]))
    with pytest.raises(Exception):
        dcap_qvl.verify(quote("sb-A"), col, FETCHED_AT)


def test_verify_signed_message_binds_sha512_of_the_message():
    """No real quote binds a message we know, so check the binding it asks for."""
    v = make()
    seen = {}
    v.verify = lambda q, lg, expected_report_data: seen.setdefault("rd", expected_report_data)
    v.verify_signed_message(b"report", quote("sb-A").hex(), log("sb-A"))
    assert seen["rd"] == hashlib.sha512(b"report").digest()


def test_an_old_dcap_qvl_is_refused(monkeypatch):
    """Before 0.3 it skipped the QE Identity check (CVE-2026-22696)."""
    monkeypatch.setattr(tdx_verifier, "version", lambda _: "0.2.9")
    with pytest.raises(VerificationError, match="older than"):
        make().verify(quote("sb-A"), log("sb-A"))


def test_event_log_round_trips_and_shrinks():
    raw = log("sb-A")
    packed = encode_event_log(raw)
    assert decode_event_log(packed) == raw
    assert len(packed) < len(raw) // 10


def test_a_decompression_bomb_is_refused():
    with pytest.raises(VerificationError, match="larger than any firmware table"):
        decode_event_log(zlib.compress(bytes(4 << 20)))


def test_a_truncated_event_log_is_refused():
    with pytest.raises(VerificationError):
        decode_event_log(encode_event_log(log("sb-A"))[:-10])


# -- in the validator ----------------------------------------------------------

def _evaluator(**kwargs):
    from sentinel.validating import MinerEvaluator

    return MinerEvaluator(None, [UKI], **kwargs)


def _health(label: str) -> dict:
    import base64

    return {"attestation": "tdx", "event_log": base64.b64encode(encode_event_log(log(label))).decode()}


class _Report:
    def __init__(self, label):
        self.signature = quote(label).hex()
        self.nonce = "n"
        self.report_data = "b"

    def canonical(self):
        return b"canonical"


def test_a_validator_without_tdx_configuration_refuses_rather_than_half_checks():
    with pytest.raises(VerificationError, match="not configured"):
        _evaluator()._verify_tdx(_Report("sb-A"), _health("sb-A"), "b", expected_nonce="n")


def test_a_tdx_miner_must_send_its_event_log():
    ev = _evaluator(tdx_mrtd=[MRTD], tdx_db_cert=DB)
    with pytest.raises(VerificationError, match="no event log"):
        ev._verify_tdx(_Report("sb-A"), {"attestation": "tdx"}, "b", expected_nonce="n")


def test_the_validator_runs_every_check_before_the_binding(monkeypatch):
    """A real quote gets through Intel, MRTD and the boot policy, and fails only
    on the binding, because its REPORT_DATA is a test nonce and not SHA-512 of a
    report. Failing there and nowhere earlier is the evidence the rest passed."""
    monkeypatch.setattr(tdx_verifier.time, "time", lambda: FETCHED_AT)
    ev = _evaluator(
        tdx_mrtd=[MRTD], tdx_db_cert=DB, tdx_collateral=CollateralCache(fetch=Fixtures())
    )
    with pytest.raises(VerificationError, match="response binding mismatch"):
        ev._verify_tdx(_Report("sb-A"), _health("sb-A"), "b", expected_nonce="n")


def test_the_validator_refuses_a_boot_with_secure_boot_off(monkeypatch):
    monkeypatch.setattr(tdx_verifier.time, "time", lambda: FETCHED_AT)
    ev = _evaluator(
        tdx_mrtd=[MRTD], tdx_db_cert=DB, tdx_collateral=CollateralCache(fetch=Fixtures())
    )
    with pytest.raises(VerificationError, match="Secure Boot is off"):
        ev._verify_tdx(_Report("sb-off-evil"), _health("sb-off-evil"), "b", expected_nonce="n")


def test_the_registry_decides_which_images_a_validator_accepts(monkeypatch):
    """Approved UKIs come from the same list as every other measurement."""
    monkeypatch.setattr(tdx_verifier.time, "time", lambda: FETCHED_AT)
    ev = _evaluator(
        tdx_mrtd=[MRTD], tdx_db_cert=DB, tdx_collateral=CollateralCache(fetch=Fixtures())
    )
    ev.approved_measurement = frozenset({"00" * 48})
    with pytest.raises(VerificationError, match="booted image is not approved"):
        ev._verify_tdx(_Report("sb-A"), _health("sb-A"), "b", expected_nonce="n")

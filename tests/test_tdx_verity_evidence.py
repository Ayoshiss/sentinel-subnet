"""
The measured miner image on GCP TDX, checked offline from what it produced.

Built from image/ on 2026-11-06, signed with throwaway test Secure Boot keys and
booted on a TDX VM with no SSH and no guest agent. The validator ran from a
separate machine over the internet. A second copy of the disk with bytes of the
miner's code changed was booted with the same keys and the same UKI.
"""

import json
import pathlib
import re

import pytest

dcap_qvl = pytest.importorskip("dcap_qvl")

from sentinel.attestation import AttestationReport, VerificationError, bind_response  # noqa: E402
from sentinel.tdx import CollateralCache, eventlog, verifier as tdx_verifier  # noqa: E402
from sentinel.tdx.verifier import decode_event_log  # noqa: E402
from sentinel.validating import MinerEvaluator  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-verity-image-2026-11-06"
COLLATERAL = ROOT / "tests" / "fixtures" / "tdx" / "collateral"

META = json.loads((EVIDENCE / "meta.json").read_text())
PROBE = json.loads((EVIDENCE / "probe.json").read_text())
BOOT = (EVIDENCE / "boot.log").read_text()
TAMPERED = (EVIDENCE / "tampered-boot.log").read_text()
DB = (EVIDENCE / "test-db.der").read_bytes()
UKI = META["uki"]["authenticode_sha384"]
ROOTHASH = META["uki"]["roothash"]


def fixture_collateral(quote: bytes):
    data = json.loads((COLLATERAL / f"{tdx_verifier.chain_key(quote)}.json").read_text())
    return dcap_qvl.QuoteCollateralV3.from_json(json.dumps(data["collateral"]))


@pytest.fixture
def evaluator(monkeypatch):
    monkeypatch.setattr(tdx_verifier.time, "time", lambda: PROBE["captured_at"])
    return MinerEvaluator(
        None, [UKI], tdx_mrtd=[META["mrtd"]], tdx_db_cert=DB,
        tdx_collateral=CollateralCache(fetch=fixture_collateral),
    )


def report() -> AttestationReport:
    return AttestationReport(**PROBE["response"]["attestation"])


def binding() -> str:
    return bind_response(PROBE["request_id"], PROBE["response"]["response_hash"])


def test_the_validator_verifies_the_measured_image(evaluator):
    evaluator._verify_tdx(report(), PROBE["health"], binding(), expected_nonce=PROBE["nonce"])


def test_the_only_image_the_firmware_loaded_is_the_approved_uki():
    import base64

    log = decode_event_log(base64.b64decode(PROBE["health"]["event_log"]))
    images = [e.digest.hex() for e in eventlog.events(log) if e.type == eventlog.EV_EFI_BOOT_SERVICES_APPLICATION]
    assert images == [UKI]


def test_the_root_hash_is_on_the_measured_command_line_and_root_is_verity():
    """The kernel booted with the UKI's own command line, and mounted the root
    through dm-verity from partitions named by that hash."""
    assert f"Command line: roothash={ROOTHASH} " in BOOT
    assert "secureboot: Secure boot enabled" in BOOT
    assert "Using verity root device /dev/mapper/root" in BOOT
    assert f"by-partuuid/{ROOTHASH[:8]}-" in BOOT
    assert re.search(r"erofs \(device dm-0\): mounted", BOOT)
    assert "miner serving on 0.0.0.0:8091" in BOOT


def test_there_is_no_login_and_no_guest_agent():
    assert "login:" not in BOOT
    assert "google_guest_agent" not in BOOT and "sshd" not in BOOT


def test_changed_code_on_the_disk_is_refused_by_the_kernel():
    """Same keys, same UKI, bytes of the miner's code changed on disk: dm-verity
    refuses the blocks, and the miner never serves."""
    assert f"Command line: roothash={ROOTHASH} " in TAMPERED
    assert TAMPERED.count("device-mapper: verity") > 0
    assert "is corrupted" in TAMPERED
    assert "miner serving" not in TAMPERED


def test_a_validator_that_has_not_approved_this_image_refuses_it(evaluator):
    evaluator.approved_measurement = frozenset({"00" * 48})
    with pytest.raises(VerificationError, match="booted image is not approved"):
        evaluator._verify_tdx(report(), PROBE["health"], binding(), expected_nonce=PROBE["nonce"])

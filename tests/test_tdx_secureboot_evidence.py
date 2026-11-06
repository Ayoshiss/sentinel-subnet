"""
The 2026-11-06 Secure Boot experiment on GCP Intel TDX, checked from raw evidence.

Follows the UKI experiment, which found T24: with Secure Boot off, a boot entry
can replace the image's embedded command line without moving RTMR1. Here the
image carries our own Secure Boot keys. Every claim in docs/results.md is
asserted against the quotes and event logs it came from.
"""

import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-uki-secureboot-2026-11-06"
EARLIER = ROOT / "docs" / "evidence" / "tdx-uki-2026-11-06"

_spec = importlib.util.spec_from_file_location("tdx_eventlog", ROOT / "scripts" / "tdx_eventlog.py")
tdx = importlib.util.module_from_spec(_spec)
sys.modules["tdx_eventlog"] = tdx
_spec.loader.exec_module(tdx)

META = json.loads((EVIDENCE / "meta.json").read_text())
UKI = META["signed_uki"]["authenticode_sha384"]
DB = (EVIDENCE / "test-db.der").read_bytes()
SECURE = ["sb-A", "sb-evil", "sb-after-tests"]


def log(label: str, where: pathlib.Path = EVIDENCE):
    return tdx.events((where / f"{label}.ccel").read_bytes())


def regs(label: str, where: pathlib.Path = EVIDENCE):
    return tdx.registers((where / f"{label}.quote").read_bytes())


@pytest.mark.parametrize("label", list(META["captures"]))
def test_every_log_replays_to_its_quote_and_every_nonce_is_bound(label):
    q = (EVIDENCE / f"{label}.quote").read_bytes()
    assert q[tdx.BODY + tdx.REPORT_DATA : tdx.BODY + tdx.REPORT_DATA + 64] == (EVIDENCE / f"{label}.nonce").read_bytes()
    replayed = tdx.replay(log(label))
    for r in ("RTMR0", "RTMR1", "RTMR2"):
        assert replayed[r] == regs(label)[r], r


@pytest.mark.parametrize("label", SECURE)
def test_secure_boot_with_our_key_passes_the_policy(label):
    assert tdx.boot_policy(log(label), uki=UKI, db_cert=DB) == []


def test_the_override_entry_passes_because_secure_boot_ignored_its_command_line():
    """sb-evil booted from the entry carrying sentinel.uki=EVIL; the guest saw A.
    The only image loaded was the approved one, verified by our key."""
    assert tdx.boot_policy(log("sb-evil"), uki=UKI, db_cert=DB) == []


def test_turning_secure_boot_off_is_refused():
    failures = tdx.boot_policy(log("sb-off-evil"), uki=UKI, db_cert=DB)
    assert any("Secure Boot is off" in f for f in failures)


def test_the_earlier_boots_without_secure_boot_are_all_refused():
    for label in ("ccel-B-host-a", "ccel-evil-host-a"):
        evs = tdx.events((EARLIER / f"{label}.bin").read_bytes())
        assert tdx.boot_policy(evs, uki=UKI, db_cert=DB)


def test_secure_boot_was_verified_by_our_db_certificate():
    (auth,) = [e for e in log("sb-A") if e.type == tdx.EV_EFI_VARIABLE_AUTHORITY]
    assert DB in auth.data


def test_refused_boot_attempts_change_rtmr1_so_its_value_cannot_be_pinned():
    """Why the policy reads the log instead of comparing RTMR1."""
    assert regs("sb-A")["RTMR1"] != regs("sb-after-tests")["RTMR1"]
    retries = [e for e in log("sb-after-tests") if e.type == tdx.EV_EFI_ACTION and e.data.startswith(b"Returning")]
    assert retries


def test_under_secure_boot_only_the_signed_image_is_loaded_not_the_kernel_inside_it():
    images = [e.digest.hex() for e in log("sb-A") if e.type == tdx.EV_EFI_BOOT_SERVICES_APPLICATION]
    assert images == [UKI]
    off = [e.digest.hex() for e in log("sb-off-evil") if e.type == tdx.EV_EFI_BOOT_SERVICES_APPLICATION]
    assert off[0] == UKI and len(off) == 2


def test_signing_does_not_change_the_image_digest():
    """Authenticode excludes the signature, so the signed UKI A measures the same
    as the unsigned one from the earlier experiment."""
    earlier = json.loads((EARLIER / "meta.json").read_text())["images"]["A"]["authenticode_sha384"]
    assert UKI == earlier

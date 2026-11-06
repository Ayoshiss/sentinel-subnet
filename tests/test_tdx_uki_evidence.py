"""
The 2026-11-06 UKI experiment on GCP Intel TDX, checked from its raw evidence.

Every claim in the results write-up is asserted here against the quotes and
firmware event logs it was drawn from, so the write-up cannot drift from what
the hardware signed. Nothing here needs TDX hardware.
"""

import json
import pathlib

import pytest

from sentinel.tdx import eventlog as tdx

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence" / "tdx-uki-2026-11-06"

META = json.loads((EVIDENCE / "meta.json").read_text())


def quote(label: str) -> bytes:
    return (EVIDENCE / f"{label}.quote").read_bytes()


def regs(label: str) -> dict[str, str]:
    return tdx.registers(quote(label))


@pytest.mark.parametrize("label", list(META["captures"]))
def test_every_quote_carries_the_nonce_we_supplied(label):
    q = quote(label)
    nonce = (EVIDENCE / f"{label}.nonce").read_bytes()
    assert q[tdx.BODY + tdx.REPORT_DATA : tdx.BODY + tdx.REPORT_DATA + 64] == nonce


@pytest.mark.parametrize("log,label", list(META["event_logs"].items()))
def test_the_event_log_replays_to_exactly_what_the_chip_signed(log, label):
    """If this holds, every input to RTMR0-2 is accounted for by the log."""
    replayed = tdx.replay(tdx.events((EVIDENCE / log).read_bytes()))
    signed = regs(label)
    for r in ("RTMR0", "RTMR1", "RTMR2"):
        assert replayed[r] == signed[r], r


def test_the_same_image_measures_identically_on_two_hosts():
    a, b = regs("uki-A-hostA"), regs("uki-A-hostB")
    assert a == {**b, "RTMR3": a["RTMR3"]}


def test_one_changed_character_in_the_embedded_command_line_moves_rtmr1():
    a, b = regs("uki-A-hostA"), regs("uki-B-hostA")
    assert a["RTMR1"] != b["RTMR1"]
    assert a["RTMR0"] == b["RTMR0"]
    assert regs("uki-B-hostB")["RTMR1"] == b["RTMR1"]


def test_rtmr1_inputs_are_computable_from_the_file_without_booting_it():
    """The firmware measured the UKI's and the kernel's Authenticode digests."""
    evs = tdx.events((EVIDENCE / "ccel-B-host-a.bin").read_bytes())
    loaded = [e.digest.hex() for e in evs if e.type == tdx.EV_EFI_BOOT_SERVICES_APPLICATION]
    img = META["images"]["B"]
    assert loaded == [img["authenticode_sha384"], img["kernel_authenticode_sha384"]]


def test_rtmr2_is_empty_under_a_uki():
    """Nothing after the firmware measured anything, so RTMR2 carries no information."""
    for label in ("uki-A-hostA", "uki-B-hostA", "evil-on-A"):
        assert regs(label)["RTMR2"] == "0" * 96


def test_a_boot_entry_can_override_the_command_line_without_moving_rtmr1():
    """The hazard: with Secure Boot off the stub accepts the boot entry's load
    options in place of the embedded command line. RTMR1 is the approved value,
    so a policy pinning RTMR1 alone would accept a boot with dm-verity removed."""
    assert regs("evil-on-A")["RTMR1"] == regs("uki-A-hostA")["RTMR1"]


def test_the_override_is_visible_only_in_rtmr0():
    assert regs("evil-on-A")["RTMR0"] != regs("uki-A-hostA")["RTMR0"]
    evs = tdx.events((EVIDENCE / "ccel-evil-host-a.bin").read_bytes())
    boot_vars = dict(e.variable() for e in evs if e.type == tdx.EV_EFI_VARIABLE_BOOT)
    assert "sentinel.uki=EVIL".encode("utf-16le") in boot_vars["Boot0043"]
    assert all(e.rtmr == 0 for e in evs if e.type == tdx.EV_EFI_VARIABLE_BOOT)


def test_the_measured_partition_table_includes_the_disk_size():
    """So an approved value is only reproducible for a fixed boot disk size."""
    evs = tdx.events((EVIDENCE / "ccel-B-host-a.bin").read_bytes())
    (g,) = [tdx.gpt(e) for e in evs if e.type == tdx.EV_EFI_GPT_EVENT]
    gib = (g["last_usable_lba"] + 1) * 512 / 2**30
    assert round(gib) == META["boot_disk_gb"]

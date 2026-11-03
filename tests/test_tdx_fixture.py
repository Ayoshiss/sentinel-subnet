"""
What a real Intel TDX quote looks like, pinned from hardware.

Captured 2026-11-03 from a GCP `c3-standard-4` with
`--confidential-compute-type=TDX`, via the guest's ConfigFS TSM interface. The
fixture exists so the TDX verification path can be built and checked in CI the
way the AMD path already is, without anyone needing a confidential VM.

These tests assert the structure we believe the format has, taken from bytes the
hardware actually emitted. That distinction matters here more than usual: two of
the three SEV-SNP bugs found in August had unit tests that passed while being
wrong, because the fixture was built from the same assumption as the code. This
fixture was not built, it was captured.

Nothing here verifies the signature. That needs Intel's PCK chain and is the
next piece of work; these tests pin layout and binding only, and should keep
passing unchanged once the verifier lands.
"""

import json
import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "tdx"
QUOTE = FIXTURES / "tdx-quote.bin"
NONCE = FIXTURES / "tdx-nonce.bin"
META = FIXTURES / "tdx-quote-meta.json"

needs_fixture = pytest.mark.skipif(not QUOTE.exists(), reason="TDX fixture not present")

#: A v4 TD quote is a 48-byte header followed by the TD quote body. Offsets are
#: from the start of the body, per Intel's TDX DCAP quoting library.
BODY = 48
MRTD = 136
RTMR0, RTMR1, RTMR2, RTMR3 = 328, 376, 424, 472
REPORT_DATA = 520
DIGEST_LEN = 48


@pytest.fixture
def quote() -> bytes:
    return QUOTE.read_bytes()


@needs_fixture
def test_the_quote_is_a_v4_tdx_quote(quote):
    """Version 4 and TEE type 0x81. Guards against capturing an SGX quote."""
    assert len(quote) == 8000
    assert int.from_bytes(quote[0:2], "little") == 4
    assert int.from_bytes(quote[4:8], "little") == 0x81


@needs_fixture
def test_the_nonce_we_supplied_is_bound_into_report_data(quote):
    """The property the whole challenge-response rests on.

    We wrote 64 random bytes to the TSM interface and the chip put them in
    REPORT_DATA. A quote that did not carry our nonce would be a replay of some
    earlier one, which is exactly what the broker's freshness check exists to
    refuse.
    """
    assert quote[BODY + REPORT_DATA : BODY + REPORT_DATA + 64] == NONCE.read_bytes()


@needs_fixture
def test_the_measurement_registers_are_populated(quote):
    """MRTD and RTMR0-2 carry real digests; RTMR3 is free for runtime use.

    This is the shape that makes TDX useful to us and distinguishes it from
    SEV-SNP on the same cloud, where the launch measurement covers the firmware
    and nothing above it. Here the boot chain is measured into RTMR1 and RTMR2,
    which is what a dm-verity root hash on the command line would land in.
    """
    def reg(off: int) -> bytes:
        return quote[BODY + off : BODY + off + DIGEST_LEN]

    for name, off in (("MRTD", MRTD), ("RTMR0", RTMR0), ("RTMR1", RTMR1), ("RTMR2", RTMR2)):
        value = reg(off)
        assert len(value) == DIGEST_LEN
        assert value != bytes(DIGEST_LEN), f"{name} is all zero, which it should not be"

    # Unused on a stock boot. If this ever fails, something started extending it
    # and the verifier needs to know what.
    assert reg(RTMR3) == bytes(DIGEST_LEN)


@needs_fixture
def test_the_registers_do_not_overlap_or_run_past_the_body(quote):
    """Cheap guard against an offset typo producing plausible-looking garbage."""
    offsets = sorted([MRTD, RTMR0, RTMR1, RTMR2, RTMR3])
    for a, b in zip(offsets, offsets[1:]):
        assert b - a >= DIGEST_LEN
    assert BODY + REPORT_DATA + 64 <= len(quote)


@needs_fixture
def test_the_capture_context_is_recorded():
    """A fixture nobody can place is a fixture nobody can reproduce."""
    meta = json.loads(META.read_text())
    assert meta["provider"] == "tdx_guest"
    assert meta["confidential_compute_type"] == "TDX"
    assert meta["quote_bytes"] == 8000
    # The kernel and command line matter because they are what RTMR1 and RTMR2
    # measure, so a future mismatch explains itself rather than looking like a bug.
    assert meta["kernel"]
    assert "BOOT_IMAGE=" in meta["cmdline"]

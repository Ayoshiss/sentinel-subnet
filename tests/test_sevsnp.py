"""
Real SEV-SNP attestation: report parsing and verification.

Two groups of tests matter here.

The offset tests, because a wrong offset is the worst failure mode available: a
misread report parses without error and then verifies the wrong bytes, so the
system would confidently accept nonsense. Each field is asserted at its
documented position rather than trusted.

And the refusals, because verification only means something if it can say no —
to a corrupted signature, a foreign chip, unapproved code, stale firmware, a
debuggable guest, or a proof issued for a different request.

The certificate chain is exercised twice: against a synthetic root for speed,
and against AMD's genuine published certificates in an integration test.
"""

import hashlib
import struct

import pytest

from sentinel.attestation import VerificationError
from sentinel.sevsnp import (
    REPORT_SIZE,
    SIGNATURE_OFFSET,
    CertificateError,
    SevSnpPolicy,
    SevSnpVerifier,
    TcbVersion,
    load_cert_chain,
    parse_report,
)
from sentinel.sevsnp.certs import CertChain
from sentinel.sevsnp.report import ReportParseError
from sentinel.sevsnp.testing import build_cert_chain, build_report, pack_tcb

MEASUREMENT = hashlib.sha384(b"sentinel-miner-image-v0.1").digest()
OTHER_MEASUREMENT = hashlib.sha384(b"backdoored-image").digest()


@pytest.fixture(scope="module")
def chain_and_key():
    return build_cert_chain("Milan")


@pytest.fixture
def chain(chain_and_key):
    return chain_and_key[0]


@pytest.fixture
def vcek_key(chain_and_key):
    return chain_and_key[1]


@pytest.fixture
def vcek(chain_and_key):
    return chain_and_key[2]


@pytest.fixture
def policy():
    return SevSnpPolicy(approved_measurement=MEASUREMENT)


@pytest.fixture
def verifier(policy, chain):
    return SevSnpVerifier("Milan", policy, chain=chain, offline=True)


# --- structure ----------------------------------------------------------------

def test_report_is_the_documented_size():
    assert REPORT_SIZE == 1184 == 0x4A0
    assert SIGNATURE_OFFSET == 0x2A0


def test_fields_land_at_documented_offsets(vcek_key):
    """A misread offset parses silently, so pin each one explicitly."""
    chip = bytes(range(64))
    blob = build_report(vcek_key, measurement=MEASUREMENT, report_data=b"XYZ", chip_id=chip)
    r = parse_report(blob)

    assert blob[0x090:0x0C0] == r.measurement == MEASUREMENT
    assert blob[0x050:0x090] == r.report_data
    assert blob[0x1A0:0x1E0] == r.chip_id == chip
    assert struct.unpack_from("<I", blob, 0x000)[0] == r.version
    assert struct.unpack_from("<Q", blob, 0x008)[0] == r.policy
    assert struct.unpack_from("<Q", blob, 0x180)[0] == r.reported_tcb.raw


def test_signature_covers_everything_before_the_signature_field(vcek_key):
    blob = build_report(vcek_key, measurement=MEASUREMENT)
    r = parse_report(blob)
    assert r.signed_bytes == blob[:0x2A0]
    assert len(r.signed_bytes) == 672


def test_report_data_is_padded_to_64_bytes(vcek_key):
    r = parse_report(build_report(vcek_key, measurement=MEASUREMENT, report_data=b"short"))
    assert len(r.report_data) == 64
    assert r.report_data.startswith(b"short")
    assert r.report_data[5:] == b"\x00" * 59


def test_tcb_unpacks_each_component():
    tcb = TcbVersion.unpack(pack_tcb(bootloader=3, tee=0, snp=8, microcode=115))
    assert (tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode) == (3, 0, 8, 115)
    assert str(tcb) == "bl3.tee0.snp8.ucode115"


def test_trailing_bytes_are_tolerated(vcek_key):
    """/dev/sev-guest returns the report inside a larger response struct."""
    blob = build_report(vcek_key, measurement=MEASUREMENT)
    assert parse_report(blob + b"\xAA" * 256).measurement == MEASUREMENT


# --- malformed input ----------------------------------------------------------

def test_short_blob_is_rejected():
    with pytest.raises(ReportParseError, match="expected at least"):
        parse_report(b"\x00" * 100)


def test_zero_version_is_rejected(vcek_key):
    blob = bytearray(build_report(vcek_key, measurement=MEASUREMENT))
    struct.pack_into("<I", blob, 0x000, 0)
    with pytest.raises(ReportParseError, match="not a SEV-SNP report"):
        parse_report(bytes(blob))


def test_unknown_signature_algorithm_is_rejected(vcek_key):
    blob = build_report(vcek_key, measurement=MEASUREMENT, signature_algo=99)
    with pytest.raises(ReportParseError, match="unsupported signature algorithm"):
        parse_report(blob)


# --- signature ----------------------------------------------------------------

def test_valid_report_verifies(verifier, vcek_key, vcek):
    blob = build_report(vcek_key, measurement=MEASUREMENT, report_data=b"bind-1")
    out = verifier.verify(blob, expected_report_data=b"bind-1", vcek=vcek)
    assert out.measurement == MEASUREMENT


def test_corrupted_signature_is_rejected(verifier, vcek_key, vcek):
    blob = build_report(vcek_key, measurement=MEASUREMENT, corrupt_signature=True)
    with pytest.raises(VerificationError, match="signature invalid"):
        verifier.verify(blob, vcek=vcek)


def test_tampered_body_breaks_the_signature(verifier, vcek_key, vcek):
    """Editing any signed byte must invalidate the report."""
    blob = bytearray(build_report(vcek_key, measurement=MEASUREMENT))
    blob[0x090] ^= 0xFF  # flip a bit of the measurement
    with pytest.raises(VerificationError, match="signature invalid"):
        verifier.verify(bytes(blob), vcek=vcek)


def test_report_from_a_different_chip_is_rejected(verifier, chain):
    """A report signed by another chip's key must not verify under this VCEK."""
    _, other_key, other_vcek = build_cert_chain("Milan")
    blob = build_report(other_key, measurement=MEASUREMENT)
    with pytest.raises(VerificationError):
        verifier.verify(blob, vcek=other_vcek)  # foreign VCEK, foreign root


# --- policy -------------------------------------------------------------------

def test_unapproved_measurement_is_rejected(verifier, vcek_key, vcek):
    blob = build_report(vcek_key, measurement=OTHER_MEASUREMENT)
    with pytest.raises(VerificationError, match="launch measurement mismatch"):
        verifier.verify(blob, vcek=vcek)


@pytest.mark.parametrize("field,floor", [
    ("min_bootloader", 4), ("min_tee", 1), ("min_snp", 9), ("min_microcode", 200),
])
def test_stale_tcb_is_rejected(chain, vcek_key, vcek, field, floor):
    """Approved code on vulnerable firmware is still exploitable."""
    policy = SevSnpPolicy(approved_measurement=MEASUREMENT, **{field: floor})
    v = SevSnpVerifier("Milan", policy, chain=chain, offline=True)
    blob = build_report(vcek_key, measurement=MEASUREMENT)  # bl3.tee0.snp8.ucode115
    with pytest.raises(VerificationError, match="stale TCB"):
        v.verify(blob, vcek=vcek)


def test_current_tcb_at_the_floor_passes(chain, vcek_key, vcek):
    policy = SevSnpPolicy(approved_measurement=MEASUREMENT, min_bootloader=3, min_snp=8)
    v = SevSnpVerifier("Milan", policy, chain=chain, offline=True)
    assert v.verify(build_report(vcek_key, measurement=MEASUREMENT), vcek=vcek)


def test_debuggable_guest_is_rejected(chain, vcek_key, vcek):
    """Policy bit 19 means the host can inspect the guest, so the report proves
    nothing about confidentiality."""
    v = SevSnpVerifier("Milan", SevSnpPolicy(approved_measurement=MEASUREMENT),
                       chain=chain, offline=True)
    blob = build_report(vcek_key, measurement=MEASUREMENT, policy=0x30000 | (1 << 19))
    with pytest.raises(VerificationError, match="debug"):
        v.verify(blob, vcek=vcek)


def test_debuggable_guest_allowed_when_explicitly_permitted(chain, vcek_key, vcek):
    policy = SevSnpPolicy(approved_measurement=MEASUREMENT, allow_debug=True)
    v = SevSnpVerifier("Milan", policy, chain=chain, offline=True)
    blob = build_report(vcek_key, measurement=MEASUREMENT, policy=0x30000 | (1 << 19))
    assert v.verify(blob, vcek=vcek)


# --- request binding ----------------------------------------------------------

def test_binding_mismatch_is_rejected(verifier, vcek_key, vcek):
    blob = build_report(vcek_key, measurement=MEASUREMENT, report_data=b"request-A")
    with pytest.raises(VerificationError, match="response binding mismatch"):
        verifier.verify(blob, expected_report_data=b"request-B", vcek=vcek)


def test_binding_is_padded_before_comparison(verifier, vcek_key, vcek):
    """The caller passes a short binding; the report stores 64 padded bytes."""
    blob = build_report(vcek_key, measurement=MEASUREMENT, report_data=b"abc")
    assert verifier.verify(blob, expected_report_data=b"abc", vcek=vcek)


# --- offline guard ------------------------------------------------------------

def test_offline_verifier_will_not_reach_kds(verifier, vcek_key):
    blob = build_report(vcek_key, measurement=MEASUREMENT)
    with pytest.raises(VerificationError, match="offline"):
        verifier.verify(blob)  # no VCEK supplied


# --- certificate chain --------------------------------------------------------

def test_synthetic_chain_verifies(chain):
    chain.verify_self()


def test_non_self_signed_root_is_rejected(chain):
    other, _, _ = build_cert_chain("Genoa")
    with pytest.raises(CertificateError, match="not self-signed"):
        CertChain(product="x", ask=chain.ask, ark=other.ask).verify_self()


def test_ask_from_another_root_is_rejected(chain):
    other, _, _ = build_cert_chain("Genoa")
    with pytest.raises(CertificateError, match="ASK signed by ARK"):
        CertChain(product="x", ask=chain.ask, ark=other.ark).verify_self()


def test_chain_order_is_detected_not_assumed(chain):
    """AMD serves ASK first, but a reordered file must still be read correctly."""
    from cryptography.hazmat.primitives.serialization import Encoding

    reordered = chain.ark.public_bytes(Encoding.PEM) + chain.ask.public_bytes(Encoding.PEM)
    parsed = load_cert_chain("Milan", reordered)
    assert parsed.ark.subject == chain.ark.subject
    assert parsed.ask.subject == chain.ask.subject


def test_wrong_certificate_count_is_rejected(chain):
    from cryptography.hazmat.primitives.serialization import Encoding

    with pytest.raises(CertificateError, match="expected 2 certificates"):
        load_cert_chain("Milan", chain.ark.public_bytes(Encoding.PEM))


def test_unknown_product_is_rejected():
    from sentinel.sevsnp.certs import fetch_cert_chain

    with pytest.raises(CertificateError, match="unknown product"):
        fetch_cert_chain("Pentium")


# --- guest: asking the chip for a report --------------------------------------

def test_ioctl_constant_matches_the_iowr_macro():
    """Derived from _IOWR('S', 0, 24) rather than copied, so a wrong value here
    is a visible arithmetic error instead of a mystery EINVAL on hardware."""
    from sentinel.sevsnp.guest import SNP_GET_REPORT

    expected = (3 << 30) | (24 << 16) | (ord("S") << 8) | 0
    assert SNP_GET_REPORT == expected == 0xC0185300


def test_request_encoding():
    from sentinel.sevsnp.guest import REQ_SIZE, build_request

    req = build_request(bytes(range(64)), vmpl=0)
    assert len(req) == REQ_SIZE == 96
    assert req[:64] == bytes(range(64))
    assert struct.unpack_from("<I", req, 64)[0] == 0
    assert req[68:] == bytes(28)


def test_user_data_must_be_exactly_64_bytes():
    """Padding silently would let two different requests share a binding."""
    from sentinel.sevsnp.guest import GuestError, build_request

    for bad in (b"", b"short", bytes(63), bytes(65)):
        with pytest.raises(GuestError, match="exactly 64 bytes"):
            build_request(bad)


def test_vmpl_is_range_checked():
    from sentinel.sevsnp.guest import GuestError, build_request

    with pytest.raises(GuestError, match="vmpl"):
        build_request(bytes(64), vmpl=4)


def test_response_parsing_skips_the_header(vcek_key):
    """The report starts at offset 32, after status/size/reserved."""
    from sentinel.sevsnp.guest import RESP_HEADER_SIZE, parse_response

    report = build_report(vcek_key, measurement=MEASUREMENT)
    resp = struct.pack("<II", 0, REPORT_SIZE) + bytes(24) + report + bytes(2784)
    assert parse_response(resp) == report
    assert RESP_HEADER_SIZE == 32


def test_nonzero_firmware_status_is_an_error():
    from sentinel.sevsnp.guest import GuestError, parse_response

    resp = struct.pack("<II", 22, REPORT_SIZE) + bytes(24) + bytes(REPORT_SIZE)
    with pytest.raises(GuestError, match="status 22"):
        parse_response(resp)


def test_truncated_response_is_an_error():
    from sentinel.sevsnp.guest import GuestError, parse_response

    with pytest.raises(GuestError, match="too short"):
        parse_response(bytes(100))


def test_silicon_refuses_to_construct_without_hardware():
    from sentinel.sevsnp.guest import GuestError, SevSnpSilicon

    with pytest.raises(GuestError, match="not a SEV-SNP guest|needs a SEV-SNP guest"):
        SevSnpSilicon(device="/nonexistent/sev-guest")


def test_available_is_false_on_this_machine():
    from sentinel.sevsnp.guest import available

    assert available() is False  # a laptop is not a confidential VM


# --- sign / verify round trip -------------------------------------------------

def test_sign_then_verify_round_trip(chain, vcek_key, vcek):
    """The full Silicon-shaped flow, with real report bytes underneath."""
    from sentinel.sevsnp.testing import FakeSevSnpSilicon

    silicon = FakeSevSnpSilicon(vcek_key, MEASUREMENT)
    v = SevSnpVerifier("Milan", SevSnpPolicy(approved_measurement=MEASUREMENT),
                       chain=chain, offline=True)

    message = b"attest this exact response"
    report = silicon.sign(message)
    out = v.verify_signed_message(message, report, vcek=vcek)
    assert out.measurement == MEASUREMENT
    assert out.chip_id_hex == silicon.chip_id


def test_report_does_not_verify_for_a_different_message(chain, vcek_key, vcek):
    """The binding is what stops a report being reused for other data."""
    from sentinel.sevsnp.testing import FakeSevSnpSilicon

    silicon = FakeSevSnpSilicon(vcek_key, MEASUREMENT)
    v = SevSnpVerifier("Milan", SevSnpPolicy(approved_measurement=MEASUREMENT),
                       chain=chain, offline=True)

    report = silicon.sign(b"message A")
    with pytest.raises(VerificationError, match="response binding mismatch"):
        v.verify_signed_message(b"message B", report, vcek=vcek)


def test_malformed_hex_is_rejected(verifier, vcek):
    with pytest.raises(VerificationError, match="not valid hex"):
        verifier.verify_signed_message(b"msg", "not-hex-at-all", vcek=vcek)

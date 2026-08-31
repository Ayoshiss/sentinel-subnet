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
import pathlib
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
from sentinel.sevsnp.certtable import CertTableError, der_to_pem, parse_cert_table
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
    """An ASK the root did not sign, with the root itself above suspicion.

    The chain is anchored to `other`'s own key so the root pin passes, which
    forces the failure to come from the ASK signature rather than from the
    anchor check. Otherwise this would pass for the wrong reason and stop
    testing the link it is named after.
    """
    from sentinel.sevsnp.certs import root_spki_sha256

    other, _, _ = build_cert_chain("Genoa")
    with pytest.raises(CertificateError, match="ASK signed by ARK"):
        CertChain(
            product="x", ask=chain.ask, ark=other.ark,
            expected_root_spki_sha256=root_spki_sha256(other.ark),
        ).verify_self()


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
    """_IOWR('S', 0, sizeof(struct snp_guest_request_ioctl)).

    The struct is `__u8 msg_version` followed by three `__u64`s, so the u8 pads
    out to 32 bytes — not the 24 this test originally asserted. Both the
    constant and this test were derived from that same wrong size, so the suite
    confirmed the bug rather than catching it, and the kernel only objected on
    real silicon with a bare ENOTTY. Hence the size is now taken from the format
    string actually used to pack the struct: the two cannot disagree again.
    """
    from sentinel.sevsnp.guest import IOCTL_FORMAT, SNP_GET_REPORT

    assert struct.calcsize(IOCTL_FORMAT) == 32
    expected = (3 << 30) | (32 << 16) | (ord("S") << 8) | 0
    assert SNP_GET_REPORT == expected == 0xC0205300


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


# --- the standalone capture script must not drift ----------------------------

def test_capture_script_agrees_with_the_parser(vcek_key):
    """scripts/capture_report.py duplicates the offsets on purpose, so it can run
    on a bare confidential VM before anything is installed. That duplication is
    only safe while both readings agree — a drift would mean the script reports
    one thing and the tested parser another, on the one machine where checking is
    expensive."""
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "capture_report.py"
    spec = importlib.util.spec_from_file_location("capture_report", path)
    cap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cap)

    assert cap.REPORT_SIZE == REPORT_SIZE
    assert cap.SIGNATURE_OFFSET == SIGNATURE_OFFSET
    assert cap.SNP_GET_REPORT == 0xC0205300
    assert struct.calcsize(cap.IOCTL_FORMAT) == 32

    user_data = hashlib.sha512(b"marker").digest()
    blob = build_report(vcek_key, measurement=MEASUREMENT, report_data=user_data)
    parsed = parse_report(blob)

    assert blob[0x090:0x0C0] == parsed.measurement
    assert blob[0x050:0x090] == parsed.report_data == user_data
    assert blob[0x1A0:0x1E0].hex().upper() == parsed.chip_id_hex

    tcb = cap.unpack_tcb(struct.unpack_from("<Q", blob, 0x180)[0])
    assert tcb == {
        "bootloader": parsed.reported_tcb.bootloader,
        "tee": parsed.reported_tcb.tee,
        "snp": parsed.reported_tcb.snp,
        "microcode": parsed.reported_tcb.microcode,
    }


# --- a report from real silicon ----------------------------------------------

#: Captured 2026-08-31 from an AMD EPYC 7B13 (Milan) SEV-SNP guest on GCP,
#: `n2d-standard-2` in us-central1-b, running at VMPL0. Every other test in this
#: file builds its reports with a synthetic key, which proves the parser is
#: self-consistent but cannot prove it reads what a real chip actually emits.
REAL_REPORT = pathlib.Path(__file__).parent / "fixtures" / "sevsnp-report-20260831T055035Z.bin"

#: What that chip reported. Pinned so a parsing change that silently shifts an
#: offset fails here rather than on the next confidential VM.
REAL_MEASUREMENT = (
    "2d24cf9624ee36449e50c6c84042540b05898f6559f02741b7b354e0cc2ed18d"
    "108352ade7dfc4cecce4fa974e51c773"
)
REAL_CHIP_ID_PREFIX = "73F0B5A781DB2168"


@pytest.mark.skipif(not REAL_REPORT.exists(), reason="hardware fixture not present")
def test_parses_a_report_from_real_hardware():
    """The offsets, read against bytes no test wrote."""
    blob = REAL_REPORT.read_bytes()
    assert len(blob) == REPORT_SIZE

    r = parse_report(blob)
    assert r.version == 5
    assert r.measurement.hex() == REAL_MEASUREMENT
    assert len(r.measurement) == 48
    assert r.chip_id_hex.startswith(REAL_CHIP_ID_PREFIX)
    assert r.signed_bytes == blob[:SIGNATURE_OFFSET]

    # The capture bound sha512 of a marker into REPORT_DATA and the chip echoed
    # it back, which is what confirms 0x050 is the right offset on real silicon.
    assert len(r.report_data) == 64
    assert r.report_data != b"\x00" * 64


@pytest.mark.skipif(not REAL_REPORT.exists(), reason="hardware fixture not present")
def test_real_guest_was_not_debuggable():
    """Policy bit 19 clear: the host could not inspect this guest, so the report
    says something about confidentiality rather than nothing."""
    r = parse_report(REAL_REPORT.read_bytes())
    assert not (r.policy >> 19) & 1
    SevSnpPolicy(approved_measurement=r.measurement).check(r)


# --- the host certificate table (extended report) -----------------------------

def _entry(guid_str, offset, length):
    """A table entry as a real host emits one: GUID big-endian, RFC 4122 order."""
    import uuid
    return uuid.UUID(guid_str).bytes + struct.pack("<II", offset, length)


def _build_table(certs):
    """certs: list of (guid, der). Lays out a table exactly as a host would."""
    from sentinel.sevsnp.certtable import ENTRY_SIZE

    header_len = (len(certs) + 1) * ENTRY_SIZE   # +1 for the zero terminator
    header, body, cursor = b"", b"", header_len
    for guid, der in certs:
        header += _entry(guid, cursor, len(der))
        body += der
        cursor += len(der)
    return header + bytes(ENTRY_SIZE) + body


VCEK_GUID = "63da758d-e664-4564-adc5-f4b93be8accd"
ASK_GUID = "4ab7b379-bbac-4fe4-a02f-05aef327c782"
ARK_GUID = "c0b406a4-a803-4952-9743-3fb6014cd0ae"


def test_cert_table_splits_by_guid():
    blob = _build_table([(VCEK_GUID, b"VVVV"), (ASK_GUID, b"AAAAAA"), (ARK_GUID, b"RR")])
    assert parse_cert_table(blob) == {"VCEK": b"VVVV", "ASK": b"AAAAAA", "ARK": b"RR"}


def test_guids_are_read_big_endian():
    """RFC 4122 order, not the Microsoft mixed-endian convention.

    Pinned against bytes a real GCP host emitted, because the original version
    of this test built its fixture with the same wrong assumption as the code
    and therefore passed while hardware returned three unrecognised GUIDs.
    Reading these the wrong way round is not an error, it is a silent fall back
    to KDS, so the wrong reading is asserted to fail explicitly.
    """
    import uuid

    # Verbatim from the certificate table of an EPYC 7B13 on GCP, 2026-08-31.
    raw = bytes.fromhex("63da758de6644564adc5f4b93be8accd")
    assert str(uuid.UUID(bytes=raw)) == VCEK_GUID
    assert str(uuid.UUID(bytes_le=raw)) == "8d75da63-64e6-6445-adc5-f4b93be8accd"

    assert _entry(VCEK_GUID, 0, 0)[:16] == raw
    assert parse_cert_table(_build_table([(VCEK_GUID, b"X")])) == {"VCEK": b"X"}


def test_empty_blob_is_not_an_error():
    """A host that provisions nothing is a normal case, distinct from corruption:
    the caller has to be able to fall back to KDS rather than crash."""
    assert parse_cert_table(b"") == {}
    assert parse_cert_table(bytes(96)) == {}


def test_unknown_guid_is_kept_under_its_uuid():
    other = "11111111-2222-3333-4444-555555555555"
    assert parse_cert_table(_build_table([(other, b"Z")])) == {other: b"Z"}


def test_entry_pointing_outside_the_blob_is_rejected():
    blob = bytearray(_build_table([(VCEK_GUID, b"X")]))
    struct.pack_into("<I", blob, 20, 9999)  # absurd length on the first entry
    with pytest.raises(CertTableError, match="outside the blob"):
        parse_cert_table(bytes(blob))


def test_unterminated_table_is_rejected():
    from sentinel.sevsnp.certtable import ENTRY_SIZE

    blob = _entry(VCEK_GUID, ENTRY_SIZE, 1) + b"X"
    with pytest.raises(CertTableError, match="no terminating entry"):
        parse_cert_table(blob)


def test_der_to_pem_round_trips(vcek):
    """PEM is emitted with the standard library so it works on a bare VM."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    der = vcek.public_bytes(Encoding.DER)
    reloaded = x509.load_pem_x509_certificate(der_to_pem(der))
    assert reloaded.public_bytes(Encoding.DER) == der


# --- the extended request struct ---------------------------------------------

def test_ext_report_ioctl_and_struct_sizes():
    from sentinel.sevsnp.guest import (
        EXT_REQ_FORMAT, REQ_SIZE, SNP_GET_EXT_REPORT, build_ext_request,
    )

    # Outer struct is unchanged; only the request body and the nr differ.
    assert SNP_GET_EXT_REPORT == (3 << 30) | (32 << 16) | (ord("S") << 8) | 0x2
    assert SNP_GET_EXT_REPORT == 0xC0205302
    assert struct.calcsize(EXT_REQ_FORMAT) == 112  # 96 + u64 + u32 + padding

    req = build_ext_request(hashlib.sha512(b"m").digest(), certs_addr=0xDEAD, certs_len=64)
    inner, addr, length = struct.unpack(EXT_REQ_FORMAT, req)
    assert len(inner) == REQ_SIZE
    assert (addr, length) == (0xDEAD, 64)
    assert inner[:64] == hashlib.sha512(b"m").digest()


# --- end to end, on bytes from real silicon -----------------------------------

HOST_DIR = pathlib.Path(__file__).parent / "fixtures" / "gcp-host-certs"
EXT_REPORT = HOST_DIR / "sevsnp-report-20260831T061928Z.bin"
HOST_BLOB = HOST_DIR / "host-certs-20260831T061928Z.bin"

needs_host_certs = pytest.mark.skipif(
    not EXT_REPORT.exists(), reason="hardware fixtures not present"
)


@pytest.fixture
def host_certs():
    """The certificate table exactly as a GCP host emitted it, 8192 bytes."""
    return parse_cert_table(HOST_BLOB.read_bytes())


@needs_host_certs
def test_host_certificate_table_yields_the_full_chain(host_certs):
    """The GUIDs a real host writes, decoded to the certificates AMD issues.

    This is the test the original endianness bug would have failed. The earlier
    unit tests could not catch it because they built their own fixtures; this
    one reads bytes produced by hardware.
    """
    assert set(host_certs) == {"VCEK", "ASK", "ARK"}

    from cryptography import x509
    subjects = {
        name: x509.load_der_x509_certificate(der).subject.rfc4514_string()
        for name, der in host_certs.items()
    }
    assert "SEV-VCEK" in subjects["VCEK"]
    assert "SEV-Milan" in subjects["ASK"]
    assert "ARK-Milan" in subjects["ARK"]


@needs_host_certs
def test_real_report_verifies_offline_against_amd(host_certs):
    """A genuine report, verified with no network at all.

    `offline=True` makes any attempt to reach AMD's KDS an error rather than a
    silent fallback, so this passing means the whole chain — AMD's root, its
    signing key, the chip's own key, and the report signature — was checked from
    bytes the host handed over with the proof. That is the property that keeps a
    validator working on the day KDS is unreachable, which is the day this was
    written.
    """
    from cryptography import x509

    blob = EXT_REPORT.read_bytes()
    report = parse_report(blob)
    chain = CertChain(
        product="Milan",
        ask=x509.load_der_x509_certificate(host_certs["ASK"]),
        ark=x509.load_der_x509_certificate(host_certs["ARK"]),
    )
    tcb = report.reported_tcb
    verifier = SevSnpVerifier(
        "Milan",
        SevSnpPolicy(
            approved_measurement=report.measurement,
            min_bootloader=tcb.bootloader, min_tee=tcb.tee,
            min_snp=tcb.snp, min_microcode=tcb.microcode,
        ),
        chain=chain,
        offline=True,
    )
    vcek = x509.load_der_x509_certificate(host_certs["VCEK"])

    verified = verifier.verify(blob, vcek=vcek)
    assert verified.measurement == report.measurement
    assert len(verified.signed_bytes) == 672


@needs_host_certs
def test_tampering_with_a_real_report_is_caught(host_certs):
    """The same verification must still be able to say no."""
    from cryptography import x509

    blob = bytearray(EXT_REPORT.read_bytes())
    blob[0x090] ^= 0xFF  # flip one bit of the launch measurement
    report = parse_report(bytes(blob))

    chain = CertChain(
        product="Milan",
        ask=x509.load_der_x509_certificate(host_certs["ASK"]),
        ark=x509.load_der_x509_certificate(host_certs["ARK"]),
    )
    verifier = SevSnpVerifier(
        "Milan", SevSnpPolicy(approved_measurement=report.measurement),
        chain=chain, offline=True,
    )
    with pytest.raises(VerificationError, match="signature invalid"):
        verifier.verify(bytes(blob), vcek=x509.load_der_x509_certificate(host_certs["VCEK"]))


@needs_host_certs
def test_the_launch_measurement_is_reproducible_across_hosts():
    """Two captures, two different physical chips, same measurement.

    This is what makes pinning a measurement meaningful: it identifies the
    image, not the machine. If it varied per host there would be nothing stable
    to approve.
    """
    first = parse_report(REAL_REPORT.read_bytes())
    second = parse_report(EXT_REPORT.read_bytes())

    assert first.chip_id_hex != second.chip_id_hex     # genuinely different chips
    assert first.measurement == second.measurement     # identical image


# --- the root of trust --------------------------------------------------------

def test_forged_chain_is_rejected():
    """The attack that worked before the root was pinned.

    An attacker with no AMD silicon generates their own root, signs an ASK with
    it, signs a VCEK with that, and signs a report claiming the approved launch
    measurement. Every signature in that chain verifies, because they made all
    of them. Internal consistency is not evidence of anything; only the identity
    of the root is.
    """
    evil_chain, evil_key, evil_vcek = build_cert_chain("Milan")
    forged = build_report(evil_key, measurement=MEASUREMENT, report_data=b"bind")

    # The attacker presents their chain as AMD's, which is the whole trick.
    passed_off_as_amd = CertChain(
        product="Milan", ask=evil_chain.ask, ark=evil_chain.ark
    )
    verifier = SevSnpVerifier(
        "Milan", SevSnpPolicy(approved_measurement=MEASUREMENT),
        chain=passed_off_as_amd, offline=True,
    )
    with pytest.raises((CertificateError, VerificationError), match="not AMD's root"):
        verifier.verify(forged, expected_report_data=b"bind", vcek=evil_vcek)


def test_a_convincing_subject_line_does_not_help():
    """`CN=ARK-Milan, O=Advanced Micro Devices` is not a secret.

    The real ARK and a forged one carry the same subject and are both
    self-signed, so neither field can distinguish them. Only the key can.
    """
    evil_chain, _, _ = build_cert_chain("Milan")
    assert "ARK-Milan" in evil_chain.ark.subject.rfc4514_string()
    assert evil_chain.ark.subject == evil_chain.ark.issuer  # self-signed, like AMD's

    with pytest.raises(CertificateError, match="not AMD's root"):
        CertChain(product="Milan", ask=evil_chain.ask, ark=evil_chain.ark).verify_self()


def test_unpinned_product_fails_closed():
    """No pinned root means no verification, not a waved-through one.

    Genoa and Turin have no pinned key yet. Accepting them 'until we add it'
    would accept every forged Genoa chain in the meantime.
    """
    from sentinel.sevsnp.certs import AMD_ROOT_SPKI_SHA256

    assert "Genoa" not in AMD_ROOT_SPKI_SHA256
    evil_chain, _, _ = build_cert_chain("Genoa")
    with pytest.raises(CertificateError, match="no pinned AMD root"):
        CertChain(product="Genoa", ask=evil_chain.ask, ark=evil_chain.ark).verify_self()


@needs_host_certs
def test_the_pinned_key_is_the_one_real_hardware_presented(host_certs):
    """The pin matches what an actual AMD chip's host handed over.

    Pinned from hardware rather than transcribed from a document, so this
    asserts the constant was not fat-fingered.
    """
    from cryptography import x509

    from sentinel.sevsnp.certs import AMD_ROOT_SPKI_SHA256, root_spki_sha256

    ark = x509.load_der_x509_certificate(host_certs["ARK"])
    assert root_spki_sha256(ark) == AMD_ROOT_SPKI_SHA256["Milan"]
    assert ark.public_key().key_size == 4096

    # And the real chain still validates against the pin.
    CertChain(
        product="Milan",
        ask=x509.load_der_x509_certificate(host_certs["ASK"]),
        ark=ark,
    ).verify_self()

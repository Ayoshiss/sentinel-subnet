"""Tests for the Sentinel attestation core."""

import pytest
from sentinel.attestation import (
    MockSilicon, AttestationAgent, verify, VerificationError,
    new_nonce, sha384, bind_response, verifier_from_public_key,
)

APPROVED = sha384(b"sentinel-miner-image-v0.1")


def make_agent(measurement=APPROVED, tcb=7):
    chip = MockSilicon()
    return chip, AttestationAgent(chip, measurement, tcb)


def test_valid_attestation_passes():
    chip, agent = make_agent()
    nonce = new_nonce()
    rd = bind_response("req-1", sha384(b"result"))
    report = agent.attest(nonce, rd)
    assert verify(report, chip.public_verifier(), APPROVED, nonce, expected_report_data=rd)


def test_tampered_code_fails():
    """A miner running a different image produces a different launch measurement."""
    chip, agent = make_agent(measurement=sha384(b"tampered-image"))
    nonce = new_nonce()
    report = agent.attest(nonce, bind_response("req", sha384(b"x")))
    with pytest.raises(VerificationError, match="launch measurement"):
        verify(report, chip.public_verifier(), APPROVED, nonce)


def test_forged_signature_fails():
    """A report signed by a different chip must not verify against the real one."""
    _, agent = make_agent()
    nonce = new_nonce()
    report = agent.attest(nonce, bind_response("req", sha384(b"x")))
    other_chip = MockSilicon()
    with pytest.raises(VerificationError, match="signature"):
        verify(report, other_chip.public_verifier(), APPROVED, nonce)


def test_replayed_nonce_fails():
    chip, agent = make_agent()
    report = agent.attest(new_nonce(), bind_response("req", sha384(b"x")))
    with pytest.raises(VerificationError, match="nonce"):
        verify(report, chip.public_verifier(), APPROVED, expected_nonce=new_nonce())


def test_stale_tcb_fails():
    chip, agent = make_agent(tcb=5)
    nonce = new_nonce()
    report = agent.attest(nonce, bind_response("req", sha384(b"x")))
    with pytest.raises(VerificationError, match="TCB"):
        verify(report, chip.public_verifier(), APPROVED, nonce, min_tcb=7)


def test_response_binding_mismatch_fails():
    """A valid proof for response A must not validate response B."""
    chip, agent = make_agent()
    nonce = new_nonce()
    rd_a = bind_response("req", sha384(b"result-A"))
    report = agent.attest(nonce, rd_a)
    rd_b = bind_response("req", sha384(b"result-B"))
    with pytest.raises(VerificationError, match="response binding"):
        verify(report, chip.public_verifier(), APPROVED, nonce, expected_report_data=rd_b)


# --- Asymmetry: the properties Ed25519 buys over a shared-secret HMAC ---------

def test_public_key_alone_verifies():
    """The headline property: verification needs the PUBLIC key and nothing else.

    Models fetching a chip's certificate and checking its reports with no
    access to the chip and no shared secret.
    """
    chip, agent = make_agent()
    nonce = new_nonce()
    rd = bind_response("req-1", sha384(b"result"))
    report = agent.attest(nonce, rd)

    # Verifier rebuilt from the published key alone — the chip is not involved.
    verifier = verifier_from_public_key(chip.public_key_hex)
    assert verify(report, verifier, APPROVED, nonce, expected_report_data=rd)


def test_verifier_carries_no_private_key():
    """A verifier must be safe to hand to anyone — it holds no signing power."""
    chip, _ = make_agent()
    verifier = chip.public_verifier()
    leaked = [
        v for v in vars(verifier).values()
        if isinstance(v, type(chip._private_key))
    ]
    assert not leaked, "verifier must not hold private key material"
    # And it genuinely cannot sign.
    assert not hasattr(verifier, "sign")


def test_public_key_of_other_chip_rejects():
    """Public verifiability must still be chip-specific."""
    _, agent = make_agent()
    nonce = new_nonce()
    report = agent.attest(nonce, bind_response("req", sha384(b"x")))
    stranger = verifier_from_public_key(MockSilicon().public_key_hex)
    with pytest.raises(VerificationError, match="signature"):
        verify(report, stranger, APPROVED, nonce)


def test_seeded_chip_is_deterministic():
    """Same seed → same identity, so demos and fixtures are reproducible."""
    seed = b"\x01" * 32
    a, b = MockSilicon.from_seed(seed), MockSilicon.from_seed(seed)
    assert a.public_key_hex == b.public_key_hex
    # Signatures from one verify under the other's public key.
    msg = b"same-chip"
    assert b.public_verifier().valid(msg, a.sign(msg))


def test_malformed_signature_is_rejected_not_raised():
    """valid() must return False on junk, never explode."""
    chip, agent = make_agent()
    nonce = new_nonce()
    report = agent.attest(nonce, bind_response("req", sha384(b"x")))
    verifier = chip.public_verifier()
    for junk in ("", "zzzz", "abc", "00" * 64):
        assert verifier.valid(report.canonical(), junk) is False


def test_tampered_report_field_fails_signature():
    """Mutating any signed field must break the signature."""
    chip, agent = make_agent()
    nonce = new_nonce()
    report = agent.attest(nonce, bind_response("req", sha384(b"x")))
    report.tcb_level = 99  # signed field, now inconsistent with the signature
    with pytest.raises(VerificationError, match="signature"):
        verify(report, chip.public_verifier(), APPROVED, nonce)

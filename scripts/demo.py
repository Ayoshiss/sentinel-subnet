"""
End-to-end attested query — the Sentinel flow, simulated.

Run:  python scripts/demo.py

Shows: a validator issues a nonce -> the miner executes a query inside the
enclave and binds an attestation -> anyone holding only the chip's PUBLIC key
verifies it, with zero trust in the miner and no shared secret. Swap
MockSilicon for real SEV-SNP and the flow is unchanged.

SIMULATION. The mock chip signs with a software Ed25519 key, not a
silicon-resident AMD-certified VCEK. It proves the protocol, not the hardware
root of trust.
"""

import pathlib
import sys

# Run directly (`python scripts/demo.py`) without installing the package.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.attestation import (
    MockSilicon, AttestationAgent, verify, VerificationError,
    new_nonce, sha384, bind_response, verifier_from_public_key,
)

APPROVED = sha384(b"sentinel-miner-image-v0.1")


def check(label: str, **kw) -> None:
    """Run one verification and report the outcome."""
    try:
        verify(**kw)
        print(f"  VERIFIED  — {label}")
    except VerificationError as e:
        print(f"  REJECTED  — {label}: {e}")


def run():
    print("Sentinel — attested query demo")
    print("(simulation: software Ed25519 stands in for an AMD SEV-SNP VCEK)")
    print("-" * 64)

    # Miner boots an enclave running the approved image.
    chip = MockSilicon()
    agent = AttestationAgent(chip, launch_measurement=APPROVED, tcb_level=7)
    print(f"\n[miner]     enclave up. chip={chip.chip_id}")
    print(f"[miner]     public key published: {chip.public_key_hex[:32]}…")
    print("            (the private key never leaves the 'chip')")

    # A request arrives; the enclave 'executes' it (mock query result).
    request_id = "req-42"
    result = {"vulnerability": "reentrancy", "severity": "high"}
    response_hash = sha384(str(result).encode())

    # A validator/gateway challenges with a fresh nonce.
    nonce = new_nonce()
    report_data = bind_response(request_id, response_hash)
    report = agent.attest(nonce, report_data)
    print(f"\n[validator] challenge nonce={nonce[:16]}…")
    print(f"[miner]     query executed → {result}")
    print(f"[miner]     attestation signed, bound to this exact response")

    # Anyone can verify using ONLY the published public key — no chip, no secret.
    print("\n[anyone]    verifying with the PUBLIC key alone (no shared secret):")
    public_only = verifier_from_public_key(chip.public_key_hex)
    check(
        "genuine hardware, approved code, this exact response",
        report=report, verifier=public_only, approved_measurement=APPROVED,
        expected_nonce=nonce, expected_report_data=report_data,
    )

    # Tamper-detection: a miner that modifies the result after attesting is caught.
    print("\n[tamper]    miner alters the result after attesting:")
    forged_data = bind_response(request_id, sha384(str({"vulnerability": "none"}).encode()))
    check(
        "altered response",
        report=report, verifier=public_only, approved_measurement=APPROVED,
        expected_nonce=nonce, expected_report_data=forged_data,
    )

    # Impersonation: a different chip's key must not validate this report.
    print("\n[impostor]  unrelated chip claims to have produced this report:")
    check(
        "wrong chip's public key",
        report=report, verifier=verifier_from_public_key(MockSilicon().public_key_hex),
        approved_measurement=APPROVED, expected_nonce=nonce,
    )

    print("\n" + "-" * 64)
    print("Verification required no secret — only the chip's public key.")
    print("That is the trust shape of a real VCEK checked against AMD's cert chain.")


if __name__ == "__main__":
    run()

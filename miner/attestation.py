"""
SEV-SNP attestation agent (stub).

Generates an AMD SEV-SNP attestation report on demand and binds it to a
caller-supplied nonce. The report is signed by the CPU's VCEK and chains to
the AMD root key (ARK -> ASK -> VCEK), so it can be verified offline by any
party without trusting the miner.
"""

from __future__ import annotations

import hashlib


class AttestationAgent:
    def __init__(self, config) -> None:
        self.config = config

    def generate_report(self, nonce: bytes) -> dict:
        """Return a signed attestation report bound to `nonce`.

        In production this issues an ioctl to /dev/sev-guest and returns the
        VCEK-signed report. Here we return the report envelope shape so callers
        and tests can integrate against a stable interface.
        """
        report_data = hashlib.sha384(nonce).hexdigest()
        return {
            "chipID": "<amd-epyc-serial>",
            "launchMeasurement": self.config.enclave_image_hash or "<measurement>",
            "tcbLevel": None,
            "reportData": report_data,   # binds this report to the nonce
            "signature": "<vcek-signature>",
            "certChain": "ARK->ASK->VCEK",
        }

    def bind_response(self, request_id: str, response_hash: str) -> bytes:
        """Compute the value bound into reportData for a served response."""
        return hashlib.sha384(f"{request_id}{response_hash}".encode()).digest()

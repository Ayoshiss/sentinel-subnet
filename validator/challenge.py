"""
Validator challenge issuance.

Re-exports the canonical nonce generator rather than defining a second one.
A validator's challenge and the enclave's report must agree on the exact nonce
representation, so there can only be one implementation of it — this used to
return raw bytes while `sentinel.attestation` returned hex, which would have
failed verification the moment the two met.
"""

from __future__ import annotations

from sentinel.attestation import new_nonce

__all__ = ["new_nonce"]

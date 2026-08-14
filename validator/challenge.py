"""Validator challenge issuance (stub)."""

from __future__ import annotations

import secrets


def new_nonce() -> bytes:
    """Return a fresh 32-byte nonce for an attestation challenge."""
    return secrets.token_bytes(32)

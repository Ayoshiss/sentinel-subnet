"""
Real Intel TDX attestation.

The counterpart of `sentinel.sevsnp` for Intel TDX. On GCP it is the platform
that closes the gap SEV-SNP leaves: there the launch measurement covers the
firmware and nothing above it, while TDX measures the boot chain into RTMRs and
a unified kernel image under Secure Boot pins exactly which code booted.

`verifier` is the validator and broker side; `guest` is the miner side, which
asks the TDX module for quotes through configfs-tsm.
"""

from .verifier import (
    ALLOWED_TCB_STATUS,
    MIN_DCAP_QVL,
    PCCS_URL,
    CollateralCache,
    TdxEvidence,
    TdxPolicy,
    TdxVerifier,
    decode_event_log,
    encode_event_log,
)

__all__ = [
    "ALLOWED_TCB_STATUS",
    "MIN_DCAP_QVL",
    "PCCS_URL",
    "CollateralCache",
    "TdxEvidence",
    "TdxPolicy",
    "TdxVerifier",
    "decode_event_log",
    "encode_event_log",
]

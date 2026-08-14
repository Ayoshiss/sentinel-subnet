"""Miner configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class MinerConfig:
    """Runtime configuration for a Sentinel miner."""

    hotkey: str = ""
    kbs_url: str = ""            # Key Broker Service endpoint
    subtensor_endpoint: str = "" # Bittensor chain endpoint
    netuid: int = 0              # assigned at registration
    enclave_image_hash: str = "" # approved SEV-SNP launch measurement
    tools: tuple[str, ...] = ("postgres.query", "solana.rpc")

    @classmethod
    def from_env(cls) -> "MinerConfig":
        return cls(
            hotkey=os.getenv("SENTINEL_HOTKEY", ""),
            kbs_url=os.getenv("SENTINEL_KBS_URL", ""),
            subtensor_endpoint=os.getenv("SENTINEL_SUBTENSOR", ""),
            netuid=int(os.getenv("SENTINEL_NETUID", "0")),
            enclave_image_hash=os.getenv("SENTINEL_IMAGE_HASH", ""),
        )

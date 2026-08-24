"""
Sentinel miner neuron — entrypoint.

A miner runs an MCP server inside an AMD SEV-SNP enclave, serves attested tool
calls, and answers validator attestation challenges. This module is the Bittensor
neuron wrapper around that: registration, lifecycle, and the challenge loop.

What is real and what is not:

    * The enclave, Key Broker handshake, MCP tools and attestation all work
      today — they live in `sentinel/` and are imported here, not reimplemented.
    * The Bittensor parts (subnet registration, collateral, the serving loop)
      are NOT built. Those methods raise NotImplementedError and land in
      Milestone 4. See ROADMAP.md.

So this file is scaffolding around working components, not a stub pretending to
be a system.
"""

from __future__ import annotations

import logging

from sentinel.attestation import MockSilicon, new_nonce
from sentinel.enclave import AttestedResponse, Enclave
from sentinel.kbs import KeyBroker
from sentinel.mcp import MCPServer

from .config import MinerConfig

logger = logging.getLogger("sentinel.miner")


class SentinelMiner:
    """Top-level miner neuron.

    Lifecycle:
        1. Register on the subnet (hotkey + collateral).            [Milestone 4]
        2. Boot the SEV-SNP enclave.                                 [simulated]
        3. Attest to the KBS and receive customer credentials.       [working]
        4. Serve MCP tool calls, each bound to a fresh attestation.  [working]
        5. Answer validator challenges every ~360 blocks.            [working]
    """

    def __init__(self, config: MinerConfig, broker: KeyBroker | None = None) -> None:
        self.config = config
        self.broker = broker
        # MockSilicon until the SEV-SNP backend lands; the Silicon protocol is
        # identical, so nothing here changes when real hardware arrives.
        self.enclave = Enclave(
            MockSilicon(),
            launch_measurement=config.enclave_image_hash,
        )
        self.mcp = MCPServer()

    # -- Bittensor integration (Milestone 4) ----------------------------------

    def register(self) -> None:
        """Register the neuron on the subnet and post TAO collateral."""
        raise NotImplementedError("Subnet registration lands in Milestone 4.")

    def serve_forever(self) -> None:
        """Serve MCP tool calls until stopped."""
        raise NotImplementedError("Serving loop lands in Milestone 4.")

    # -- working today --------------------------------------------------------

    def unlock(self, resource: str) -> None:
        """Attest to the Key Broker and receive the credential for `resource`."""
        if self.broker is None:
            raise RuntimeError("no Key Broker configured")
        self.enclave.unlock(self.broker, resource)
        logger.info("credential released for %s", resource)

    def handle_call(self, request_id: str, tool: str, arguments: dict, nonce: str) -> AttestedResponse:
        """Execute a tool call inside the enclave and attest the result."""
        return self.enclave.run_attested(
            request_id, nonce, lambda: self.mcp.call_tool(tool, arguments)
        )

    def handle_challenge(self, nonce: str) -> AttestedResponse:
        """Answer a validator challenge with a fresh attestation."""
        return self.enclave.attest_result("challenge", {"chip_id": self.enclave.chip_id}, nonce)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    miner = SentinelMiner(MinerConfig.from_env())
    logger.info("Sentinel miner initialised. chip=%s", miner.enclave.chip_id)
    logger.info("Bittensor registration is not implemented yet — see ROADMAP.md.")
    # Demonstrates the parts that do work:
    logger.info("self-challenge ok: %s", bool(miner.handle_challenge(new_nonce()).attestation.signature))


if __name__ == "__main__":
    main()

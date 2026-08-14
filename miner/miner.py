"""
Sentinel miner neuron — entrypoint (skeleton).

A Sentinel miner runs an MCP server inside an AMD SEV-SNP enclave, serves
attested tool calls, and responds to validator attestation challenges. This
module is the neuron entrypoint: it registers on the subnet, boots the
in-enclave services, and serves requests.

Status: skeleton. Interfaces are defined; enclave integration and MCP tool
handlers land during the testnet phase.
"""

from __future__ import annotations

import logging

from .config import MinerConfig
from .attestation import AttestationAgent
from .mcp_server import MCPServer

logger = logging.getLogger("sentinel.miner")


class SentinelMiner:
    """Top-level miner neuron.

    Lifecycle:
        1. Register on the subnet (hotkey + collateral).
        2. Launch the SEV-SNP enclave and generate the ephemeral TEE keypair.
        3. Fetch customer credentials from the Key Broker Service (KBS),
           released only after the enclave passes attestation.
        4. Serve MCP tool calls, binding each response to a fresh attestation.
        5. Respond to validator challenges every ~360 blocks.
    """

    def __init__(self, config: MinerConfig) -> None:
        self.config = config
        self.attestation = AttestationAgent(config)
        self.mcp = MCPServer(config)

    def register(self) -> None:
        """Register the neuron on the subnet and post TAO collateral."""
        raise NotImplementedError("Subnet registration lands in testnet phase.")

    def bootstrap_enclave(self) -> None:
        """Launch the SEV-SNP guest VM and generate the ephemeral TEE keypair.

        The launch measurement produced here is what the KBS verifies before
        releasing credentials. A tampered image changes the measurement and is
        refused credentials.
        """
        raise NotImplementedError("Enclave bootstrap lands in testnet phase.")

    def fetch_credentials(self) -> None:
        """Attest to the KBS and receive the credential bundle sealed to PK_TEE."""
        raise NotImplementedError("KBS handshake lands in testnet phase.")

    def serve(self) -> None:
        """Serve MCP tool calls until stopped."""
        raise NotImplementedError("Serving loop lands in testnet phase.")

    def handle_challenge(self, nonce: bytes) -> dict:
        """Produce a fresh attestation bound to a validator-supplied nonce."""
        return self.attestation.generate_report(nonce)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config = MinerConfig.from_env()
    miner = SentinelMiner(config)
    logger.info("Sentinel miner initialised (skeleton).")
    # miner.register(); miner.bootstrap_enclave(); miner.fetch_credentials(); miner.serve()


if __name__ == "__main__":
    main()

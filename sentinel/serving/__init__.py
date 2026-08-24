"""HTTP serving layer for the miner neuron.

Bittensor v11 removed the axon/dendrite/synapse stack: a neuron publishes its
`ip:port` on-chain with the ServeAxon intent and serves over its own HTTP layer,
authenticating callers with hotkey signatures (`bittensor.http_auth`).

That suits Sentinel — MCP is already an HTTP protocol, so it is served natively
rather than wrapped in someone else's message types.
"""

from .handler import MinerHandler, Request, Response

__all__ = ["MinerHandler", "Request", "Response"]

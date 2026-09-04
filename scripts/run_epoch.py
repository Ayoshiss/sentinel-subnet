"""
Milestone 5, one full subnet epoch against a live chain.

Run:  python scripts/run_epoch.py --netuid 2

Brings up miners, publishes their endpoints on-chain, then runs a validator
round that discovers them from the metagraph, challenges each with a fresh
nonce, verifies attestations, scores them, and submits weights through Yuma's
timelock-encrypted commit path.

This is the whole mechanism end to end. Nothing is stubbed except the silicon:
the chain is real, the registrations are real, the weights land on-chain and are
hidden until the reveal round.

Local note: the chain rejects loopback axons, so a miner publishes a LAN-style
address and the validator maps it back to 127.0.0.1 with --host-override. On a
real deployment the published address is the one that actually answers.

SIMULATION. MockSilicon signs in software rather than in an AMD-certified
processor, this proves the protocol, not the hardware root of trust.
"""

import argparse
import asyncio
import logging
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import bittensor as bt

from sentinel.attestation import MockSilicon, sha384
from sentinel.chain import discover_miners, has_validator_permit, publish_axon
from sentinel.database import MockDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.serving import MinerHandler
from sentinel.serving.server import make_server
from sentinel.validating import MinerEvaluator, MinerTarget
from sentinel.validating.weights import set_weights

APPROVED = sha384(b"sentinel-miner-image-v0.1")
DSN = "postgres://app_user:hunter2@customer-db.internal:5432/production"
TRUE_ROWS = [[1, "ada@example.com", "enterprise"],
             [2, "grace@example.com", "pro"],
             [3, "alan@example.com", "free"]]


def start_miner(label: str, port: int, hotkey_ss58: str, measurement: str = APPROVED, rows=None):
    """A miner enclave serving attested MCP on `port`."""
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=measurement))
    broker.store_secret("customer-db", DSN)
    enclave = Enclave(MockSilicon(), launch_measurement=measurement)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    creds = enclave.unlock(broker, "customer-db")

    mcp = MCPServer()
    mcp.register(PostgresQueryTool(MockDatabase(creds, columns=["id", "email", "plan"],
                                                rows=rows or TRUE_ROWS)))
    handler = MinerHandler(enclave, mcp, hotkey_ss58=hotkey_ss58)
    server = make_server(handler, "0.0.0.0", port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"  [{label}] serving on :{server.server_port}  chip={enclave.chip_id}")
    return server


async def main(netuid: int, wallet_name: str, advertise_ip: str, host_override: str | None, endpoint: str):
    print("Sentinel: full epoch")
    print("=" * 78)

    miner_w = bt.Wallet(name=wallet_name, hotkey="miner")
    val_w = bt.Wallet(name=wallet_name, hotkey="validator")
    miner_hot = miner_w.hotkey.ss58_address
    val_hot = val_w.hotkey.ss58_address

    server = start_miner("miner", 8091, miner_hot)

    async with bt.Subtensor(endpoint) as st:
        mg = await bt.metagraph.fetch(st, netuid)
        print(f"\n  netuid {netuid}  block={mg.block}  tempo={mg.tempo}  uids={mg.num_uids}")

        if not await has_validator_permit(st, netuid, val_hot):
            print("\n  validator has no permit: it cannot set weights.")
            print("  Stake to the validator hotkey and wait for an epoch boundary.")
            server.shutdown()
            return

        # 1. publish the miner's endpoint on-chain
        print("\n[1] publishing miner endpoint")
        print("-" * 78)
        miner_signer = bt.resolve_signer(miner_w, "hotkey")
        try:
            r = await publish_axon(st, miner_signer, netuid, advertise_ip, 8091)
            print(f"  ServeAxon success={r.success}  {str(r.message)[:70]}")
        except ValueError as exc:
            print(f"  {exc}")
        await st.wait_for_block()

        # 2. discover from the metagraph: the validator is told nothing directly
        print("\n[2] validator discovers miners from the metagraph")
        print("-" * 78)
        miners = await discover_miners(st, netuid, exclude_hotkeys=[val_hot])
        if not miners:
            print("  no miners advertising an endpoint yet (ServeAxon is rate-limited)")
            server.shutdown()
            return
        for m in miners:
            print(f"  uid {m.uid}  {m.base_url}  {m.hotkey_ss58[:14]}…")

        # 3. challenge, verify, score
        print("\n[3] challenging each miner")
        print("-" * 78)
        targets = [
            MinerTarget(
                uid=m.uid,
                hotkey_ss58=m.hotkey_ss58,
                base_url=_rewrite_host(m.base_url, host_override),
            )
            for m in miners
        ]
        evaluator = MinerEvaluator(val_w.hotkey, APPROVED, latency_ceiling_ms=60_000)
        outcomes = evaluator.evaluate_round(targets)

        print(f"  {'uid':<5}{'attest':>7}{'latency':>9}{'correct':>9}{'cache':>7}{'nonce':>7}{'WEIGHT':>9}")
        for o in outcomes:
            s = o.scores
            print(f"  {o.uid:<5}{s.attestation:>7.2f}{s.latency:>9.2f}{s.correctness:>9.2f}"
                  f"{s.cache_hygiene:>7.2f}{s.nonce_discipline:>7.2f}{o.weight:>9.4f}")
            if o.error:
                print(f"        error: {o.error}")

        # 4. weights on-chain, via the encrypted commit path
        print("\n[4] submitting weights to Yuma")
        print("-" * 78)
        weights = MinerEvaluator.weights_from(outcomes)
        for uid, w in sorted(weights.items()):
            print(f"  uid {uid}  {w:.4f}  {'█' * int(w * 40)}")

        val_signer = bt.resolve_signer(val_w, "hotkey")
        result = await set_weights(st, val_signer, netuid, weights)
        print(f"\n  success={result.success}  {str(result.message)[:60]}")
        if result.data.get("reveal_round"):
            print(f"  timelock reveal_round={result.data['reveal_round']} "
                  "(hidden until then, so no other validator can copy it)")

    print("\n" + "=" * 78)
    print("Discovered on-chain, challenged over signed HTTP, verified by attestation,")
    print("scored, and weighted, without trusting any miner at any point.")
    server.shutdown()


def _rewrite_host(url: str, override: str | None) -> str:
    """Point a published LAN address back at localhost for a single-box run."""
    if not override:
        return url
    scheme, _, rest = url.partition("://")
    _, _, port = rest.partition(":")
    return f"{scheme}://{override}:{port}" if port else f"{scheme}://{override}"


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--netuid", type=int, default=2)
    p.add_argument("--wallet", default="sentinel-dev")
    p.add_argument("--endpoint", default="ws://127.0.0.1:9944")
    p.add_argument("--advertise-ip", default="192.168.1.50",
                   help="address published on-chain (loopback is rejected)")
    p.add_argument("--host-override", default="127.0.0.1",
                   help="rewrite discovered hosts for a single-box run")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    asyncio.run(main(args.netuid, args.wallet, args.advertise_ip, args.host_override, args.endpoint))

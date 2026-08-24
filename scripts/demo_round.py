"""
Milestone 4 — a full validator round against a mixed field of miners.

Run:  python scripts/demo_round.py

Four miners come up on real sockets. One is honest. The others are each
dishonest in a different way, and the validator has to catch them using nothing
but signed HTTP and attestation — no privileged access, no trust in any miner,
and no knowledge of what the correct database rows actually are.

    miner 0   honest
    miner 1   running modified code
    miner 2   fabricating rows
    miner 3   replaying a stale attestation

The last one is the most interesting result. The validator cannot know the right
answer to a query against a customer's private database — that is the entire
point of the product. So it never tries. It asks every miner the same question
and lets the majority expose the liar, while attestation stops the fakes from
voting on what the majority is.

SIMULATION. MockSilicon signs in software rather than in an AMD-certified
processor. This proves the protocol, not the hardware root of trust.
"""

import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bittensor.sp_core import Keypair

from sentinel.attestation import MockSilicon, sha384
from sentinel.database import MockDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.serving import MinerHandler
from sentinel.serving.server import make_server
from sentinel.validating import MinerEvaluator, MinerTarget

APPROVED = sha384(b"sentinel-miner-image-v0.1")
DSN = "postgres://app_user:hunter2@customer-db.internal:5432/production"
TRUE_ROWS = [[1, "ada@example.com", "enterprise"],
             [2, "grace@example.com", "pro"],
             [3, "alan@example.com", "free"]]
FAKE_ROWS = [[1, "attacker@evil.com", "enterprise"]]


def build_miner(label, measurement=APPROVED, rows=None, replay=False):
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=measurement))
    broker.store_secret("customer-db", DSN)
    enclave = Enclave(MockSilicon(), launch_measurement=measurement)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    creds = enclave.unlock(broker, "customer-db")

    mcp = MCPServer()
    mcp.register(PostgresQueryTool(MockDatabase(
        creds, columns=["id", "email", "plan"], rows=rows or TRUE_ROWS)))

    hotkey = Keypair.create_from_uri(f"//Miner-{label}")
    handler = MinerHandler(enclave, mcp, hotkey_ss58=hotkey.ss58_address)

    if replay:
        stale, original = "00" * 32, handler.enclave.run_attested
        handler.enclave.run_attested = lambda rid, nonce, work: original(rid, stale, work)

    server = make_server(handler, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hotkey, f"http://127.0.0.1:{server.server_port}"


def run():
    print("Sentinel — validator round")
    print("(simulation: software Ed25519 stands in for an AMD SEV-SNP VCEK)")
    print("=" * 78)

    field = [
        ("honest",            dict()),
        ("modified-code",     dict(measurement=sha384(b"backdoored-image"))),
        ("fabricates-rows",   dict(rows=FAKE_ROWS)),
        ("replays-old-proof", dict(replay=True)),
    ]
    miners = [build_miner(name, **kw) for name, kw in field]

    print("\nminers on the subnet")
    print("-" * 78)
    for uid, ((name, _), (_, hk, url)) in enumerate(zip(field, miners)):
        print(f"  uid {uid}  {name:18} {url}")

    validator = Keypair.create_from_uri("//Validator")
    evaluator = MinerEvaluator(validator, APPROVED, latency_ceiling_ms=60_000)
    targets = [MinerTarget(uid=i, hotkey_ss58=hk.ss58_address, base_url=url)
               for i, (_, hk, url) in enumerate(miners)]

    print("\nvalidator challenges each miner with a fresh nonce…")
    outcomes = evaluator.evaluate_round(targets)

    print("\nscores")
    print("-" * 78)
    print(f"  {'uid':<4} {'miner':<18} {'attest':>7} {'latency':>8} {'correct':>8} "
          f"{'cache':>6} {'nonce':>6} {'WEIGHT':>8}")
    for (name, _), o in zip(field, outcomes):
        s = o.scores
        print(f"  {o.uid:<4} {name:<18} {s.attestation:>7.2f} {s.latency:>8.2f} "
              f"{s.correctness:>8.2f} {s.cache_hygiene:>6.2f} {s.nonce_discipline:>6.2f} "
              f"{o.weight:>8.4f}")

    print("\nwhy each miner lost marks")
    print("-" * 78)
    for (name, _), o in zip(field, outcomes):
        if o.error:
            print(f"  uid {o.uid} {name:18} {o.error}")
        elif o.scores.correctness == 0.0:
            print(f"  uid {o.uid} {name:18} disagreed with the majority on the same query")
        else:
            print(f"  uid {o.uid} {name:18} clean")

    weights = MinerEvaluator.weights_from(outcomes)
    print("\nyuma weights submitted (normalised)")
    print("-" * 78)
    for uid, w in sorted(weights.items()):
        bar = "█" * int(w * 50)
        print(f"  uid {uid}  {w:>6.4f}  {bar}")

    print("\n" + "=" * 78)
    print("The validator never saw the customer's data, and never trusted a miner.")
    print("Attestation caught the modified code; consensus caught the liar.")

    for server, _, _ in miners:
        server.shutdown()


if __name__ == "__main__":
    run()

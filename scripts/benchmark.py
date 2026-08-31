"""
Measure how well the validator separates honest miners from dishonest ones.

Run:  python scripts/benchmark.py --rounds 100

A single passing round proves the mechanism exists. It says nothing about how
often it works, whether honest miners get wrongly rejected, or how the two
populations separate over time. This runs the real validator against a real
field of miners over many rounds and reports rates rather than anecdotes.

The field is one honest miner plus six ways of being dishonest, each isolated so
a failure names a specific defence:

    backdoored      runs a modified image        -> launch measurement
    replay          reuses a stale attestation   -> nonce binding
    fabricator      invents database rows        -> consensus correctness
    cacheable       lets replies be cached       -> cache hygiene
    slow            answers, but late            -> latency scoring
    unreachable     does not answer at all       -> liveness
    malformed       returns a corrupt report     -> signature verification

Every round uses fresh nonces, so nothing is reused between rounds and a miner
cannot benefit from having answered before.

Attestation here is `MockSilicon`. That does not weaken these numbers: what is
being measured is whether the protocol catches each attack, which is a property
of the challenge-verify-score design rather than of the silicon underneath it.
Real hardware changes where the signature comes from, not whether a mismatched
measurement is caught.
"""

import argparse
import json
import pathlib
import statistics
import sys
import threading
import time
from collections import defaultdict

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
DSN = "postgres://app:secret@customer-db:5432/prod"
TRUE_ROWS = [[1, "ada@example.com", "enterprise"],
             [2, "grace@example.com", "pro"],
             [3, "alan@example.com", "free"]]
FAKE_ROWS = [[1, "attacker@evil.com", "enterprise"]]

#: Two honest miners, so consensus has a majority that is not a single voice.
FIELD = [
    ("honest-a",    {}),
    ("honest-b",    {}),
    ("backdoored",  {"measurement": sha384(b"backdoored-image")}),
    ("replay",      {"replay": True}),
    ("fabricator",  {"rows": FAKE_ROWS}),
    ("cacheable",   {"cacheable": True}),
    ("slow",        {"delay_ms": 900}),
    ("malformed",   {"malformed": True}),
    ("unreachable", {"unreachable": True}),
]

#: Miners that are slow but honest. They should score *lower*, not be rejected —
#: counting them as undetected attacks would misstate the detection rate, and
#: rejecting them would be a false positive.
DEGRADED = {"slow"}

#: What each dishonest miner should fail on. A miner failing for the *wrong*
#: reason is a bug, not a success, so the harness checks the reason too.
EXPECTED = {
    "backdoored":  "attestation",
    "replay":      "attestation",       # a stale nonce fails verification outright
    "fabricator":  "correctness",
    "cacheable":   "cache_hygiene",
    "malformed":   "attestation",
    "unreachable": "unreachable",
}


def build_miner(name, measurement=APPROVED, rows=None, replay=False,
                cacheable=False, delay_ms=0, malformed=False, unreachable=False):
    """One miner, dishonest in at most one specific way."""
    if unreachable:
        hotkey = Keypair.create_from_uri(f"//Miner-{name}")
        return None, hotkey, "http://127.0.0.1:1"

    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=measurement))
    broker.store_secret("customer-db", DSN)
    enclave = Enclave(MockSilicon(), launch_measurement=measurement)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    creds = enclave.unlock(broker, "customer-db")

    mcp = MCPServer()
    mcp.register(PostgresQueryTool(MockDatabase(
        creds, columns=["id", "email", "plan"], rows=rows or TRUE_ROWS)))

    hotkey = Keypair.create_from_uri(f"//Miner-{name}")
    handler = MinerHandler(enclave, mcp, hotkey_ss58=hotkey.ss58_address)

    if replay:
        stale, original = "00" * 32, handler.enclave.run_attested
        handler.enclave.run_attested = lambda rid, n, work: original(rid, stale, work)

    if malformed:
        original_attest = handler.enclave.run_attested

        def corrupt(rid, nonce, work):
            out = original_attest(rid, nonce, work)
            out.attestation.signature = "00" * 64
            return out

        handler.enclave.run_attested = corrupt

    if delay_ms:
        original_handle = handler.handle
        handler.handle = lambda req: (time.sleep(delay_ms / 1000), original_handle(req))[1]

    server = make_server(handler, "127.0.0.1", 0)
    if cacheable:
        server.RequestHandlerClass = _cacheable(server.RequestHandlerClass)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hotkey, f"http://127.0.0.1:{server.server_port}"


def _cacheable(cls):
    class _C(cls):
        def _write(self, status, payload):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "public, max-age=300")
            self.end_headers()
            self.wfile.write(payload)
    return _C


def classify(name, outcome):
    """Which defence caught this miner, if any."""
    if outcome.error and "unreachable" in outcome.error:
        return "unreachable"
    if not outcome.verified:
        return "attestation"
    if outcome.scores.correctness == 0.0:
        return "correctness"
    if outcome.scores.cache_hygiene == 0.0:
        return "cache_hygiene"
    return None


def run(rounds: int, latency_ceiling_ms: float):
    print(f"Sentinel — validator benchmark, {rounds} rounds")
    print("=" * 78)

    miners = [(name, *build_miner(name, **kw)) for name, kw in FIELD]
    validator = Keypair.create_from_uri("//Validator")
    evaluator = MinerEvaluator(validator, APPROVED, latency_ceiling_ms=latency_ceiling_ms)
    targets = [MinerTarget(uid=i, hotkey_ss58=hk.ss58_address, base_url=url)
               for i, (_, _, hk, url) in enumerate(miners)]
    names = {i: name for i, (name, *_) in enumerate(miners)}

    weights = defaultdict(list)
    latencies = defaultdict(list)
    caught = defaultdict(int)
    caught_correctly = defaultdict(int)
    verified = defaultdict(int)

    started = time.time()
    try:
        for r in range(rounds):
            for o in evaluator.evaluate_round(targets):
                name = names[o.uid]
                weights[name].append(o.weight)
                if o.latency_ms:
                    latencies[name].append(o.latency_ms)
                if o.verified:
                    verified[name] += 1
                reason = classify(name, o)
                if reason:
                    caught[name] += 1
                    if EXPECTED.get(name) == reason:
                        caught_correctly[name] += 1
            if (r + 1) % 10 == 0:
                print(f"  {r + 1}/{rounds} rounds")
    finally:
        for _, server, _, _ in miners:
            if server:
                server.shutdown()

    elapsed = time.time() - started
    return build_report(rounds, elapsed, names, weights, latencies,
                        caught, caught_correctly, verified, latency_ceiling_ms)


def build_report(rounds, elapsed, names, weights, latencies, caught,
                 caught_correctly, verified, latency_ceiling_ms):
    honest = [n for n in weights if n.startswith("honest")]
    degraded = [n for n in weights if n in DEGRADED]
    dishonest = [n for n in weights if not n.startswith("honest") and n not in DEGRADED]

    rows = []
    for name in weights:
        w = weights[name]
        lat = latencies.get(name, [])
        rows.append({
            "miner": name,
            "expected_defence": EXPECTED.get(name, "none (honest)"),
            "rounds": len(w),
            "mean_weight": round(statistics.mean(w), 4),
            "max_weight": round(max(w), 4),
            "verified_pct": round(100 * verified[name] / len(w), 1),
            "caught_pct": round(100 * caught[name] / len(w), 1),
            "caught_by_expected_pct": round(100 * caught_correctly[name] / len(w), 1),
            "latency_p50_ms": round(statistics.median(lat), 1) if lat else None,
            "latency_p95_ms": round(sorted(lat)[int(len(lat) * 0.95)], 1) if len(lat) > 20 else None,
        })

    honest_weights = [w for n in honest for w in weights[n]]
    dishonest_weights = [w for n in dishonest for w in weights[n]]
    degraded_weights = [w for n in degraded for w in weights[n]]
    # A false rejection is an honest or merely-slow miner scored to zero.
    false_rejects = sum(1 for n in honest + degraded for w in weights[n] if w == 0.0)

    return {
        "rounds": rounds,
        "miners": len(weights),
        "elapsed_seconds": round(elapsed, 1),
        "latency_ceiling_ms": latency_ceiling_ms,
        "per_miner": rows,
        "summary": {
            "honest_mean_weight": round(statistics.mean(honest_weights), 4),
            "dishonest_mean_weight": round(statistics.mean(dishonest_weights), 4),
            "honest_min_weight": round(min(honest_weights), 4),
            "dishonest_max_weight": round(max(dishonest_weights), 4),
            "degraded_mean_weight": round(statistics.mean(degraded_weights), 4) if degraded_weights else None,
            "false_rejections": false_rejects,
            "false_rejection_rate_pct": round(
                100 * false_rejects / len(honest_weights + degraded_weights), 3),
            "detection_rate_pct": round(
                100 * sum(caught[n] for n in dishonest)
                / sum(len(weights[n]) for n in dishonest), 2),
            "correct_attribution_pct": round(
                100 * sum(caught_correctly[n] for n in dishonest)
                / sum(len(weights[n]) for n in dishonest), 2),
        },
    }


def render(report):
    s = report["summary"]
    print(f"\nresults over {report['rounds']} rounds ({report['elapsed_seconds']}s)")
    print("-" * 78)
    print(f"  {'miner':<13}{'defence':<16}{'verified':>9}{'caught':>8}{'by cause':>10}"
          f"{'mean w':>9}{'p50 ms':>8}")
    for r in report["per_miner"]:
        p50 = f"{r['latency_p50_ms']:.0f}" if r["latency_p50_ms"] else "-"
        print(f"  {r['miner']:<13}{r['expected_defence']:<16}"
              f"{r['verified_pct']:>8.1f}%{r['caught_pct']:>7.1f}%"
              f"{r['caught_by_expected_pct']:>9.1f}%{r['mean_weight']:>9.4f}{p50:>8}")

    print(f"\n  detection rate            {s['detection_rate_pct']}%")
    print(f"  caught by expected cause  {s['correct_attribution_pct']}%")
    print(f"  false rejections          {s['false_rejections']}  ({s['false_rejection_rate_pct']}%)"
          "   [honest or merely slow, scored to zero]")
    print(f"  honest mean weight        {s['honest_mean_weight']}")
    print(f"  degraded (slow) mean      {s['degraded_mean_weight']}")
    print(f"  dishonest mean weight     {s['dishonest_mean_weight']}")
    print(f"  worst honest / best dishonest  {s['honest_min_weight']} / {s['dishonest_max_weight']}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=50)
    p.add_argument("--latency-ceiling-ms", type=float, default=2000.0)
    p.add_argument("--out", default="results.json")
    args = p.parse_args()

    report = run(args.rounds, args.latency_ceiling_ms)
    render(report)
    pathlib.Path(args.out).write_text(json.dumps(report, indent=2))
    print(f"\n  written to {args.out}")

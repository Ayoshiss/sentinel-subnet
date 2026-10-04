#!/usr/bin/env python3
"""
Run the key broker as a separate daemon, on the customer's own machine.

Why this script exists at all: until now `run_miner.py` built the broker and the
enclave in one process, so the party holding the database password and the party
being checked were the same program. The verification logic ran, and proved
nothing. A customer reading the code could reasonably ask what stops the miner
operator from printing the secret, and the honest answer was "nothing, it is
their own variable".

With this, the two live on different machines:

    customer's host                     untrusted host
    ---------------                     --------------
    run_broker.py   <-- attestation --  run_miner.py --broker-url ...
      holds the DSN  -- credential -->    holds no secret until it attests

The operator of the miner host never possesses the DSN. They receive it, into a
process whose launch measurement the broker checked, and only while that
measurement stays approved. Rotate the secret here and the old image cannot get
the new one.

What this does NOT fix. The credential crosses the wire in the clear inside TLS,
and TLS does not protect it from the miner's operator: the client does not pin
this broker's certificate, so it validates against the guest's trust store, which
that operator owns, and the launch measurement does not cover the root filesystem
where that store lives. So an operator who is willing to intercept their own
guest can still read the credential. Threat register T22 and T23.

What the split does buy is that taking the credential is no longer passive. It
requires deliberate interception rather than reading a local variable, and that
leaves evidence. Terminate TLS on this box, keep proxies you do not control out of
the path, and treat --insecure as loopback-only, but do not tell a customer the
credential is unobtainable, because it is not yet.

Usage, mock chip, both ends on one laptop:

    python scripts/run_broker.py \
      --scope analytics="postgresql://ro@localhost/analytics" \
      --measurement ccdc5cf0... --allow-mock-chip <CHIP_ID>=<PUBKEY_HEX> \
      --bind 127.0.0.1 --port 8100

Real silicon: the miner sends a full SEV-SNP report and no chip needs trusting
by hand, because AMD's certificate chain does that job. Pass --product and the
broker verifies VCEK -> ASK -> ARK itself.
"""

from __future__ import annotations

import argparse
import logging
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.kbs import KeyBroker, ReleasePolicy
from sentinel.kbs_remote import BrokerHandler, verifier_factory
from sentinel.serving.server import make_server

logger = logging.getLogger("sentinel.broker")

DEFAULT_RESOURCE = "database"


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Sentinel key broker (customer side)")
    p.add_argument(
        "--scope", action="append", default=[], metavar="NAME=DSN",
        help="a named secret, one per database role. Repeatable. The miner asks "
             "for these by name and never learns another scope's DSN.",
    )
    p.add_argument(
        "--measurement", action="append", default=[], metavar="HEX", required=True,
        help="an approved launch measurement. Repeatable: the same image "
             "measures differently on different hosts, so one value describes "
             "one machine, not a fleet.",
    )
    p.add_argument(
        "--min-tcb", type=int, default=None,
        help="minimum SNP TCB. Defaults to the product floor from AMD's "
             "bulletins; only lower it knowingly.",
    )
    p.add_argument("--product", default="Milan", help="AMD product line for certificate checks")
    p.add_argument(
        "--allow-mock-chip", action="append", default=[], metavar="CHIPID=PUBKEY",
        help="trust a MockSilicon chip. Development only: a mock chip proves "
             "the plumbing works, not that any hardware is involved.",
    )
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8100)
    return p.parse_args(argv)


def parse_scopes(entries: list[str]) -> dict[str, str]:
    if not entries:
        raise SystemExit("--scope NAME=DSN is required; a broker with no secret has no job")
    scopes: dict[str, str] = {}
    for entry in entries:
        name, sep, dsn = entry.partition("=")
        name, dsn = name.strip(), dsn.strip()
        if not sep or not name or not dsn:
            raise SystemExit(f"--scope must be NAME=DSN, got {entry!r}")
        if name in scopes:
            raise SystemExit(f"--scope {name!r} given twice")
        scopes[name] = dsn
    return scopes


def build_broker(args) -> KeyBroker:
    policy_kwargs = {"approved_measurement": list(args.measurement)}
    if args.min_tcb is not None:
        policy_kwargs["min_tcb"] = args.min_tcb

    if args.allow_mock_chip:
        broker = KeyBroker(policy=ReleasePolicy(**policy_kwargs))
        for entry in args.allow_mock_chip:
            chip_id, sep, pubkey = entry.partition("=")
            if not sep or not chip_id.strip() or not pubkey.strip():
                raise SystemExit(f"--allow-mock-chip must be CHIPID=PUBKEY, got {entry!r}")
            broker.trust_chip(chip_id.strip(), pubkey.strip())
        logger.warning(
            "MOCK CHIPS TRUSTED: %d. Reports from these are Ed25519, not signed "
            "by any processor. Never point this at a real database.",
            len(args.allow_mock_chip),
        )
    else:
        # No verifier is built up front, because the certificates that anchor
        # verification arrive with each report. The customer runs this box and
        # never touches the miner's host, which is the entire point of the split.
        broker = KeyBroker(
            policy=ReleasePolicy(**policy_kwargs),
            sevsnp_factory=verifier_factory(
                args.product,
                list(args.measurement),
                {"min_snp": args.min_tcb} if args.min_tcb is not None else None,
            ),
        )

    for name, dsn in parse_scopes(args.scope).items():
        broker.store_secret(name, dsn)
        logger.info("holding a secret for scope %r", name)
    return broker


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args(argv)
    broker = build_broker(args)
    server = make_server(BrokerHandler(broker), args.bind, args.port)
    logger.info(
        "broker listening on http://%s:%d, %d approved measurement(s)",
        args.bind, server.server_port, len(args.measurement),
    )
    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        logger.warning(
            "bound to %s: put TLS in front of this. The released credential "
            "travels in the response body.", args.bind,
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

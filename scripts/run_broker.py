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

How the credential travels. The broker never sends it in the clear: it seals
it to a key the enclave made and bound into its attestation, and signs what it
sends with this broker's identity key (--identity-key). A relay the operator puts
in the path sees ciphertext, with or without TLS. If the operator points the
miner at a broker of their own instead, every answer names that broker, so a
customer checks the fingerprint this script logs at start against the answers.

That holds on Intel TDX, where the whole image is measured. On AMD SEV-SNP only
the firmware is measured, so an operator can change the running code and read
the credential after it is opened. Threat register T20, T22 and T23. Never tell
a customer the credential is unobtainable.

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
    p.add_argument(
        "--tdx-mrtd", action="append", default=[], metavar="HEX",
        help="approved TD firmware. With --tdx-db-cert, accept Intel TDX "
             "enclaves; --measurement then also lists approved UKI digests.",
    )
    p.add_argument("--tdx-db-cert", metavar="DER",
                   help="Secure Boot db certificate of the approved TDX image")
    p.add_argument(
        "--identity-key", default="~/.config/sentinel/broker-identity.pem", metavar="PATH",
        help="this broker's signing key, created on first run. Its fingerprint is "
             "what you check miners' answers against, so keep it stable and private.",
    )
    p.add_argument(
        "--tls-ca", metavar="DIR",
        help="issue each approved enclave a TLS certificate from the CA in DIR "
             "(ca.key, ca.crt; created on first run), and refuse enclaves that "
             "do not ask for one. Give your agent DIR/ca.crt to trust.",
    )
    p.add_argument("--tls-name", action="append", default=[], metavar="HOST",
                   help="host name or IP the agent uses to reach the miner; repeatable")
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

    if args.tdx_mrtd or args.tdx_db_cert:
        if not (args.tdx_mrtd and args.tdx_db_cert):
            raise SystemExit("TDX needs both --tdx-mrtd and --tdx-db-cert")
        from sentinel.tdx import TdxPolicy, TdxVerifier

        broker.tdx = TdxVerifier(TdxPolicy(
            approved_uki=list(args.measurement),
            approved_mrtd=list(args.tdx_mrtd),
            db_cert=pathlib.Path(args.tdx_db_cert).read_bytes(),
        ))

    from sentinel.sealing import BrokerIdentity

    key_path = pathlib.Path(args.identity_key).expanduser()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    broker.identity = BrokerIdentity.load_or_create(key_path)
    logger.info(
        "broker fingerprint %s: every answer from a miner using this broker names it",
        broker.identity.fingerprint,
    )

    if args.tls_ca or args.tls_name:
        if not (args.tls_ca and args.tls_name):
            raise SystemExit("TLS needs both --tls-ca and --tls-name")
        from sentinel.tls import TlsIssuer, make_ca

        ca_dir = pathlib.Path(args.tls_ca).expanduser()
        if not (ca_dir / "ca.key").exists():
            make_ca(ca_dir)
            logger.info("created a TLS CA in %s", ca_dir)
        broker.tls_issuer = TlsIssuer.from_dir(ca_dir, args.tls_name)
        logger.info(
            "issuing enclave TLS certificates for %s; agents trust %s",
            ", ".join(args.tls_name), ca_dir / "ca.crt",
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
            "bound to %s: put TLS in front of this. The credential itself is "
            "sealed to the enclave, but TLS still hides who asks for what.", args.bind,
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

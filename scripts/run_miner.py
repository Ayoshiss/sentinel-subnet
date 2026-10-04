"""
A Sentinel miner, long running, on real silicon.

    python scripts/run_miner.py --netuid 554 --wallet sentinel \
        --advertise-ip 34.x.x.x --measurement <hex>

Everything before this ran a miner and a validator together for the length of
one demonstration. This runs only the miner, and it runs until something stops
it, which is the difference between showing the mechanism works and taking a
position on a live subnet.

The chip is the point. On a SEV-SNP guest the enclave signs with the processor
and the broker checks AMD's certificate chain; the credential is released to a
measured image, not to whoever is holding the wallet. `--allow-mock` exists so
the wiring can be exercised on a laptop, and says so loudly, because a mock
miner on a real subnet is claiming a guarantee it is not providing.

First boot on a new image, before there is a measurement to pin:

    python scripts/run_miner.py --print-measurement

That prints what the firmware measured and exits. Pin the value, redeploy with
it, and from then on the miner refuses to serve if the image is not the one
that was approved.
"""

import argparse
import logging
import pathlib
import signal
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.database import Credentials, PostgresDatabase, SqliteDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import CredentialReleaseError, KeyBroker, ReleasePolicy
from sentinel.kbs_remote import BrokerUnreachable, RemoteBroker
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.serving import MinerHandler
from sentinel.serving.server import make_server

logger = logging.getLogger("sentinel.miner")

RESOURCE = "customer-db"

#: The allowlist is refreshed from chain rather than read per request, so an
#: RPC outage cannot stop the miner answering. A stale list is a far better
#: failure than a miner that goes dark for something it did not cause.
ALLOWLIST_REFRESH_SECONDS = 600

#: ServeAxon is rate limited per neuron (50 blocks by default), and a published
#: endpoint does not expire. Re-publishing hourly is enough to recover from a
#: chain-side loss without ever tripping the limit.
REPUBLISH_SECONDS = 3600


# --- silicon ------------------------------------------------------------------

def open_silicon(allow_mock: bool, mock_seed: str | None = None):
    """The real chip if there is one, a mock only when explicitly permitted."""
    from sentinel.sevsnp import guest

    if guest.available():
        silicon = guest.SevSnpSilicon()
        logger.info("SEV-SNP guest detected, chip %s", silicon.chip_id)
        return silicon, True

    if not allow_mock:
        raise SystemExit(
            "no /dev/sev-guest: this host is not a SEV-SNP guest.\n"
            "Run on a confidential VM, or pass --allow-mock to exercise the "
            "wiring without the hardware guarantee."
        )

    from sentinel.attestation import MockSilicon

    logger.warning(
        "MOCK SILICON: signing in software. Attestations from this miner prove "
        "the protocol works and nothing about the hardware."
    )
    if mock_seed:
        # A mock chip normally has a fresh key per process, which makes it
        # impossible to register with a separate broker ahead of time. A seed
        # fixes the identity so the split can be rehearsed on one laptop. Real
        # silicon needs none of this: AMD's chain identifies the chip.
        try:
            seed = bytes.fromhex(mock_seed)
        except ValueError as exc:
            raise SystemExit(f"--mock-chip-seed must be hex: {exc}") from exc
        if len(seed) != 32:
            raise SystemExit(f"--mock-chip-seed must be 32 bytes, got {len(seed)}")
        silicon = MockSilicon.from_seed(seed, chip_id=f"MOCK-EPYC-{seed[:4].hex()}")
        logger.warning("mock chip identity is derived from a seed and is not secret")
        return silicon, False
    return MockSilicon(), False


def build_verifier(silicon, product: str, measurement_hex: str):
    """A verifier anchored to AMD's pinned root, using the host's certificates.

    The certificates arrive from the host alongside the report, which sounds
    like trusting the attacker to supply the evidence. It is not: the chain is
    checked against a root whose SPKI hash is compiled in, so a substituted root
    fails before any field of the report is read. The benefit is that
    verification never depends on AMD's KDS being reachable, which it was not on
    the day this path was written.
    """
    from cryptography import x509

    from sentinel.sevsnp import SevSnpPolicy, SevSnpVerifier
    from sentinel.sevsnp.certs import CertChain
    from sentinel.sevsnp.verifier import min_tcb_for

    certs = silicon.certificates
    missing = {"VCEK", "ASK", "ARK"} - set(certs)
    if missing:
        raise SystemExit(
            f"host provisioned no {', '.join(sorted(missing))}; cannot verify "
            "offline. This is a host configuration problem, not a guest one."
        )

    chain = CertChain(
        product=product,
        ask=x509.load_der_x509_certificate(certs["ASK"]),
        ark=x509.load_der_x509_certificate(certs["ARK"]),
    )
    verifier = SevSnpVerifier(
        product,
        # The floor matters more here than at the validator. A validator scoring
        # a miner zero stops it being paid; the broker refusing means firmware
        # with known holes never receives the credential at all.
        SevSnpPolicy(
            approved_measurement=bytes.fromhex(measurement_hex),
            **min_tcb_for(product),
        ),
        chain=chain,
        offline=True,
    )
    return verifier, certs


# --- assembly -----------------------------------------------------------------

def parse_scopes(args) -> dict[str, str]:
    """Named scopes from --scope, or the single --dsn as the default scope.

    Each scope should be a database role with SELECT on the views that scope is
    allowed, and nothing else. The enclave then cannot read beyond it even if
    everything above it fails: a stolen key, a bug in the handler, or an
    operator who modified the miner after boot, which the launch measurement
    does not cover.
    """
    remote = bool(getattr(args, "broker_url", None))
    if not args.scope:
        # Remote: ask for the default scope by name. The DSN behind it is the
        # broker's business, and this process is not entitled to know it before
        # it has attested.
        return {RESOURCE: "" if remote else args.dsn}

    scopes: dict[str, str] = {}
    for entry in args.scope:
        name, sep, dsn = entry.partition("=")
        name, dsn = name.strip(), dsn.strip()
        if remote:
            if sep:
                raise SystemExit(
                    f"--scope {entry!r} carries a DSN, but --broker-url was given. "
                    "With a remote broker this host must not hold the secret; "
                    "pass the scope name alone and store the DSN on the broker."
                )
            if not name:
                raise SystemExit("--scope must be a NAME")
            dsn = ""
        elif not sep or not name or not dsn:
            raise SystemExit(f"--scope must be NAME=DSN, got {entry!r}")
        if "." in name:
            # Tools are named "<scope>.query" and scope is matched on the part
            # before the first dot, so a dot in the name would silently widen
            # what a restricted key can reach.
            raise SystemExit(f"scope name {name!r} must not contain a dot")
        if name in scopes:
            raise SystemExit(f"--scope {name!r} given twice")
        scopes[name] = dsn
    return scopes


def resolve_allowlist(args) -> set[str] | None:
    """Who may call this miner. None means anyone, and says so loudly.

    Fails closed: if validators cannot be read from chain and no hotkey was
    named explicitly, the miner refuses to start rather than serving the
    network at large. Opening it has to be a decision someone typed.
    """
    if args.allow_any:
        logger.warning(
            "AUTHORISATION DISABLED: any registered hotkey may query this "
            "enclave, including arbitrary reads of whatever database it is "
            "attached to. Never run this against real data."
        )
        return None

    allowed = set(args.allow_hotkey)
    if not args.no_allow_validators:
        import asyncio

        import bittensor as bt

        from sentinel.chain import validator_hotkeys

        async def _fetch() -> set[str]:
            async with bt.Subtensor(args.endpoint) as st:
                return await validator_hotkeys(st, args.netuid)

        try:
            found = asyncio.run(_fetch())
            logger.info("allowlist: %d validators on netuid %d", len(found), args.netuid)
            allowed |= found
        except Exception as exc:  # noqa: BLE001 - chain trouble must be explicit
            if not allowed:
                raise SystemExit(
                    f"could not read validators from chain ({exc}) and no "
                    "--allow-hotkey was given. Refusing to start rather than "
                    "serving every hotkey on the network. Pass --allow-hotkey, "
                    "or --allow-any if this enclave holds nothing real."
                ) from exc
            logger.warning("could not refresh validators (%s); using %d named hotkeys",
                           exc, len(allowed))

    logger.info("allowlist: %d hotkeys may call this miner", len(allowed))
    return allowed


async def refresh_allowlist(args, allowed: set[str], stop: threading.Event) -> None:
    """Keep the allowlist current. On failure the previous set stands."""
    import bittensor as bt

    from sentinel.chain import validator_hotkeys

    explicit = set(args.allow_hotkey)
    while not stop.is_set():
        stop.wait(ALLOWLIST_REFRESH_SECONDS)
        if stop.is_set():
            break
        try:
            async with bt.Subtensor(args.endpoint) as st:
                found = await validator_hotkeys(st, args.netuid)
            # Mutated in place: the handler holds this same object.
            allowed.clear()
            allowed.update(explicit | found)
            logger.info("allowlist refreshed, %d hotkeys", len(allowed))
        except Exception as exc:  # noqa: BLE001 - a stale list beats no miner
            logger.warning("allowlist refresh failed, keeping previous: %s", exc)


def build_miner(args, hotkey_ss58: str):
    """Wire chip to broker to enclave to MCP, and return a server ready to run."""
    silicon, real = open_silicon(args.allow_mock, getattr(args, "mock_chip_seed", None))

    remote = bool(getattr(args, "broker_url", None))
    if real:
        actual = silicon.measurement
        if actual != args.measurement:
            # The whole point. An image that is not the approved one does not
            # get to serve while quietly claiming it is.
            raise SystemExit(
                f"launch measurement mismatch.\n"
                f"  approved: {args.measurement}\n"
                f"  running:  {actual}\n"
                "Either this is not the approved image, or the image changed "
                "and the pinned value needs updating deliberately."
            )
    scopes = parse_scopes(args)

    if remote:
        # The custody separation the whole design rests on. The broker is a
        # different process on a different machine, owned by whoever owns the
        # data, and this process holds no DSN until it has proved what it booted.
        # Nothing here verifies the report: the party that checks the proof is
        # the party that holds the secret, which is the only arrangement that
        # means anything.
        broker = RemoteBroker(args.broker_url, insecure=getattr(args, "broker_insecure", False))
        logger.info(
            "brokering to %s; this host stores no credential for %s",
            broker.url, ", ".join(sorted(scopes)),
        )
        if not real:
            # The mock chip has to be registered with the broker by hand, so
            # print what the operator needs to hand over. Both values are public.
            logger.info(
                "register this mock chip with the broker: --allow-mock-chip %s=%s",
                silicon.chip_id, silicon.public_verifier().public_key_hex,
            )
    else:
        if real:
            verifier, certs = build_verifier(silicon, args.product, args.measurement)
            broker = KeyBroker(
                policy=ReleasePolicy(approved_measurement=args.measurement),
                sevsnp=verifier,
                sevsnp_certs=certs,
            )
        else:
            broker = KeyBroker(policy=ReleasePolicy(approved_measurement=args.measurement))
            broker.trust_chip(silicon.chip_id, silicon.public_verifier().public_key_hex)
        for name, dsn in scopes.items():
            broker.store_secret(name, dsn)
        logger.warning(
            "no --broker-url: this miner releases credentials to itself, so the "
            "operator of this host holds the secret. Development only."
        )

    enclave = Enclave(silicon, launch_measurement=args.measurement)
    mcp = MCPServer()
    for name in scopes:
        # One attestation per scope, not one for all of them. The report is
        # bound to the scope being requested, so a proof obtained for the
        # analytics credential cannot be replayed to unlock payments.
        try:
            credentials = enclave.unlock(broker, name)
        except BrokerUnreachable as exc:
            # Nobody has refused anything; the broker is simply not answering.
            # Said separately because the fix is a network one, and an operator
            # told "refused" would go and rebuild an image that is fine.
            raise SystemExit(
                f"{exc}\nThe broker has not refused this enclave, it did not "
                "answer. Check the URL, the firewall and that run_broker.py is up."
            ) from exc
        except CredentialReleaseError as exc:
            raise SystemExit(
                f"the broker refused to release {name!r}: {exc}\n"
                "This is the mechanism working. Either this image is not the one "
                "the broker approved, the chip is not trusted, or the firmware is "
                "below its floor. Nothing is served without the credential."
            ) from exc
        logger.info("credential released to the enclave for %r", name)
        mcp.register(PostgresQueryTool(
            open_database(credentials, args.seed),
            scope=None if name == RESOURCE else name,
        ))

    allowed = resolve_allowlist(args)

    api_keys = None
    if args.api_keys:
        from sentinel.serving.apikeys import ApiKeyStore

        api_keys = ApiKeyStore.from_file(args.api_keys)
        logger.info("%d API key(s) loaded; non-Bittensor callers may connect", len(api_keys))

    handler = MinerHandler(
        enclave, mcp, hotkey_ss58=hotkey_ss58,
        allowed_hotkeys=allowed, api_keys=api_keys,
    )
    return make_server(handler, args.bind, args.port), enclave, allowed


DEFAULT_SEED = pathlib.Path(__file__).parent / "miner-seed.sql"


def open_database(credentials: Credentials, seed: pathlib.Path | None):
    """Postgres when the credential points at one, SQLite otherwise.

    The DSN read here is the one the broker released, not the one the operator
    typed. They are the same string today because this miner brokers to itself,
    but reading the released copy is what keeps that an implementation detail
    rather than a dependency.
    """
    dsn = credentials.dsn
    if dsn.startswith(("postgres://", "postgresql://")):
        return PostgresDatabase(credentials)

    # sqlite:///relative.db and sqlite:////absolute.db, as SQLAlchemy spells it.
    rest = dsn.removeprefix("sqlite://")
    path = rest[1:] if rest.startswith("//") else rest.lstrip("/")
    # Unseeded, the validator's probe hits a missing table and the miner scores
    # zero for correctness however good its attestation was.
    seed_sql = seed.read_text() if seed else None
    return SqliteDatabase(credentials, path=path or ":memory:", seed_sql=seed_sql)


# --- chain --------------------------------------------------------------------

async def publish_forever(args, wallet, stop: threading.Event) -> None:
    """Keep the endpoint published, re-asserting it periodically."""
    import bittensor as bt

    from sentinel.chain import publish_axon

    signer = bt.resolve_signer(wallet, "hotkey")
    while not stop.is_set():
        try:
            async with bt.Subtensor(args.endpoint) as st:
                result = await publish_axon(
                    st, signer, args.netuid, args.advertise_ip, args.port
                )
                logger.info("ServeAxon success=%s", getattr(result, "success", result))
        except Exception as exc:  # noqa: BLE001 - a miner must survive chain trouble
            # Serving continues regardless. An unreachable chain costs discovery
            # by new validators; it does not stop answering the ones that
            # already know the endpoint.
            logger.warning("could not publish endpoint: %s", exc)
        stop.wait(REPUBLISH_SECONDS)


# --- entry point --------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--netuid", type=int, default=554)
    p.add_argument("--wallet", default="sentinel")
    p.add_argument("--hotkey", default="miner")
    # Serve as this identity while holding none of its key material. The miner
    # never signs with the hotkey: it verifies callers' signatures, and its own
    # answers are signed by the chip. The private hotkey is needed only to
    # publish the endpoint, which is one chain call that belongs on a machine
    # you control rather than on a cloud VM someone else operates.
    p.add_argument("--hotkey-ss58",
                   help="serve under this address; publish the axon elsewhere")
    # netuid 554 lives on testnet, not finney. Defaulting to finney would
    # publish the endpoint on a chain the subnet is not on, and the failure
    # is quiet: the miner serves happily and no validator ever finds it.
    p.add_argument("--endpoint", default="test")
    p.add_argument("--advertise-ip", help="the address validators can reach")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8091)
    p.add_argument("--product", default="Milan", help="EPYC product line")
    p.add_argument("--measurement", help="the approved launch measurement, hex")
    p.add_argument("--dsn", default="sqlite:///",
                   help="one database, released as the 'customer-db' scope")
    # Scopes are the answer to "how does the AI know which data is sensitive".
    # It does not: the credential released into the enclave is a role that can
    # only reach approved views, so data out of scope is unreachable rather
    # than merely unrequested. Each scope is its own credential, unlocked by
    # its own attestation, and exposed as its own tool.
    p.add_argument(
        "--broker-url", metavar="URL",
        help="release credentials from a broker at this URL instead of from a "
             "broker in this process. With it, the operator of this host never "
             "holds a DSN: --scope takes bare NAMEs and the secrets live on the "
             "customer's machine. Without it the miner brokers to itself, which "
             "is fine for development and proves nothing about custody.",
    )
    p.add_argument(
        "--broker-insecure", action="store_true",
        help="permit an http:// broker URL. The released credential travels in "
             "that response body, so this is for loopback testing only.",
    )
    p.add_argument("--scope", action="append", default=[], metavar="NAME=DSN",
                   help="a named scope and the restricted credential for it; repeat")
    p.add_argument("--seed", type=pathlib.Path, default=DEFAULT_SEED,
                   help="SQL to seed a fresh SQLite database with")
    p.add_argument("--no-seed", action="store_true",
                   help="do not seed; the database already has the data")
    p.add_argument("--mock-chip-seed", metavar="HEX32",
                   help="derive the mock chip's key from this 32-byte seed so a "
                        "separate broker can trust it in advance. Development only.")
    p.add_argument("--allow-mock", action="store_true",
                   help="run without SEV-SNP, for wiring tests only")
    p.add_argument("--print-measurement", action="store_true",
                   help="print this VM's launch measurement and exit")
    # Who may call. Authentication proves a caller holds a hotkey; it says
    # nothing about whether they should be querying this enclave. Left open,
    # any hotkey on the network can run arbitrary reads against whatever
    # database the enclave is attached to.
    p.add_argument("--allow-hotkey", action="append", default=[], metavar="SS58",
                   help="permit this hotkey to call; repeat for more")
    p.add_argument("--no-allow-validators", action="store_true",
                   help="do not auto-permit validators holding a permit on this netuid")
    # Callers who are not on Bittensor. A customer running this over their own
    # database has no hotkey, so without this the self-hosted deployment cannot
    # be used by the people it exists for.
    p.add_argument("--api-keys", metavar="FILE",
                   help="JSON of label -> sha256 digest; see scripts/make_api_key.py")
    p.add_argument("--allow-any", action="store_true",
                   help="permit ANY registered hotkey; demos only, never with real data")
    p.add_argument("--no-chain", action="store_true",
                   help="serve without publishing on-chain")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    )

    if args.print_measurement:
        from sentinel.sevsnp import guest

        if not guest.available():
            print("not a SEV-SNP guest: there is no launch measurement to read.")
            return 1
        print(guest.SevSnpSilicon().measurement)
        return 0

    if not args.measurement:
        p.error("--measurement is required (or --print-measurement to read it)")
    if args.no_seed:
        args.seed = None
    if not args.no_chain and not args.advertise_ip:
        p.error("--advertise-ip is required (or --no-chain to serve without publishing)")

    hotkey_ss58 = args.hotkey_ss58 or "mock-hotkey"
    wallet = None
    if args.hotkey_ss58 and not args.no_chain:
        p.error("--hotkey-ss58 serves without a wallet, so it needs --no-chain; "
                "publish the axon from wherever the hotkey lives")
    if not args.no_chain:
        import bittensor as bt

        wallet = bt.Wallet(name=args.wallet, hotkey=args.hotkey)
        hotkey_ss58 = wallet.hotkey.ss58_address

    server, enclave, allowed = build_miner(args, hotkey_ss58)
    stop = threading.Event()

    threading.Thread(target=server.serve_forever, daemon=True).start()
    logger.info(
        "miner serving on %s:%d  chip=%s  hotkey=%s",
        args.bind, server.server_port, enclave.chip_id, hotkey_ss58,
    )

    if not args.no_chain:
        import asyncio

        threading.Thread(
            target=lambda: asyncio.run(publish_forever(args, wallet, stop)),
            daemon=True,
        ).start()

    # Validators come and go, so the allowlist has to as well. Runs even with
    # --no-chain: not publishing an endpoint is a different decision from not
    # reading who is allowed to call.
    if allowed is not None and not args.no_allow_validators:
        import asyncio

        threading.Thread(
            target=lambda: asyncio.run(refresh_allowlist(args, allowed, stop)),
            daemon=True,
        ).start()

    # Shut down on a signal rather than on an exception, so a restart is a
    # deliberate event and systemd can tell the difference between the two.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    try:
        while not stop.is_set():
            time.sleep(1)
    finally:
        logger.info("shutting down")
        stop.set()
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

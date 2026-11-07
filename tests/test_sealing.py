"""
Sealed credential release, and the attacks it exists to stop.

The operator chooses where the miner's broker URL points. These tests put a
relay of the operator's in that path, on real sockets, and check what it can and
cannot do: read the credential (no), swap the key it is sealed to (no), or stand
up a broker of its own (yes, but every answer then names that broker, and a
customer checking for theirs refuses it).
"""

import json
import os
import stat
import threading
import urllib.request

import pytest
from bittensor.sp_core import Keypair

from sentinel.attestation import MockSilicon, sha384
from sentinel.database import MockDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import CredentialReleaseError, KeyBroker, ReleasePolicy, release_binding
from sentinel.kbs_remote import BrokerHandler, RemoteBroker
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.sealing import BrokerIdentity, EnclaveKey, SealedCredential, SealingError
from sentinel.serving import MinerHandler
from sentinel.serving.handler import Request, Response
from sentinel.serving.server import make_server
from sentinel.validating import MinerEvaluator, MinerTarget

APPROVED = sha384(b"sentinel-miner-image-v0.1")
RESOURCE = "customer-db"
DSN = "postgres://app:s3cret-pw@customer-db:5432/prod"
ROWS = [[1, "ada@example.com", "enterprise"]]


def customer_broker(dsn: str = DSN) -> KeyBroker:
    """A real broker: default policy, so nothing is released in the clear."""
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, dsn)
    return broker


def trusted_enclave(broker: KeyBroker) -> Enclave:
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    return enclave


def serve(handler):
    server = make_server(handler, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


class Relay:
    """The operator's relay: forwards everything, records everything.

    `rewrite` lets it change a request on the way through, which is how it
    tries to substitute a key of its own.
    """

    def __init__(self, upstream: str, rewrite=None) -> None:
        self.upstream = upstream
        self.rewrite = rewrite
        self.seen: list[bytes] = []

    def handle(self, request: Request) -> Response:
        body = request.body
        if self.rewrite and request.path == "/release":
            body = self.rewrite(json.loads(body))
        self.seen.append(body)
        forwarded = urllib.request.Request(
            self.upstream + request.path, data=body if request.method == "POST" else None,
            headers={"Content-Type": "application/json"}, method=request.method,
        )
        try:
            with urllib.request.urlopen(forwarded, timeout=10) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        self.seen.append(raw)
        return Response(status, json.loads(raw))


# -- the broker refuses to release in the clear ---------------------------------

def test_a_real_broker_never_releases_in_the_clear():
    broker = customer_broker()
    enclave = trusted_enclave(broker)
    nonce = broker.challenge()
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))
    with pytest.raises(CredentialReleaseError, match="does not release credentials in the clear"):
        broker.release(RESOURCE, report)


def test_the_enclave_unlocks_and_learns_which_broker_it_used():
    broker = customer_broker()
    enclave = trusted_enclave(broker)
    assert enclave.unlock(broker, RESOURCE).dsn == DSN
    assert enclave.broker_fingerprint == broker.identity.fingerprint


# -- the operator's relay --------------------------------------------------------

@pytest.fixture
def real_broker():
    broker = customer_broker()
    server, url = serve(BrokerHandler(broker))
    yield broker, url
    server.shutdown()


def test_a_relay_on_the_wire_sees_only_ciphertext(real_broker):
    """Plain HTTP, every byte recorded by the operator, and still no credential."""
    broker, url = real_broker
    relay = Relay(url)
    relay_server, relay_url = serve(relay)
    try:
        enclave = trusted_enclave(broker)
        assert enclave.unlock(RemoteBroker(relay_url, insecure=True), RESOURCE).dsn == DSN
    finally:
        relay_server.shutdown()
    wire = b"".join(relay.seen)
    assert b'"sealed"' in wire, "the release did pass through the relay"
    assert DSN.encode() not in wire
    assert b"s3cret-pw" not in wire


def test_a_relay_cannot_swap_in_a_key_of_its_own(real_broker):
    """The attestation binds the enclave's key, so a substituted key no longer
    matches it and the broker refuses."""
    broker, url = real_broker
    mine = EnclaveKey()

    def substitute(payload):
        payload["enclave_key"] = mine.public_hex
        return json.dumps(payload).encode()

    relay = Relay(url, rewrite=substitute)
    relay_server, relay_url = serve(relay)
    try:
        enclave = trusted_enclave(broker)
        # Worded per chip type: a binding mismatch for the mock, a different
        # resource or key for real hardware. Refused either way.
        with pytest.raises(CredentialReleaseError, match="binding mismatch|different resource or key"):
            enclave.unlock(RemoteBroker(relay_url, insecure=True), RESOURCE)
    finally:
        relay_server.shutdown()
    assert DSN.encode() not in b"".join(relay.seen)


# -- the sealed release itself ----------------------------------------------------

def sealed_pair():
    identity, key = BrokerIdentity(), EnclaveKey()
    sealed = identity.seal(DSN, enclave_key=key.public_hex, resource=RESOURCE, nonce="n1")
    return identity, key, sealed


def test_a_sealed_release_opens_only_for_its_enclave():
    identity, key, sealed = sealed_pair()
    assert key.open(sealed, resource=RESOURCE, nonce="n1") == (DSN, identity.fingerprint)
    with pytest.raises(SealingError, match="different enclave"):
        EnclaveKey().open(sealed, resource=RESOURCE, nonce="n1")


@pytest.mark.parametrize("field", ["ciphertext", "signature", "ephemeral", "iv", "broker_key"])
def test_any_change_to_a_sealed_release_is_refused(field):
    _, key, sealed = sealed_pair()
    data = sealed.to_dict()
    raw = bytearray(bytes.fromhex(data[field]))
    raw[0] ^= 1
    data[field] = raw.hex()
    with pytest.raises(SealingError):
        key.open(SealedCredential.from_dict(data), resource=RESOURCE, nonce="n1")


def test_a_sealed_release_answers_one_request():
    _, key, sealed = sealed_pair()
    with pytest.raises(SealingError, match="different request"):
        key.open(sealed, resource=RESOURCE, nonce="another")
    with pytest.raises(SealingError, match="different request"):
        key.open(sealed, resource="payments-db", nonce="n1")


def test_the_broker_identity_is_stable_and_private_on_disk(tmp_path):
    path = tmp_path / "broker.key"
    first = BrokerIdentity.load_or_create(path)
    assert BrokerIdentity.load_or_create(path).fingerprint == first.fingerprint
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_one_enclave_takes_credentials_from_one_broker():
    first, second = customer_broker(), customer_broker()
    enclave = trusted_enclave(first)
    second.trust_chip(enclave.chip_id, enclave.public_key_hex)
    enclave.unlock(first, RESOURCE)
    with pytest.raises(CredentialReleaseError, match="one enclave takes credentials from one broker"):
        enclave.unlock(second, RESOURCE)


# -- answers name their broker, and a customer checks it --------------------------

def miner_using(broker: KeyBroker, rewrite_broker: str | None = None):
    enclave = trusted_enclave(broker)
    credentials = enclave.unlock(broker, RESOURCE)
    mcp = MCPServer()
    mcp.register(PostgresQueryTool(MockDatabase(credentials, columns=["id", "email", "plan"], rows=ROWS)))
    hotkey = Keypair.create_from_uri(f"//Miner{id(enclave)}")
    handler = MinerHandler(enclave, mcp, hotkey_ss58=hotkey.ss58_address)
    if rewrite_broker is not None:
        # A miner that claims a different broker than the one it used.
        original = handler.handle

        def claim(request):
            response = original(request)
            if "broker" in response.payload:
                response.payload["broker"] = rewrite_broker
            return response
        handler.handle = claim
    server, url = serve(handler)
    return server, MinerTarget(uid=0, hotkey_ss58=hotkey.ss58_address, base_url=url)


def round_against(target, **kwargs):
    evaluator = MinerEvaluator(Keypair.create_from_uri("//Validator"), APPROVED,
                               latency_ceiling_ms=60_000, **kwargs)
    (outcome,) = evaluator.evaluate_round([target])
    return outcome


def test_a_customer_accepts_answers_from_their_own_broker():
    broker = customer_broker()
    server, target = miner_using(broker)
    try:
        outcome = round_against(target, expected_broker=broker.identity.fingerprint)
    finally:
        server.shutdown()
    assert outcome.verified, outcome.error


def test_an_operators_own_broker_is_visible_and_refused():
    """The operator points the miner at a broker they run, with data they chose.
    It works, and every answer says so."""
    customers, operators = customer_broker(), customer_broker(dsn="postgres://fake@operator/db")
    server, target = miner_using(operators)
    try:
        subnet = round_against(target)
        customer = round_against(target, expected_broker=customers.identity.fingerprint)
    finally:
        server.shutdown()
    assert subnet.verified, "the subnet only needs the claim to be honest"
    assert not customer.verified
    assert "not ours" in customer.error


def test_a_miner_cannot_claim_a_broker_it_did_not_use():
    """The broker is bound into the attestation, so rewriting the claim breaks it."""
    customers, operators = customer_broker(), customer_broker(dsn="postgres://fake@operator/db")
    server, target = miner_using(operators, rewrite_broker=customers.identity.fingerprint)
    try:
        outcome = round_against(target, expected_broker=customers.identity.fingerprint)
    finally:
        server.shutdown()
    assert not outcome.verified
    assert "binding" in outcome.error

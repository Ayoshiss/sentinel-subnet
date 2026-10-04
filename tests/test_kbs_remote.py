"""
The split: broker in one process, enclave in another, a socket in between.

These tests exist because the in-process version of this flow could pass every
test in test_kbs.py while proving nothing about custody. A broker the miner
constructs itself is a broker the miner's operator can read. The point here is
that `Enclave.unlock` works unchanged against a broker it can only reach over
HTTP, and that the failures stay distinguishable: refused is not the same event
as unreachable, and an operator needs to know which one they are looking at.
"""

import pathlib
import threading

import pytest

from sentinel.attestation import MockSilicon, sha384
from sentinel.enclave import Enclave
from sentinel.kbs import CredentialReleaseError, KeyBroker, ReleasePolicy
from sentinel.kbs_remote import BrokerHandler, BrokerUnreachable, RemoteBroker
from sentinel.serving.server import make_server

APPROVED = sha384(b"sentinel-miner-image-v0.1")
OTHER = sha384(b"a-modified-image")
DSN = "postgres://user:secret@customer-db:5432/app"
RESOURCE = "customer-db"


@pytest.fixture
def running_broker():
    """A broker on a real socket, torn down afterwards.

    Port 0 so tests never collide with a miner or another test run.
    """
    brokers: list[KeyBroker] = []

    def start(broker: KeyBroker) -> RemoteBroker:
        server = make_server(BrokerHandler(broker), "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        brokers.append(broker)
        return RemoteBroker(f"http://127.0.0.1:{server.server_port}", insecure=True)

    servers: list = []
    yield start
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def approved_broker(measurement: str = APPROVED) -> KeyBroker:
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=measurement))
    broker.store_secret(RESOURCE, DSN)
    return broker


# --- the thing that was never true before -------------------------------------

def test_enclave_unlocks_across_a_socket(running_broker):
    """The credential crosses a process boundary, and `Enclave` is unmodified."""
    broker = approved_broker()
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)

    remote = running_broker(broker)
    credentials = enclave.unlock(remote, RESOURCE)

    assert credentials.dsn == DSN
    assert credentials.resource == RESOURCE


def test_miner_process_holds_no_secret_until_it_attests(running_broker):
    """The enclave has nothing before unlocking, which is the whole claim."""
    broker = approved_broker()
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    remote = running_broker(broker)

    assert enclave.credential_for(RESOURCE) is None
    enclave.unlock(remote, RESOURCE)
    assert enclave.credential_for(RESOURCE).dsn == DSN


# --- refusals survive the wire ------------------------------------------------

def test_wrong_measurement_is_refused_over_http(running_broker):
    """A modified image gets an error, not a degraded credential."""
    broker = approved_broker()
    enclave = Enclave(MockSilicon(), launch_measurement=OTHER)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    remote = running_broker(broker)

    with pytest.raises(CredentialReleaseError) as caught:
        enclave.unlock(remote, RESOURCE)
    assert DSN not in str(caught.value)


def test_untrusted_chip_is_refused_over_http(running_broker):
    broker = approved_broker()
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    remote = running_broker(broker)  # chip never registered

    with pytest.raises(CredentialReleaseError):
        enclave.unlock(remote, RESOURCE)


def test_refusal_reason_reaches_the_operator(running_broker):
    """The broker's reason survives, because debugging a refusal needs it."""
    broker = approved_broker()
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    remote = running_broker(broker)

    with pytest.raises(CredentialReleaseError) as caught:
        enclave.unlock(remote, "a-resource-the-broker-does-not-hold")
    assert "no secret stored" in str(caught.value)


def test_nonce_cannot_be_replayed_across_the_wire(running_broker):
    """One proof, one release. A captured request does not unlock twice."""
    broker = approved_broker()
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    remote = running_broker(broker)

    from sentinel.kbs import release_binding

    nonce = remote.challenge()
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))
    assert remote.release(RESOURCE, report).dsn == DSN
    with pytest.raises(CredentialReleaseError):
        remote.release(RESOURCE, report)


# --- unreachable is its own failure ------------------------------------------

def test_unreachable_broker_is_not_a_refusal():
    """Different diagnosis, different exception.

    A refusal means this image is not trusted and no retry helps. Unreachable
    means nobody has decided anything, and the operator should look at the
    network rather than at their image.
    """
    # Port 1 on loopback: nothing listens there, and connecting fails fast.
    remote = RemoteBroker("http://127.0.0.1:1", insecure=True, timeout=2.0)
    with pytest.raises(BrokerUnreachable):
        remote.challenge()


def test_unreachable_is_still_a_release_error():
    """Callers that catch `CredentialReleaseError` must still fail closed."""
    remote = RemoteBroker("http://127.0.0.1:1", insecure=True, timeout=2.0)
    with pytest.raises(CredentialReleaseError):
        remote.challenge()


# --- the transport is the weak part, so say so loudly ------------------------

def test_plaintext_url_is_refused_by_default():
    """The credential travels in the response body, so http needs a decision."""
    with pytest.raises(ValueError, match="plaintext"):
        RemoteBroker("http://broker.example.com")


def test_https_is_accepted():
    assert RemoteBroker("https://broker.example.com/").url == "https://broker.example.com"


def test_non_http_scheme_is_refused():
    with pytest.raises(ValueError, match="http"):
        RemoteBroker("broker.example.com")


# --- what the remote broker deliberately cannot do ---------------------------

def test_remote_broker_cannot_store_secrets_or_trust_chips():
    """Absent on purpose: those are the customer's decisions on their machine.

    If a miner could call them over the network it could register its own chip
    and deposit its own secret, and the split would be decoration.
    """
    remote = RemoteBroker("https://broker.example.com")
    assert not hasattr(remote, "store_secret")
    assert not hasattr(remote, "trust_chip")


def test_broker_health_reveals_nothing(running_broker):
    """Reachability, not an inventory of what is held."""
    import json
    import urllib.request

    remote = running_broker(approved_broker())
    with urllib.request.urlopen(remote.url + "/health", timeout=5) as response:
        body = json.loads(response.read())
    assert body["role"] == "broker"
    assert RESOURCE not in json.dumps(body)
    assert "secret" not in json.dumps(body).lower()


# --- the attack the split invites --------------------------------------------
#
# Across a network the broker cannot read the miner's host, so the certificates
# come from the miner: the party being judged supplies the evidence. That is
# only safe because AMD's root is pinned on the broker side. These two tests are
# the ones that decide whether the split is real or theatre.

HOST_DIR = pathlib.Path(__file__).parent / "fixtures" / "gcp-host-certs"
needs_host_certs = pytest.mark.skipif(
    not HOST_DIR.exists(), reason="hardware fixtures not present"
)


def test_a_miner_supplied_chain_with_its_own_root_is_refused(running_broker):
    """A forged chain verifies perfectly and must still be refused.

    An operator who wants the credential without running the approved image can
    generate a root, sign an ASK with it, sign a VCEK with that, and sign a
    report claiming whatever measurement the broker wants. Every signature in
    that chain is valid. The only thing that stops it is that the root is not
    AMD's, which is checked against a key pinned on the customer's machine.
    """
    from sentinel.attestation import AttestationAgent
    from sentinel.kbs import release_binding
    from sentinel.kbs_remote import verifier_factory
    from sentinel.sevsnp.testing import FakeSevSnpSilicon, build_cert_chain

    chain, vcek_key, vcek = build_cert_chain("Milan")
    measurement = bytes.fromhex(APPROVED)[:48].ljust(48, b"\x00")
    silicon = FakeSevSnpSilicon(vcek_key, measurement)

    broker = KeyBroker(
        policy=ReleasePolicy(approved_measurement=measurement.hex()),
        sevsnp_factory=verifier_factory("Milan", [measurement.hex()], {"min_snp": 8}),
    )
    broker.store_secret(RESOURCE, DSN)
    remote = running_broker(broker)

    agent = AttestationAgent(silicon, measurement.hex(), 8)
    nonce = remote.challenge()
    report = agent.attest(nonce, release_binding(RESOURCE))
    from cryptography.hazmat.primitives.serialization import Encoding

    certificates = {
        "VCEK": vcek.public_bytes(Encoding.DER),
        "ASK": chain.ask.public_bytes(Encoding.DER),
        "ARK": chain.ark.public_bytes(Encoding.DER),
    }

    with pytest.raises(CredentialReleaseError) as caught:
        remote.release(RESOURCE, report, certificates)
    # The refusal must be about the root, not an incidental parse failure: a
    # test that passed for the wrong reason would hide the hole it exists to
    # guard.
    assert "root" in str(caught.value).lower()
    assert DSN not in str(caught.value)


def test_a_chain_missing_its_root_releases_nothing(running_broker):
    """No ARK, no verdict. Silence is not consent."""
    from sentinel.attestation import AttestationAgent
    from sentinel.kbs import release_binding
    from sentinel.kbs_remote import verifier_factory
    from sentinel.sevsnp.testing import FakeSevSnpSilicon, build_cert_chain

    _chain, vcek_key, _vcek = build_cert_chain("Milan")
    measurement = bytes.fromhex(APPROVED)[:48].ljust(48, b"\x00")
    broker = KeyBroker(
        policy=ReleasePolicy(approved_measurement=measurement.hex()),
        sevsnp_factory=verifier_factory("Milan", [measurement.hex()], {"min_snp": 8}),
    )
    broker.store_secret(RESOURCE, DSN)
    remote = running_broker(broker)

    agent = AttestationAgent(FakeSevSnpSilicon(vcek_key, measurement), measurement.hex(), 8)
    report = agent.attest(remote.challenge(), release_binding(RESOURCE))

    with pytest.raises(CredentialReleaseError) as caught:
        remote.release(RESOURCE, report, {})
    assert "ARK" in str(caught.value) or "VCEK" in str(caught.value)


@needs_host_certs
def test_the_factory_builds_a_verifier_that_trusts_real_amd_certs():
    """The honest path: certificates handed over the wire still reach AMD's root.

    Uses the certificates a real GCP host provisioned. Proves the broker can
    verify an enclave it has no access to, which is what makes it deployable on
    the customer's own machine.
    """
    from cryptography import x509

    from sentinel.kbs_remote import verifier_factory

    certs = {p.stem.upper(): p.read_bytes() for p in HOST_DIR.glob("*.der")}
    if not {"VCEK", "ASK", "ARK"} <= set(certs):
        pytest.skip("host certificate fixtures incomplete")

    build = verifier_factory("Milan", ["00" * 48])
    verifier = build(certs)
    # The chain is the claim under test, not the measurement, so check the
    # anchoring directly: a non-AMD root raises here.
    verifier.cert_chain().verify_self()
    from sentinel.sevsnp.certs import verify_vcek
    verify_vcek(x509.load_der_x509_certificate(certs["VCEK"]), verifier.cert_chain())


def test_a_wrong_url_is_not_reported_as_a_refusal(running_broker):
    """A 404 is a misconfiguration, not a verdict on the image.

    Worth separating because the two send an operator to different places: one
    to their nginx config, the other to rebuild an image that was fine.
    """
    remote = running_broker(approved_broker())
    wrong = RemoteBroker(remote.url + "/not-a-route", insecure=True, timeout=5.0)
    with pytest.raises(BrokerUnreachable, match="404"):
        wrong.challenge()

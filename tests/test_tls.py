"""
TLS that ends inside the enclave (T25).

The key server issues the enclave's certificate only against an attestation
that binds the TLS key, and every answer's proof names the key it was served
under. These tests run real sockets and check that the ways around it fail:

    * a relay that swaps in its own TLS key at release time   -> refused
    * a proxy that terminates TLS with a different key         -> caught
    * a proof naming a TLS key, delivered over plain http      -> caught
    * an agent trusting a CA other than the customer's         -> no connection
"""

import ssl
import threading
import urllib.request

import pytest
from bittensor.sp_core import Keypair
from cryptography import x509

from sentinel.attestation import MockSilicon, sha384
from sentinel.database import MockDatabase
from sentinel.enclave import Enclave
from sentinel.kbs import CredentialReleaseError, KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool
from sentinel.serving import MinerHandler
from sentinel.serving.server import make_server
from sentinel.tls import EnclaveTls, TlsError, TlsIssuer, make_ca, spki_der
from sentinel.validating import MinerEvaluator, MinerTarget

APPROVED = sha384(b"sentinel-miner-image-v0.1")
RESOURCE = "customer-db"
DSN = "postgres://app:secret@customer-db:5432/prod"
ROWS = [[1, "ada@example.com", "enterprise"]]


@pytest.fixture
def ca_dir(tmp_path):
    make_ca(tmp_path / "ca")
    return tmp_path / "ca"


def broker_with_ca(ca_dir, names=("127.0.0.1",)):
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DSN)
    broker.tls_issuer = TlsIssuer.from_dir(ca_dir, list(names))
    return broker


def enclave_for(broker, tls=True):
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED, tls=tls)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    return enclave


# -- issuing -------------------------------------------------------------------

def test_an_attested_enclave_gets_a_certificate_for_its_own_key(ca_dir):
    broker = broker_with_ca(ca_dir, ["miner.internal", "10.0.0.5"])
    enclave = enclave_for(broker)
    enclave.unlock(broker, RESOURCE)

    cert = x509.load_pem_x509_certificate(enclave.tls.certificate_pem.encode())
    assert spki_der(cert.public_key()) == enclave.tls.spki
    ca = x509.load_pem_x509_certificate((ca_dir / "ca.crt").read_bytes())
    cert.verify_directly_issued_by(ca)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["miner.internal"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.5"]


def test_a_host_name_longer_than_a_common_name_allows(ca_dir):
    """GCP internal names run past 64 characters. Found on the first TDX run."""
    name = "sentinel-smoke-miner.us-central1-a.c.example-project-0000-0000-00000.internal"
    broker = broker_with_ca(ca_dir, [name])
    enclave = enclave_for(broker)
    enclave.unlock(broker, RESOURCE)
    cert = x509.load_pem_x509_certificate(enclave.tls.certificate_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [name]


def test_a_broker_with_a_ca_refuses_an_enclave_without_tls(ca_dir):
    broker = broker_with_ca(ca_dir)
    enclave = enclave_for(broker, tls=False)
    with pytest.raises(CredentialReleaseError, match="requires TLS"):
        enclave.unlock(broker, RESOURCE)


def test_a_relay_cannot_swap_in_its_own_tls_key(ca_dir):
    """The attestation binds the enclave's key. Sending another one fails the
    binding, so a relay cannot get a certificate for a key it holds."""
    broker = broker_with_ca(ca_dir)
    enclave = enclave_for(broker)
    relay_key = EnclaveTls()
    original = broker.release

    def relayed(*args, **kwargs):
        kwargs["tls_key"] = relay_key.spki.hex()
        return original(*args, **kwargs)

    broker.release = relayed
    with pytest.raises(CredentialReleaseError):
        enclave.unlock(broker, RESOURCE)


def test_the_enclave_rejects_a_certificate_for_another_key(ca_dir):
    other = EnclaveTls()
    cert = TlsIssuer.from_dir(ca_dir, ["127.0.0.1"]).issue(other.spki.hex())
    with pytest.raises(TlsError, match="different key"):
        EnclaveTls().accept(cert)


def test_make_ca_will_not_overwrite(ca_dir):
    with pytest.raises(TlsError, match="refusing"):
        make_ca(ca_dir)


# -- serving -------------------------------------------------------------------

def tls_miner(broker, *, serve_with=None, plain=False):
    """A running miner. `serve_with` serves under a different TLS key than the
    enclave's, as a terminating proxy would; `plain` serves http."""
    enclave = enclave_for(broker)
    credentials = enclave.unlock(broker, RESOURCE)
    if not enclave.tls.certificate_pem:
        enclave.tls.self_sign()
    mcp = MCPServer()
    mcp.register(PostgresQueryTool(MockDatabase(credentials, columns=["id", "email", "plan"], rows=ROWS)))
    hotkey = Keypair.create_from_uri(f"//Miner{id(enclave)}")
    handler = MinerHandler(enclave, mcp, hotkey_ss58=hotkey.ss58_address)
    context = None if plain else (serve_with or enclave.tls).server_context()
    server = make_server(handler, "127.0.0.1", 0, tls=context)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    scheme = "http" if plain else "https"
    target = MinerTarget(uid=0, hotkey_ss58=hotkey.ss58_address,
                         base_url=f"{scheme}://127.0.0.1:{server.server_port}")
    return server, target, enclave


def check(target, **kwargs):
    evaluator = MinerEvaluator(Keypair.create_from_uri("//Validator"), APPROVED,
                               latency_ceiling_ms=60_000, **kwargs)
    (outcome,) = evaluator.evaluate_round([target])
    return outcome


def test_an_agent_trusting_the_customer_ca_is_verified(ca_dir):
    server, target, _ = tls_miner(broker_with_ca(ca_dir))
    try:
        outcome = check(target, ca_file=str(ca_dir / "ca.crt"), require_tls=True)
    finally:
        server.shutdown()
    assert outcome.verified, outcome.error


def test_without_a_ca_the_key_is_pinned_by_the_proof():
    """No key server CA: the miner self-signs, and the proof is what vouches."""
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DSN)
    server, target, _ = tls_miner(broker)
    try:
        outcome = check(target, require_tls=True)
    finally:
        server.shutdown()
    assert outcome.verified, outcome.error


def test_a_proxy_terminating_tls_with_another_key_is_caught(ca_dir):
    proxy = EnclaveTls()
    proxy.self_sign()
    server, target, _ = tls_miner(broker_with_ca(ca_dir), serve_with=proxy)
    try:
        outcome = check(target)
    finally:
        server.shutdown()
    assert not outcome.verified
    assert "did not end in the enclave" in outcome.error


def test_a_tls_proof_over_plain_http_is_caught(ca_dir):
    server, target, _ = tls_miner(broker_with_ca(ca_dir), plain=True)
    try:
        outcome = check(target)
    finally:
        server.shutdown()
    assert not outcome.verified
    assert "plain http" in outcome.error


def test_a_validator_given_an_http_url_falls_back_to_https(ca_dir):
    """Chain endpoints have no scheme, so validators start with http."""
    server, target, _ = tls_miner(broker_with_ca(ca_dir))
    target = MinerTarget(uid=0, hotkey_ss58=target.hotkey_ss58,
                         base_url=target.base_url.replace("https://", "http://"))
    try:
        outcome = check(target)
    finally:
        server.shutdown()
    assert outcome.verified, outcome.error


def test_an_agent_trusting_another_ca_cannot_connect(ca_dir, tmp_path):
    make_ca(tmp_path / "other")
    server, target, _ = tls_miner(broker_with_ca(ca_dir))
    context = ssl.create_default_context(cafile=str(tmp_path / "other" / "ca.crt"))
    try:
        with pytest.raises(urllib.error.URLError, match="CERTIFICATE_VERIFY_FAILED"):
            urllib.request.urlopen(target.base_url + "/health", context=context, timeout=10)
    finally:
        server.shutdown()


def test_health_names_the_tls_key(ca_dir):
    server, target, enclave = tls_miner(broker_with_ca(ca_dir))
    context = ssl.create_default_context(cafile=str(ca_dir / "ca.crt"))
    try:
        import json
        with urllib.request.urlopen(target.base_url + "/health", context=context, timeout=10) as r:
            assert json.loads(r.read())["tls"] == enclave.tls.fingerprint
    finally:
        server.shutdown()


def test_the_certificate_crosses_the_wire_from_a_remote_key_server(ca_dir):
    """The production shape: the key server on another machine, over a socket."""
    from sentinel.kbs_remote import BrokerHandler, RemoteBroker

    broker = broker_with_ca(ca_dir)
    server = make_server(BrokerHandler(broker), "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        enclave = enclave_for(broker)
        remote = RemoteBroker(f"http://127.0.0.1:{server.server_port}", insecure=True)
        enclave.unlock(remote, RESOURCE)
    finally:
        server.shutdown()
    cert = x509.load_pem_x509_certificate(enclave.tls.certificate_pem.encode())
    assert spki_der(cert.public_key()) == enclave.tls.spki

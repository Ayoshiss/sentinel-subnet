"""Key Broker tests — a credential must be unreachable without valid attestation."""

import time

import pytest

from sentinel.attestation import MockSilicon, sha384
from sentinel.enclave import Enclave
from sentinel.kbs import CredentialReleaseError, KeyBroker, ReleasePolicy

APPROVED = sha384(b"sentinel-miner-image-v0.1")
DSN = "postgres://user:secret@customer-db:5432/app"
RESOURCE = "customer-db"


def make_broker(policy: ReleasePolicy | None = None) -> KeyBroker:
    broker = KeyBroker(policy=policy or ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, DSN)
    return broker


def make_enclave(measurement: str = APPROVED, tcb: int = 7) -> Enclave:
    return Enclave(MockSilicon(), launch_measurement=measurement, tcb_level=tcb)


def trusted(broker: KeyBroker, enclave: Enclave) -> None:
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)


# --- the happy path -----------------------------------------------------------

def test_approved_enclave_receives_credential():
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)
    creds = enclave.unlock(broker, RESOURCE)
    assert creds.dsn == DSN
    assert creds.resource == RESOURCE


# --- the refusals: each is a reason an operator cannot reach the secret --------

def test_tampered_image_gets_nothing():
    """Modified miner code fails the launch measurement, so no credential."""
    broker = make_broker()
    rogue = make_enclave(measurement=sha384(b"backdoored-image"))
    trusted(broker, rogue)  # even a genuine chip cannot save unapproved code
    with pytest.raises(CredentialReleaseError, match="launch measurement"):
        rogue.unlock(broker, RESOURCE)


def test_untrusted_chip_gets_nothing():
    """A chip the broker has never certified is refused before signature checks."""
    broker, enclave = make_broker(), make_enclave()
    # deliberately not registered
    with pytest.raises(CredentialReleaseError, match="not a trusted processor"):
        enclave.unlock(broker, RESOURCE)


def test_impersonated_chip_gets_nothing():
    """Registering a chip ID against someone else's key must not help."""
    broker, enclave = make_broker(), make_enclave()
    broker.trust_chip(enclave.chip_id, MockSilicon().public_key_hex)  # wrong key
    with pytest.raises(CredentialReleaseError, match="signature"):
        enclave.unlock(broker, RESOURCE)


def test_stale_tcb_gets_nothing():
    """Vulnerable firmware is refused even if everything else is right."""
    broker = make_broker()
    old = make_enclave(tcb=5)
    trusted(broker, old)
    with pytest.raises(CredentialReleaseError, match="TCB"):
        old.unlock(broker, RESOURCE)


def test_replayed_attestation_gets_nothing():
    """A spent nonce cannot unlock the secret twice."""
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)

    nonce = broker.challenge()
    from sentinel.kbs import release_binding
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))

    assert broker.release(RESOURCE, report).dsn == DSN  # first use succeeds
    with pytest.raises(CredentialReleaseError, match="nonce"):
        broker.release(RESOURCE, report)  # replay refused


def test_expired_nonce_gets_nothing():
    broker = make_broker(ReleasePolicy(approved_measurement=APPROVED, nonce_ttl_seconds=-1))
    enclave = make_enclave()
    trusted(broker, enclave)
    from sentinel.kbs import release_binding

    nonce = broker.challenge()
    time.sleep(0.01)
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))
    with pytest.raises(CredentialReleaseError, match="nonce"):
        broker.release(RESOURCE, report)


def test_attestation_for_one_resource_cannot_unlock_another():
    """Cross-resource replay: proof for the analytics DB must not open payments."""
    broker, enclave = make_broker(), make_enclave()
    broker.store_secret("payments-db", "postgres://u:p@payments:5432/pay")
    trusted(broker, enclave)

    from sentinel.kbs import release_binding
    nonce = broker.challenge()
    report = enclave.agent.attest(nonce, release_binding(RESOURCE))  # bound to customer-db

    with pytest.raises(CredentialReleaseError, match="response binding"):
        broker.release("payments-db", report)


def test_unknown_resource_is_refused():
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)
    with pytest.raises(CredentialReleaseError, match="no secret stored"):
        enclave.unlock(broker, "does-not-exist")


# --- hygiene ------------------------------------------------------------------

def test_credentials_are_not_exposed_in_repr():
    """A DSN must not leak through logs or tracebacks."""
    broker, enclave = make_broker(), make_enclave()
    trusted(broker, enclave)
    creds = enclave.unlock(broker, RESOURCE)
    assert "secret" not in repr(creds)
    assert "redacted" in repr(creds)


def test_failed_unlock_leaves_no_credential_in_enclave():
    broker = make_broker()
    rogue = make_enclave(measurement=sha384(b"backdoored-image"))
    trusted(broker, rogue)
    with pytest.raises(CredentialReleaseError):
        rogue.unlock(broker, RESOURCE)
    assert rogue.credential_for(RESOURCE) is None

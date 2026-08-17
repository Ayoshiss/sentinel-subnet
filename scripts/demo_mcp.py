"""
Milestone 2 — an agent queries a real database it is never trusted with.

Run:  python scripts/demo_mcp.py

The claim being demonstrated: a miner operator can host the service, run the
hardware, and see every packet, and still never obtain the customer's database
credentials or be able to alter a result undetected.

Four acts:
    1. an approved enclave unlocks the credential and answers a query
    2. the answer is verified by a stranger holding only a public key
    3. a miner that edits the result is caught
    4. a miner running modified code never gets the credential at all

SIMULATION. `MockSilicon` signs in software rather than in an AMD-certified
processor, and `MockDatabase` stands in for the customer's Postgres. This proves
the protocol, not the hardware root of trust.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sentinel.attestation import (
    MockSilicon, VerificationError, bind_response, new_nonce, sha384,
    verify, verifier_from_public_key,
)
from sentinel.database import Credentials, MockDatabase, canonical
from sentinel.enclave import Enclave
from sentinel.kbs import CredentialReleaseError, KeyBroker, ReleasePolicy
from sentinel.mcp import MCPServer
from sentinel.mcp.tools import PostgresQueryTool

APPROVED = sha384(b"sentinel-miner-image-v0.1")
CUSTOMER_DSN = "postgres://app_user:hunter2@customer-db.internal:5432/production"
RESOURCE = "customer-db"
SQL = "SELECT id, email, plan FROM customers ORDER BY id"


def rule(title: str) -> None:
    print(f"\n{title}\n" + "─" * 68)


def run() -> None:
    print("Sentinel — attested database access")
    print("(simulation: software Ed25519 + in-memory database)")
    print("═" * 68)

    # The customer deposits their credential with the broker. It never goes to
    # the miner, and after this point it is not in anyone's hands.
    broker = KeyBroker(policy=ReleasePolicy(approved_measurement=APPROVED))
    broker.store_secret(RESOURCE, CUSTOMER_DSN)
    rule("[customer]  deposits the database credential with the key broker")
    print(f"  resource : {RESOURCE}")
    print(f"  dsn      : {CUSTOMER_DSN[:28]}…  (broker-held, never given to the miner)")

    # A miner boots the approved image inside a confidential VM.
    enclave = Enclave(MockSilicon(), launch_measurement=APPROVED, tcb_level=7)
    broker.trust_chip(enclave.chip_id, enclave.public_key_hex)
    rule("[miner]     boots the approved enclave image")
    print(f"  chip       : {enclave.chip_id}")
    print(f"  measurement: {APPROVED[:32]}…")
    print(f"  public key : {enclave.public_key_hex[:32]}…  (published)")

    # ACT 1 — unlock, then answer.
    rule("[act 1]     enclave attests, broker releases, query runs")
    credentials = enclave.unlock(broker, RESOURCE)
    print(f"  ✓ credential released to attested code  → {credentials!r}")

    server = MCPServer()
    server.register(PostgresQueryTool(MockDatabase(credentials)))
    print(f"  ✓ MCP tools available: {[t['name'] for t in server.list_tools()]}")

    request_id, nonce = "req-42", new_nonce()
    attested = enclave.run_attested(
        request_id, nonce,
        lambda: server.call_tool("postgres.query", {"sql": SQL}),
    )
    print(f"  ✓ query executed: {SQL}")
    for row in attested.result["rows"]:
        print(f"      {row}")
    print(f"  ✓ result bound into attestation (hash {attested.response_hash[:24]}…)")

    # ACT 2 — a stranger verifies, holding only the public key.
    rule("[act 2]     a third party verifies with the public key alone")
    public_only = verifier_from_public_key(enclave.public_key_hex)
    try:
        verify(
            attested.attestation, public_only,
            approved_measurement=APPROVED, expected_nonce=nonce,
            expected_report_data=bind_response(request_id, attested.response_hash),
        )
        print("  VERIFIED — approved code, genuine chip, this exact result")
    except VerificationError as exc:
        print(f"  REJECTED — {exc}")

    # ACT 3 — the miner tampers with the data on the way out.
    rule("[act 3]     miner edits a row after attesting")
    forged = dict(attested.result)
    forged["rows"] = [[1, "attacker@evil.com", "enterprise"]]
    print(f"  claimed: {forged['rows'][0]}")
    try:
        verify(
            attested.attestation, public_only,
            approved_measurement=APPROVED, expected_nonce=nonce,
            expected_report_data=bind_response(request_id, sha384(canonical(forged))),
        )
        print("  (should not happen)")
    except VerificationError as exc:
        print(f"  REJECTED — {exc}")

    # ACT 4 — the strongest property: modified code never gets the secret.
    rule("[act 4]     miner swaps in modified code and asks for the credential")
    rogue = Enclave(MockSilicon(), launch_measurement=sha384(b"backdoored-image"))
    broker.trust_chip(rogue.chip_id, rogue.public_key_hex)  # genuine chip, bad image
    print(f"  chip       : {rogue.chip_id}  (genuine, registered)")
    print(f"  measurement: {sha384(b'backdoored-image')[:32]}…  (not approved)")
    try:
        rogue.unlock(broker, RESOURCE)
        print("  (should not happen)")
    except CredentialReleaseError as exc:
        print(f"  REFUSED — {exc}")
    print(f"  credential held by rogue enclave: {rogue.credential_for(RESOURCE)}")

    print("\n" + "═" * 68)
    print("The operator ran the hardware and never held the credential.")
    print("The agent trusted no one and still proved the answer was genuine.")


if __name__ == "__main__":
    run()

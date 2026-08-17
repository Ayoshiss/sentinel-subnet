# Development

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install pytest -r requirements.txt
```

## Run the tests
```bash
python -m pytest -q
```
Integration tests are skipped unless a database is reachable. To include them:
```bash
docker compose up -d postgres
DATABASE_URL=postgres://tao:tao@localhost:5432/tao python -m pytest -q
```

## Run the attested-query demo
```bash
python scripts/demo.py
```
Shows the end-to-end flow: enclave attestation → independent verification →
tamper detection → impersonation rejection.

`MockSilicon` stands in for a real AMD SEV-SNP chip. It signs with an **Ed25519**
key that never leaves the mock chip, and verification uses only the matching
**public** key — so the demo exhibits genuine public verifiability, the same
trust shape as a VCEK checked against AMD's certificate chain. The `Silicon`
interface is identical to the hardware one, so the real backend drops in without
changing anything upstream.

> **Simulation, not production security.** The key is generated in software by
> the process, not burned into silicon and certified by AMD. It proves the
> protocol, not the hardware root of trust.

## Run the attested database demo
```bash
python scripts/demo_mcp.py
```
The Milestone 2 flow, in four acts: an approved enclave unlocks a credential from
the Key Broker and answers a query; a third party verifies the result holding only
a public key; a miner that edits the result is caught; and a miner running modified
code is refused the credential outright.

That last act is the product claim — the operator runs the hardware and still never
obtains the customer's database password.

## How the pieces fit
| Module | Role |
|---|---|
| `sentinel/attestation.py` | Report generation, signing, verification |
| `sentinel/kbs.py` | Key Broker — releases secrets only to attested code |
| `sentinel/enclave.py` | Confidential execution: unlock → run → attest result |
| `sentinel/mcp/server.py` | MCP tool registry and dispatch |
| `sentinel/mcp/tools/postgres.py` | `postgres.query`, read-only by default |
| `sentinel/database.py` | `Database` seam: `MockDatabase` / `PostgresDatabase` |

Two attestations happen per request, and they prove different things: **unlock**
convinces the broker to release a credential, **respond** lets anyone verify the
result afterwards without having been involved in the unlock.

## Where the real hardware lands
`sentinel/attestation.py` → replace `MockSilicon` with a backend that reads
`/dev/sev-guest` and returns a VCEK-signed report, plus a verifier that walks the
AMD ARK → ASK → VCEK certificate chain. Everything else stays the same.

See [ROADMAP.md](../ROADMAP.md) for the full milestone plan.

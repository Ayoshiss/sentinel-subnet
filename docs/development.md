# Development

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install pytest
```

## Run the tests
```bash
python -m pytest tests/ -q
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

## Where the real hardware lands
`sentinel/attestation.py` → replace `MockSilicon` with a backend that reads
`/dev/sev-guest` and returns a VCEK-signed report, plus a verifier that walks the
AMD ARK → ASK → VCEK certificate chain. Everything else stays the same.

See [ROADMAP.md](../ROADMAP.md) for the full milestone plan.

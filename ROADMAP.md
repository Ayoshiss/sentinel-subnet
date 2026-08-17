# Sentinel — Development Roadmap

The path from scaffolding to a live testnet subnet. Strategy: **build the full
flow with a simulated TEE first, then swap in real AMD SEV-SNP behind the same
interfaces.** This gets a working demo fast and isolates the hardware work.

---

## Milestone 1 — Attestation core  (the moat) ✅ started
The differentiator. Prove that a response came from genuine, unmodified code.

- [x] `sentinel/attestation.py` — report generation, verification, response binding (mock-first)
- [x] Tests for signature validity, launch-measurement match, nonce binding, tamper detection
- [x] `scripts/demo.py` — end-to-end attested query, verifiable independently
- [ ] Swap `MockSilicon` for real `/dev/sev-guest` + AMD VCEK cert chain (needs EPYC hardware — first-hire task)

## Milestone 2 — MCP tool + enclave execution ✅ mostly done
- [x] MCP `postgres.query` handler (`sentinel/mcp/`), read-only by default
- [x] Key Broker Service (`sentinel/kbs.py`) — releases credentials only to an
      attested enclave; chip registry stands in for AMD's cert directory
- [x] `Database` seam: `MockDatabase` for tests/CI, `PostgresDatabase` for real use
- [x] End-to-end: request → enclave unlocks → query → result + attestation (`scripts/demo_mcp.py`)
- [x] Integration test against real Postgres, skipped unless `DATABASE_URL` is set
- [ ] Run the MCP server inside an actual confidential VM (container first, then SEV-SNP)

> Note: the existing `postgres/` directory is only `schema.sql` for the gateway's
> own billing tables (customers, api_keys, usage_events). That is Sentinel's SaaS
> backend, deliberately **not** what a miner queries — the MCP tool connects to a
> *customer's* database using KBS-released credentials.

## Milestone 3 — Gateway + x402 payments
- [ ] Gateway routes agent request to a miner (reuse existing `gateway/`)
- [ ] 402 Payment Required flow; x402 signature verify + settle (testnet/mock first)
- [ ] Zero-cache headers on paid responses

## Milestone 4 — Bittensor neuron integration
- [ ] Miner: register on Bittensor **testnet**, serve requests, respond to challenges
- [ ] Validator: challenge with nonce → verify attestation → score (40/30/20/5/5) → set weights
- [ ] Commit-reveal weights; ActivityCutoff aligned to challenge tempo

## Milestone 5 — Testnet launch
- [ ] Deploy 1 validator + 2–3 miners on testnet
- [ ] Run the challenge/score loop for a full epoch
- [ ] Publish testnet number → flips "Live on Testnet" in the maturity tracker

---

## Immediate next commits
1. ~~Merge Milestone 1 (attestation core + tests + demo)~~ — done
2. ~~CI: GitHub Actions running `pytest` on every push~~ — done
3. ~~`docs/development.md` with run instructions~~ — done
4. ~~Postgres MCP handler + Key Broker~~ — done
5. Containerise the enclave (Dockerfile for the miner image, measured at build)
6. Milestone 3: gateway routes an agent request to a miner, x402 payment flow

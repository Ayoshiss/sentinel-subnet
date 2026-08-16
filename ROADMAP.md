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

## Milestone 2 — MCP tool + enclave execution
- [ ] Wire existing `postgres/` code into an MCP `postgres.query` handler
- [ ] Credential store: fetch from a Key Broker Service (start with local Vault/mock, then Trustee)
- [ ] Run the MCP server inside a confidential VM (simulate with a container first)
- [ ] End-to-end: request → enclave executes query → returns result + attestation

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

## Immediate next commits (this week)
1. Merge Milestone 1 (attestation core + tests + demo) — **done, push it**
2. CI: GitHub Actions running `pytest` on every push (fast credibility win)
3. `docs/development.md` with run instructions
4. Open Milestone 2 issues; start the Postgres MCP handler from existing code

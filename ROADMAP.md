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
- [x] **Real SEV-SNP verification** (`sentinel/sevsnp/`) — report parsing, VCEK →
      ASK → ARK chain validation against AMD's genuine published certificates,
      ECDSA P-384 signature checking, TCB floors and guest-policy checks. Raises
      the same `VerificationError` as the mock path, so the Key Broker and
      validator are unchanged.
- [x] **Report generation** (`sentinel/sevsnp/guest.py`) — the `/dev/sev-guest`
      ioctls, standard and extended, request/response encoding, and
      `SevSnpSilicon` behind the same `Silicon` interface as the mock.
- [x] **Run it on real silicon.** Done 2026-08-31 on an AMD EPYC 7B13. A genuine
      report and AMD's real certificate chain are fixtures in `tests/fixtures/`,
      so the end-to-end verification runs in CI without hardware. Two captures on
      different physical chips gave identical launch measurements.
- [x] **Remove the dependency on AMD's KDS.** The extended report carries the
      host's certificate chain, so validators verify without reaching AMD. Their
      KDS was refusing connections the day this was built, which is the argument
      for it.
- [x] **Pin AMD's root.** The chain was previously anchored to any self-signed
      certificate, so a forged root, ASK and VCEK verified a report claiming any
      launch measurement. Now compared against a pinned key; unpinned product
      lines fail closed.
- [ ] **Measurement rotation.** `approved_measurement` is a single value. A cloud
      guest-image refresh changes it and fails every miner at once. Needs an
      overlap window and a way to publish a successor.
- [ ] **Reproducible builds**, so a third party can derive the approved
      measurement from source rather than taking ours on trust.
- [ ] **Miners on 554 running real silicon.** Persistent confidential VMs are
      ongoing cost, deliberately deferred until there is someone to serve.

## Milestone 2 — MCP tool + enclave execution ✅ mostly done
- [x] MCP `postgres.query` handler (`sentinel/mcp/`), read-only by default
- [x] Key Broker Service (`sentinel/kbs.py`) — releases credentials only to an
      attested enclave; chip registry stands in for AMD's cert directory
- [x] `Database` seam: `MockDatabase` for tests/CI, `PostgresDatabase` for real use
- [x] End-to-end: request → enclave unlocks → query → result + attestation (`scripts/demo_mcp.py`)
- [x] Integration test against real Postgres, skipped unless `DATABASE_URL` is set
- [ ] **Encrypt released credentials to the enclave's ephemeral key (PK_TEE).** The
      broker currently returns the DSN in the clear once attestation passes, so it is
      only as private as the channel. Production should encrypt to a per-boot public
      key carried in the attestation report, so nothing but that enclave can decrypt
      it — the Trustee + Vault behaviour. Gating logic is unchanged; this hardens
      what happens *after* the decision to release.
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

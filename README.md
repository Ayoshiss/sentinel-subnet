# Sentinel

**The trust layer for the AI agent economy.**

Sentinel is a Bittensor subnet where AI agents act on real systems (databases, wallets, APIs) through **hardware-attested confidential compute**. Miners run [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers inside AMD SEV-SNP enclaves. Customer credentials live only inside the enclave; the operator cannot see the queries, the credentials, or the responses. Every response ships with a cryptographic attestation, signed by the chip itself, proving the query ran on genuine, unmodified hardware. Agents pay per query via [x402](https://www.x402.org) micropayments. Miners post slashable TAO collateral and are continuously re-attested by validators under Yuma Consensus.

> Trust the silicon, not the vendor.

---

## Status

**Live on Bittensor testnet as netuid 554, with attestation verified on real AMD
silicon.** The protocol, attestation, credential release, attested tool execution,
independent verification, runs today under 167 tests, CI green on every push.

Three things you can check without asking us for anything:

```bash
btcli subnets metagraph 554 --network test   # the subnet exists (bittensor >= 11)
python scripts/benchmark.py --rounds 100     # 100% detection, 0 false rejections
python -m pytest tests/test_sevsnp.py -q     # a real AMD-signed report, verified offline
```

| Area | State |
|---|---|
| Attestation core | **Working** (`sentinel/attestation.py`), Ed25519, publicly verifiable |
| Key Broker (credential release) | **Working** (`sentinel/kbs.py`), every refusal path tested |
| MCP `postgres.query` tool | **Working** (`sentinel/mcp/`), read-only by default |
| Attested query, end to end | **Working** (`scripts/demo_mcp.py`), CI on every push |
| **SEV-SNP hardware** | **Verified on real silicon**, AMD EPYC 7B13, VCEK → ASK → ARK → report signature, offline, against a pinned AMD root |
| Miner / validator neurons | **Working**, bittensor v11, weights land via timelock commit |
| Testnet | **Live**, netuid 554 since 2026-08-29 |
| Published results | `docs/results.md`: 100 rounds, 900 challenges |
| Gateway stack | **Live in production** (`gateway/`, `sidecar/`, `web/`), routes paid inference to SN64 |
| Architecture, threat register, Yuma mechanics, litepaper | Complete (`docs/`) |

Run `python scripts/demo_mcp.py` to watch a miner running modified code be refused
a customer credential.

**The honest gap.** The miners registered on 554 still run `MockSilicon`. Capturing
and verifying genuine reports is done and is in CI; putting live miners on
persistent confidential VMs is ongoing infrastructure and cost, deferred until
there is someone to serve. `MockSilicon` signs with a software Ed25519 key that has
the same trust shape as a real VCEK (public verifiability, no shared secret) so it
proves the protocol rather than the hardware root of trust. The `Silicon` and
`Verifier` interfaces are what the real backend implements, and that swap changes no
callers.

**And no design partners yet.** The product works; nobody has signed up to use it.

---

## Project history

Sentinel evolved from earlier gateway work into its current confidential-MCP form. The lineage (**Lattice → Bhairab (TAO Gateway) → Sentinel**) reflects a deliberate convergence, not churn: each step narrowed toward the same insight, that the missing layer in the agent economy is *trusted access to real systems*. The gateway layer carries forward from that work; the confidential-execution and attestation layers are new. The commit history in this repository reflects that continuous build.

---

## Why Sentinel

An agent that can only talk is a demo. An agent that can *act* (query production data, sign a transaction, update a record) is a product. Acting requires credentials, and handing credentials to an autonomous agent on someone else's infrastructure is the biggest unsolved risk in the agent economy.

Every current option fails the same test:

- **SaaS tool gateways** (Arcade, Composio), your keys sit on the vendor's servers. You trust their policy.
- **Self-hosting**, weeks of engineering per integration, and now you run security infrastructure.
- **Raw keys in agent memory**, today's default, and the reason keys leak constantly.

Confidential computing for agents is a validated, emerging field. What does not yet exist is a **decentralised, incentivised network of attested tool-servers.** That is the gap Sentinel fills.

---

## Architecture at a glance

Five layers, with the customer at the top and AMD silicon at the bottom as the only trusted parties. Everything between (gateway, network, miner operator, cloud host) is deliberately untrusted and constrained by cryptography.

```
Customer AI Agent            (trusted)
      │  MCP + x402
Sentinel Gateway             (untrusted, optional, verify independently)
      │
Bittensor Subnet             (untrusted, decentralised)
      │
Miner Host + Hypervisor      (untrusted)
   ┌──────────────────────┐
   │  SEV-SNP Enclave      │ (trusted)
   │   MCP server          │
   │   Credential store    │
   │   Attestation agent   │
   │   Ephemeral TEE keys  │
   └──────────────────────┘
      │
AMD EPYC Hardware            (trusted: root of trust)
```

Full component inventory, request/payment/attestation flows, failure modes, and deployment topology are in [`docs/architecture.md`](docs/architecture.md).

---

## Repository layout

Three layers at different maturities. Being precise about which is which matters
more than making the tree look finished.

**Sentinel core: working, tested (167 tests, CI on every push)**
```
sentinel/
├── attestation.py            # reports, response binding, verification
├── kbs.py                    # Key Broker, releases secrets only to attested code
├── enclave.py                # unlock → execute → attest the result
├── chain.py                  # metagraph discovery, ServeAxon, permit checks
├── database.py               # Database seam: Mock / Sqlite / Postgres backends
├── mcp/
│   ├── server.py             # MCP tool registry and dispatch
│   └── tools/postgres.py     # postgres.query, read-only by default
├── serving/                  # miner HTTP layer, hotkey auth, replay protection
├── validating/               # challenge → verify → score → submit weights
└── sevsnp/                   # real AMD attestation
    ├── report.py             # binary report parsing
    ├── certs.py              # AMD chain, root public key pinned
    ├── certtable.py          # host certificates from the extended report
    ├── verifier.py           # the five checks a report must pass
    └── guest.py              # /dev/sev-guest ioctls, standard and extended
tests/                        # 167 tests, weighted toward the refusal paths
└── fixtures/                 # a genuine AMD-signed report and AMD's real chain
scripts/
├── demo.py                   # attestation, verification, tamper detection
├── demo_mcp.py               # credential release → attested query → refusals
├── demo_round.py             # a validator round against dishonest miners
├── benchmark.py              # validator accuracy over N rounds
├── capture_report.py         # standalone report capture for a confidential VM
├── run_epoch.py              # a full epoch against a chain
└── launch_testnet.py         # subnet creation and registration
```

**Inherited gateway stack, live in production, carried forward from TAO Gateway**
```
gateway/                      # Go: auth, billing, x402, rate limiting, risk scan
sidecar/                      # Python: model routing to Bittensor SN64 + backstop
web/                          # Next.js frontend
postgres/schema.sql           # gateway's own billing tables (not customer data)
deploy/ · demo/ · chat.py · smoke-test.sh
Dockerfile.fly · docker-compose.yml · fly.toml · supervisord.conf
```

**Docs**
```
docs/
├── architecture.md           # full engineering spec
├── litepaper.md              # litepaper v0.1
├── threat-register.md        # 19 threats, scored impact × likelihood
├── bittensor-mechanics.md    # Yuma, commit-reveal, emissions, Taoflow
└── development.md            # setup, tests, demos, how the pieces fit
ROADMAP.md                    # milestone plan and what is still open
```

---

## Incentive mechanism

Validators challenge every miner with a fresh nonce every 360 blocks (~72 min) and score on five axes:

| Axis | Weight |
|---|---|
| Attestation validity | 40% |
| Response latency | 30% |
| Correctness (mirrored queries) | 20% |
| Cache-header hygiene | 5% |
| Nonce discipline | 5% |

Weights are aggregated by Yuma Consensus with stake-weighted median clipping. Commit-reveal (v3) prevents weight-copying. Only attestation-verified miners are discoverable, defeating Sybil tool-servers. Failing attestation triggers on-chain slashing. See [`docs/bittensor-mechanics.md`](docs/bittensor-mechanics.md).

---

## Roadmap

| Phase | Ships | Gate |
|---|---|---|
| M 0–2 | SEV-SNP miner image; Postgres + Solana tools; x402 on testnet | 3 design partners signed |
| M 3–4 | Mainnet subnet; KBS credential release; validator scoring + slashing | First paid queries |
| M 5–6 | Enterprise connectors; premium tier; security audit | $2K+ MRR sustained |
| M 7–9 | Enterprise gateway (DID + Stripe + audit trails) | Top-10 by inflow |
| M 10–12 | EU region; community validator opening | $20K+ MRR → Series A |

---

## License

MIT, see [`LICENSE`](LICENSE).

## Contact

Ayoshis Prakash Sitaula · Founder · 4yoshiss@gmail.com

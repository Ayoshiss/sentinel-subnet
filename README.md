# Sentinel

**The trust layer for the AI agent economy.**

Sentinel is a Bittensor subnet where AI agents act on real systems — databases, wallets, APIs — through **hardware-attested confidential compute**. Miners run [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers inside AMD SEV-SNP enclaves. Customer credentials live only inside the enclave; the operator cannot see the queries, the credentials, or the responses. Every response ships with a cryptographic attestation, signed by the chip itself, proving the query ran on genuine, unmodified hardware. Agents pay per query via [x402](https://www.x402.org) micropayments. Miners post slashable TAO collateral and are continuously re-attested by validators under Yuma Consensus.

> Trust the silicon, not the vendor.

---

## Status

**Pre-registration.** The system architecture, threat model, Bittensor mechanics, and go-to-market are complete. The testnet build is the next milestone. This repository holds the design corpus and the miner/validator/gateway scaffolding that the testnet will grow from.

| Area | State |
|---|---|
| Architecture spec | Complete (`docs/`) |
| Threat register (19 threats, scored) | Complete (`docs/`) |
| Bittensor / Yuma mechanics | Complete (`docs/`) |
| Litepaper v0.1 | Complete (`docs/`) |
| Miner scaffolding | Skeleton (`miner/`) |
| Validator scaffolding | Skeleton (`validator/`) |
| Gateway | Carried forward from prior work (`gateway/`) |
| Testnet | Next milestone |

---

## Project history

Sentinel evolved from earlier gateway work into its current confidential-MCP form. The lineage — **Lattice → Bhairab (TAO Gateway) → Sentinel** — reflects a deliberate convergence, not churn: each step narrowed toward the same insight, that the missing layer in the agent economy is *trusted access to real systems*. The gateway layer carries forward from that work; the confidential-execution and attestation layers are new. The commit history in this repository reflects that continuous build.

---

## Why Sentinel

An agent that can only talk is a demo. An agent that can *act* — query production data, sign a transaction, update a record — is a product. Acting requires credentials, and handing credentials to an autonomous agent on someone else's infrastructure is the biggest unsolved risk in the agent economy.

Every current option fails the same test:

- **SaaS tool gateways** (Arcade, Composio) — your keys sit on the vendor's servers. You trust their policy.
- **Self-hosting** — weeks of engineering per integration, and now you run security infrastructure.
- **Raw keys in agent memory** — today's default, and the reason keys leak constantly.

Confidential computing for agents is a validated, emerging field. What does not yet exist is a **decentralised, incentivised network of attested tool-servers.** That is the gap Sentinel fills.

---

## Architecture at a glance

Five layers, with the customer at the top and AMD silicon at the bottom as the only trusted parties. Everything between — gateway, network, miner operator, cloud host — is deliberately untrusted and constrained by cryptography.

```
Customer AI Agent            (trusted)
      │  MCP + x402
Sentinel Gateway             (untrusted, optional — verify independently)
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
AMD EPYC Hardware            (trusted — root of trust)
```

Full component inventory, request/payment/attestation flows, failure modes, and deployment topology are in [`docs/architecture.md`](docs/architecture.md).

---

## Repository layout

```
sentinel/
├── README.md
├── LICENSE
├── requirements.txt
├── docs/
│   ├── architecture.md          # full engineering spec
│   ├── litepaper.md             # litepaper v0.1
│   ├── threat-register.md       # 19 threats, scored impact × likelihood
│   └── bittensor-mechanics.md   # Yuma, commit-reveal, emissions, Taoflow
├── miner/
│   ├── miner.py                 # neuron entrypoint (skeleton)
│   ├── mcp_server.py            # in-enclave MCP tool handlers (stub)
│   ├── attestation.py           # SEV-SNP report generation (stub)
│   └── config.py
├── validator/
│   ├── validator.py             # challenge / verify / score loop (skeleton)
│   ├── challenge.py             # nonce challenge (stub)
│   └── scoring.py               # 40/30/20/5/5 rubric (stub)
└── gateway/
    ├── README.md                # carried forward from Bhairab
    └── gateway.py               # routing / billing / attestation cache (stub)
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

MIT — see [`LICENSE`](LICENSE).

## Contact

Ayoshis Prakash Sitaula · Founder · 4yoshiss@gmail.com

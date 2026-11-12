# Sentinel

**The trust layer for the AI agent economy.**

Sentinel is a Bittensor subnet where AI agents reach real systems through **hardware-attested confidential compute**: read-only PostgreSQL, and HTTPS APIs called with a key the operator never sees. Miners run [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers inside Intel TDX trust domains, booted from a signed, reproducible image. A credential is released only to an image the processor proves is on the published list, and every answer is bound to a fresh quote signed by the processor, checkable against Intel's root without trusting us. Validators re-attest every miner continuously under Yuma Consensus. What that covers today, and what it does not, is stated below.

> Trust the silicon, not the vendor.

---

## Status

**Live on Bittensor testnet as netuid 554. Every miner runs a signed, measured
image on Intel TDX, and the validator checks which image booted, not just which
chip.** 483 tests, CI green on every push.

Three things you can check without asking us for anything:

```bash
btcli subnets metagraph 554 --network test   # the subnet exists (bittensor >= 11)
python scripts/benchmark.py --rounds 100     # designed attacks zeroed, 0 false rejections
python -m pytest tests/test_tdx_verifier.py tests/test_verify_page.py -q   # real TDX quotes, verified offline
```

| Area | State |
|---|---|
| Intel TDX attestation | **Live on every miner since 2026-11-09** (`sentinel/tdx/`). Intel's signature and TCB status via dcap-qvl, debug off, approved TD firmware, the boot log replayed to the signed registers, Secure Boot under our key, an approved release booted, the quote bound to the answer |
| Measured image | **Released** (`image/`). Kernel, initrd and command line in one signed boot file; read-only root under dm-verity, its hash on the measured command line. Reproducible: two builds of the same commit give the same measurement. A disk with changed code was refused by the kernel |
| Signed releases | **Five so far**, v1 to v5, each built from a commit and signed with our Secure Boot key. The approved list is `measurements.json`; its hash is published on chain and a change takes effect 720 blocks later |
| Credential release | **Sealed to the enclave.** The key server encrypts the credential to a key that exists only inside the attested image, and signs every release; each answer names the key server (`sentinel/sealing.py`). An operator relaying the traffic saw the credential zero times |
| TLS | **Ends inside the enclave** (`sentinel/tls.py`). The image makes its TLS key in memory, the customer's key server certifies only that key, and since v5 the processor signs the key's name in every answer |
| MCP tools | `postgres.query`, read-only by default, one tool per scoped credential; `<scope>.request` for HTTPS APIs, limited to the methods and paths the customer lists |
| Browser verifier | **Built, not yet published** (`web/verify/`). A reviewer pastes an answer and runs the same checks in their own browser |
| Miner / validator neurons | **Working**, bittensor v11, weights land via timelock commit |
| Consensus catching a tampered miner | **Demonstrated 2026-10-04**, and now a second line: on TDX, changed code fails attestation itself |
| AMD SEV-SNP | **No longer accepted for mining.** On GCP its measurement covers the firmware and nothing above it (`docs/results.md`). The verifier (`sentinel/sevsnp/`) is kept and tested |
| Payments, slashing | **Not built.** No Sentinel query is paid for, and no miner posts collateral |
| Gateway stack | **Live, but separate** (`gateway/`, `sidecar/`), inherited from TAO Gateway. Not wired to Sentinel queries |
| Results, threat register, whitepaper | `docs/results.md` (every hardware run, method and numbers), `docs/threat-register.md` (25 threats) |

**Honest limits.**

- **We hold the signing key.** The approved list means "images we signed".
  The builds are reproducible, so anyone can rebuild a release and compare the
  measurement, but no one outside has done that yet.
- **Every miner on 554 is ours.** Consensus between three machines we run is
  not consensus between independent operators.
- **On the subnet, the miner holds the test credential itself.** Custody comes
  from a key server run by the customer (`docs/pilot-install.md`).
- **AMD SEV-SNP still has the measurement gap,** which is why Sentinel
  requires TDX.
- **Hosted agent platforms that trust only public certificate authorities**
  cannot connect to a miner yet.
- **No external security review, no design partners yet.**

---

## Run a node

Netuid 554 on Bittensor **testnet**. There are no emissions; the reason to run
one is to evaluate the design and report what breaks.

- **[Run a miner](docs/mining.md)**. Boots our signed image on a GCP Intel TDX
  machine, about $168 a month on demand (list prices, 2026-11-06). Read the
  first two sections before provisioning.
- **[Run a validator](docs/validating.md)**. No special hardware; a validator
  checks attestations rather than producing them.
- **[Subnet facts and the approved measurement](TESTNET.md)**

Outside the subnet, a single customer can run Sentinel in front of their own
database: **[pilot install](docs/pilot-install.md)**, and
**[who holds which key](docs/key-custody.md)**.

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

Five layers, with the customer at the top and Intel silicon at the bottom as the only trusted parties. Everything between (gateway, network, cloud host, miner operator) is deliberately untrusted and constrained by cryptography. The image itself is trusted because its measurement is checked, and today that means trusting our signing key (see the limits above).

```
Customer AI Agent            (trusted)
      │  MCP
Sentinel Gateway             (untrusted, optional, verify independently)
      │
Bittensor Subnet             (untrusted, decentralised)
      │
Miner Host + Hypervisor      (untrusted)
   ┌──────────────────────┐
   │  TDX trust domain     │ (trusted: measured)
   │   MCP server          │
   │   Credential store    │
   │   Attestation agent   │
   │   TLS + sealing keys  │
   └──────────────────────┘
      │
Intel Xeon (TDX) Hardware    (trusted: root of trust)
```

Full component inventory, request/payment/attestation flows, failure modes, and deployment topology are in [`docs/architecture.md`](docs/architecture.md).

---

## Repository layout

Three layers at different maturities. Being precise about which is which matters
more than making the tree look finished.

**Sentinel core: working, tested (CI on every push)**
```
sentinel/
├── attestation.py            # reports, response binding, verification
├── kbs.py                    # Key Broker, releases secrets only to attested code
├── kbs_remote.py             # the same broker across a network, so custody actually separates
├── enclave.py                # unlock → execute → attest the result
├── chain.py                  # metagraph discovery, ServeAxon, permit checks
├── database.py               # Database seam: Mock / Sqlite / Postgres backends
├── mcp/
│   ├── server.py             # MCP tool registry and dispatch
│   └── tools/postgres.py     # postgres.query, read-only by default
├── serving/                  # miner HTTP layer, hotkey auth, replay protection
├── validating/               # challenge → verify → score → submit weights
├── sealing.py                # credentials sealed to the enclave's attested key
├── tls.py                    # TLS key made in the enclave, bound into attestation
├── registry.py               # the approved-image list, its on-chain hash
├── tdx/                      # Intel TDX: quote verification, boot log replay, guest
└── sevsnp/                   # AMD attestation (verifier kept; no longer accepted for mining)
    ├── report.py             # binary report parsing
    ├── certs.py              # AMD chain, root public key pinned
    ├── certtable.py          # host certificates from the extended report
    ├── verifier.py           # the five checks a report must pass
    └── guest.py              # /dev/sev-guest ioctls, standard and extended
tests/                        # weighted toward the refusal paths
└── fixtures/                 # genuine AMD and Intel TDX evidence
image/                        # the measured miner image: build, sign, release
web/verify/                   # the browser verifier
scripts/
├── demo.py                   # attestation, verification, tamper detection
├── demo_mcp.py               # credential release → attested query → refusals
├── demo_round.py             # a validator round against dishonest miners
├── benchmark.py              # validator accuracy over N rounds
├── capture_report.py         # standalone report capture for a confidential VM
├── run_epoch.py              # a full epoch against a chain, one round, demo
├── run_miner.py              # the long-running miner, real silicon or nothing
├── run_validator.py          # the long-running validator, discovers and scores
├── publish_axon.py           # ServeAxon, run where the hotkey lives, not on the VM
├── set_subnet_identity.py    # full on-chain identity, fields btcli cannot reach
└── launch_testnet.py         # subnet creation and registration
deploy/                       # pilot script, key server and validator units
```

**Inherited gateway stack, carried forward from TAO Gateway**
```
gateway/                      # Go: auth, billing, x402, rate limiting, risk scan
sidecar/                      # Python: model routing to Bittensor SN64 + backstop
postgres/schema.sql           # gateway's own billing tables (not customer data)
deploy/ · demo/ · chat.py · smoke-test.sh
Dockerfile.fly · docker-compose.yml · fly.toml · supervisord.conf
```

**Docs**
```
docs/
├── architecture.md           # full engineering spec
├── whitepaper.md             # what the system is, and what is not built
├── threat-register.md        # 25 threats, scored impact × likelihood
├── results.md                # every hardware run, method and numbers
├── mining.md · validating.md · pilot-install.md · key-custody.md
├── bittensor-mechanics.md    # Yuma, commit-reveal, emissions, Taoflow
└── development.md            # setup, tests, demos, how the pieces fit
ROADMAP.md                    # milestone plan and what is still open
```

---

## Incentive mechanism

Validators challenge every miner with a fresh nonce about every 22 minutes and score on five axes:

| Axis | Weight | Behaviour |
|---|---|---|
| Attestation validity | 40% | **gate** |
| Response latency | 30% | points |
| Correctness (mirrored queries) | 20% | **gate** once a round has 3+ verified miners |
| Cache-header hygiene | 5% | **gate** |
| Nonce discipline | 5% | **gate** |

**Integrity gates, quality scores.** Whether a miner cheated is a yes or no;
how good it is is a matter of degree. Mixing the two meant a cheat forfeited
only the axis that caught it and kept the rest, so a caching cheat scored 0.95
against an honest slow miner's 0.887. The integrity axes now gate: fail one and
the miner earns nothing, whatever else it did. Correctness is the exception,
because it is decided by majority and a majority of one is a miner agreeing with
itself, so it only gates when there are enough participants for a vote to mean
something. Full numbers and the before/after are in
[`docs/results.md`](docs/results.md).

Weights are aggregated by Yuma Consensus with stake-weighted median clipping. Commit-reveal (v3) prevents weight-copying. Only attestation-verified miners earn, so every miner must boot an approved release on genuine Intel TDX. That does not prove miners belong to different people: one operator can run several. Failing attestation zeroes a miner's weight; there is no slashing. See [`docs/bittensor-mechanics.md`](docs/bittensor-mechanics.md).

---

## Roadmap

Ordered by what blocks what. Nothing below is promised by a date.

| Step | What | Unblocks |
|---|---|---|
| 1 | Measured application on Intel TDX. **Done:** released, on every miner since 2026-11-09 | Closed T23 on TDX |
| 2 | Credential sealed to the enclave, key server named in every answer, TLS ending inside the enclave. **Done:** v1 to v5 | Closed T20, T22 and T25 on TDX |
| 3 | Miners run by independent operators. **Next:** guide in `docs/mining.md` | Correctness by vote means something |
| 4 | External security review | Real credentials on third-party hardware |
| 5 | Payments | Only once someone is using it |

The earlier milestone plan is kept in [`ROADMAP.md`](ROADMAP.md) for history.
---

## License

MIT, see [`LICENSE`](LICENSE).

## Contact

Ayoshis Prakash Sitaula · Founder · 4yoshiss@gmail.com

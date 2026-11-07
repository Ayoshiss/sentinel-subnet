# Sentinel

**The trust layer for the AI agent economy.**

Sentinel is a Bittensor subnet where AI agents reach real systems through **hardware-attested confidential compute**, starting with read-only PostgreSQL. Miners run [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers inside AMD SEV-SNP confidential VMs. A credential is released only to a VM that attests on a genuine chip, and every response is bound to a fresh report signed by the chip itself, checkable against AMD's root without contacting AMD or us. Validators re-attest every miner continuously under Yuma Consensus. What that attestation covers today, and what it does not, is stated below.

> Trust the silicon, not the vendor.

---

## Status

**Live on Bittensor testnet as netuid 554, with attestation verified on real AMD
silicon.** The protocol, attestation, credential release, attested tool execution,
independent verification, runs today under 400 tests, CI green on every push.

Three things you can check without asking us for anything:

```bash
btcli subnets metagraph 554 --network test   # the subnet exists (bittensor >= 11)
python scripts/benchmark.py --rounds 100     # designed attacks zeroed, 0 false rejections
python -m pytest tests/test_sevsnp.py -q     # a real AMD-signed report, verified offline
```

| Area | State |
|---|---|
| Attestation core | **Working** (`sentinel/attestation.py`), Ed25519, publicly verifiable |
| Key Broker (credential release) | **Working** (`sentinel/kbs.py`), every refusal path tested |
| Broker on a separate machine | **Working, including on real silicon.** Two VMs, EPYC 7B13 enclave attesting to a broker on another host which verified the VCEK chain it was handed; transcript and negative control in `docs/split-proof.md`, `bash scripts/demo_split.sh` in CI. TLS and third-party custody still unproven |
| MCP `postgres.query` tool | **Working** (`sentinel/mcp/`), read-only by default |
| Attested query, end to end | **Working** (`scripts/demo_mcp.py`), CI on every push |
| **SEV-SNP hardware** | **Verified on real silicon**, AMD EPYC 7B13, VCEK → ASK → ARK → report signature, offline, against a pinned AMD root |
| Intel TDX | **Miner, validator and measured image built, run on hardware 2026-11-06, not deployed.** `sentinel/tdx/`: Intel's signature and TCB status via dcap-qvl, approved TD firmware, the firmware event log replayed to the signed registers, Secure Boot under our key, only the approved image loaded, quote bound to the rows. A real TDX miner scored 1.0; checked offline in CI. `image/` builds a reproducible image with a dm-verity root on the measured command line; two independent builds matched, and tampered code was refused by the kernel. Test keys only |
| Miner / validator neurons | **Working**, bittensor v11, weights land via timelock commit |
| Testnet | **Live**, netuid 554 since 2026-08-29 |
| Payments, slashing | **Not built.** No Sentinel query is paid for, and no miner posts collateral |
| What the measurement covers | **Measured, not assumed.** AMD SEV-SNP on GCP covers firmware only; the same change moves two Intel TDX registers on the same cloud. `scripts/probe_measurement_scope.sh`, results in `docs/results.md` |
| Consensus catching a tampered miner | **Demonstrated on hardware 2026-10-04.** Three miner processes on one VM, all operated by us; one with edited code passed attestation (`attest=1.00`) and was zeroed by consensus (`correct=0.00`). Three processes we run are not three independent operators. See `docs/results.md` |
| Published results | `docs/results.md`: 100 rounds, 1,000 challenges, simulated silicon. Every designed-detectable attack zeroed. The exfiltrator, which answers correctly while copying data, scores 1.0: no scoring rule can see it |
| Gateway stack | **Live, but separate** (`gateway/`, `sidecar/`), inherited from TAO Gateway, routes paid inference to SN64. Its x402 support covers the gateway's own scan endpoint and is not wired to Sentinel queries |
| Architecture, threat register, Yuma mechanics, whitepaper | Complete (`docs/`) |

Run `python scripts/demo_mcp.py` to watch a miner running modified code be refused
a customer credential.

**The honest gap.** On the GCP AMD platform the launch measurement covers the
firmware and nothing above it: kernel, command line and root filesystem are all
unmeasured, established by experiment in `docs/results.md`. An operator with root
can change the miner's code and still produce a valid attestation: tested on our own
live miner, which scored full marks while serving fabricated data. Two consequences
follow. The guarantee holds against the host and the infrastructure, not against the
operator. And a credential released to that VM, by our broker or a customer's, is
reachable by the operator, since the guest trust store is theirs to change
(threat register T20, T22, T23). That is still true of every live miner on 554,
which run on AMD. **The fix exists on Intel TDX and has been run once on
hardware:** `image/` builds a reproducible miner image whose read-only root is
covered by the measured boot, and a copy with changed code was refused by the kernel
and never served. On that image the credential is sealed to the enclave's attested
key, so an operator's relay between miner and broker saw only ciphertext, and a
miner pointed at the operator's own broker names it in every answer, which the
customer refuses (T20, T22). None of it is deployed, and the Secure Boot keys were
test keys.

**No design partners and no independent miners yet.** Every miner on 554 is ours.

---

## Run a node

Netuid 554 on Bittensor **testnet**. There are no emissions; the reason to run
one is to evaluate the design and report what breaks.

- **[Run a miner](docs/mining.md)**. Needs an AMD SEV-SNP confidential VM,
  about $36 a month on GCP spot or $74 on demand (list prices, 2026-11-06). Read
  the known limitation section before provisioning.
- **[Run a validator](docs/validating.md)**. No special hardware; a validator
  checks attestations rather than producing them.
- **[Subnet facts and the approved measurement](TESTNET.md)**

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

Five layers, with the customer at the top and AMD silicon at the bottom as the only trusted parties. Everything between (gateway, network, cloud host) is deliberately untrusted and constrained by cryptography. The miner operator is the exception today: see the honest gap above, since the measurement does not yet cover the application they run.

```
Customer AI Agent            (trusted)
      │  MCP
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
└── sevsnp/                   # real AMD attestation
    ├── report.py             # binary report parsing
    ├── certs.py              # AMD chain, root public key pinned
    ├── certtable.py          # host certificates from the extended report
    ├── verifier.py           # the five checks a report must pass
    └── guest.py              # /dev/sev-guest ioctls, standard and extended
tests/                        # weighted toward the refusal paths
└── fixtures/                 # a genuine AMD-signed report and AMD's real chain
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
deploy/                       # GCP provisioning, startup script, systemd unit
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
├── threat-register.md        # 24 threats, scored impact × likelihood
├── bittensor-mechanics.md    # Yuma, commit-reveal, emissions, Taoflow
└── development.md            # setup, tests, demos, how the pieces fit
ROADMAP.md                    # milestone plan and what is still open
```

---

## Incentive mechanism

Validators challenge every miner with a fresh nonce every 360 blocks (~72 min) and score on five axes:

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

Weights are aggregated by Yuma Consensus with stake-weighted median clipping. Commit-reveal (v3) prevents weight-copying. Only attestation-verified miners are discoverable, so every miner must run on a genuine confidential VM. That does not prove miners belong to different people: one operator can run several. Failing attestation zeroes a miner's weight; there is no slashing. See [`docs/bittensor-mechanics.md`](docs/bittensor-mechanics.md).

---

## Roadmap

Ordered by what blocks what. Nothing below is promised by a date.

| Step | What | Unblocks |
|---|---|---|
| 1 | Measured application on Intel TDX: kernel, command line and read-only root filesystem in the signed measurement, image built reproducibly from this repository. **Built and run on hardware 2026-11-06 (`image/`); production keys, registry entries and deployment remain** | Closes T23; makes a signed response proof that the approved code produced it |
| 2 | Credential release bound to an attested key, broker identity attested in every answer. **Built and run on hardware 2026-11-07** | Closes T20 and T22 on TDX |
| 3 | Miners run by independent operators | Correctness by vote means something |
| 4 | External security review | Real credentials on third-party hardware |
| 5 | Payments | Only once someone is using it |

The earlier milestone plan is kept in [`ROADMAP.md`](ROADMAP.md) for history.
---

## License

MIT, see [`LICENSE`](LICENSE).

## Contact

Ayoshis Prakash Sitaula · Founder · 4yoshiss@gmail.com

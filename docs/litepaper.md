# Sentinel — Litepaper v0.1

**The trust layer for the AI agent economy.**

A Bittensor subnet where AI agents act on real systems through hardware-attested
confidential compute, paying per query in machine-native money — and the silicon
itself proves nobody saw the data.

## Abstract

AI agents are proliferating, and every useful one eventually needs access to a
real system: a database, a wallet, an API. Today that access requires handing
credentials to third-party infrastructure and trusting a policy promise. Sentinel
removes the trust. Miners run Model Context Protocol (MCP) servers inside AMD
SEV-SNP enclaves; customer credentials live only inside the enclave; every
response ships with a cryptographic attestation, signed by the chip, proving the
query ran on genuine, unmodified hardware. Agents pay per call via x402
micropayments. Miners post slashable TAO collateral and are continuously
re-attested by validators under Yuma Consensus. The result is a decentralised
marketplace of **attested tool-servers** — the confidential execution layer the
agent economy is missing, and one of the few Bittensor subnet designs built to
earn real external revenue rather than farm emissions.

## 1. The problem

An agent that can only talk is a demo. An agent that can *act* is a product. But
acting requires credentials, and handing credentials to an autonomous agent on
someone else's infrastructure is the biggest unsolved risk in the agent economy.

- **SaaS tool gateways** (Arcade, Composio) — keys sit on the vendor's servers.
- **Self-hosting** — weeks of engineering per integration.
- **Raw keys in agent memory** — today's default; keys leak constantly.

Confidential computing for agents is a validated, emerging field. What does not
yet exist is a **decentralised, incentivised network of attested tool-servers.**

## 2. The solution — bonded couriers with sealed briefcases

| Element | In Sentinel |
|---|---|
| The courier | A miner running an AMD EPYC machine |
| The sealed briefcase | An AMD SEV-SNP confidential VM |
| The documents | The agent's query + the customer's sealed credentials |
| The signed receipt | A hardware attestation signed by the chip's VCEK |
| The bond | Slashable TAO collateral |
| The delivery fee | An x402 per-query micropayment in USDC |

## 3. Architecture

Five layers; only the customer (top) and AMD silicon (bottom) are trusted. See
[architecture.md](architecture.md) for the full spec — component inventory,
request/payment/attestation flows, failure modes, deployment topology.

## 4. Incentive mechanism

Validators challenge every miner with a fresh nonce every 360 blocks (~72 min)
and score on five axes: attestation validity (40%), latency (30%), correctness
(20%), cache hygiene (5%), nonce discipline (5%). Yuma aggregates with median
clipping; commit-reveal prevents copying; only attested miners are discoverable;
failing attestation triggers slashing.

## 5. Economics

Three revenue lines, all registering as external inflow: per-query x402 fees,
an enterprise gateway (DID + Stripe + audit trails), and premium connectors.
Under Taoflow, customer USDC converts to TAO buys → net inflow → sustained
emissions → more miners → more capacity → more customers. Revenue is both income
and the ranking mechanism.

**The number:** of ~128 subnets, only six have positive external inflow today.
~$20–30K/month of genuine customer inflow would place Sentinel in the network's
top five by real revenue.

## 6. Security model

The customer trusts only AMD's silicon and the chain that proves it. A formal
threat register scores 19 threats by impact × likelihood; the single
high-severity threat (a miner running tampered code) is neutralised at its root
by the KBS refusing credentials to any enclave whose launch measurement doesn't
match the approved image. See [threat-register.md](threat-register.md).

## 7. Roadmap

| Phase | Ships | Gate |
|---|---|---|
| M 0–2 | SEV-SNP miner image; Postgres + Solana tools; x402 testnet | 3 design partners |
| M 3–4 | Mainnet; KBS release; validator scoring + slashing | First paid queries |
| M 5–6 | Enterprise connectors; premium tier; audit | $2K+ MRR |
| M 7–9 | Enterprise gateway | Top-10 by inflow |
| M 10–12 | EU region; community validators | $20K+ MRR → Series A |

## 8. Status & team

Pre-registration. Architecture, threat model, Bittensor mechanics, and GTM
complete; testnet build is next. Founder-led by Ayoshis Prakash Sitaula
(Kathmandu), with a senior TEE/attestation engineer as the first funded hire.

> We taught machines to think. Sentinel lets us trust them to act — with proof
> built into the silicon itself.

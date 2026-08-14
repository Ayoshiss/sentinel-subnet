# Sentinel · System Architecture

**Version:** v0.4 (post-research synthesis)
**Status:** Design reference for build phase
**Audience:** Founding engineer, Lamida due diligence, technical partners

---

## 0. One-paragraph summary

Sentinel is a Bittensor subnet where independently-operated miners run hardware-attested (AMD SEV-SNP) MCP servers that let AI agents securely access customer systems (databases, APIs, wallets). Miners never see the data they route because it's processed inside a CPU enclave that they physically cannot inspect. Every response includes a cryptographic attestation proving the query ran on genuine, unmodified hardware. Agents pay per query via x402 machine-native micropayments; enterprise customers pay via Stripe with DID-based identity. A gateway layer (evolution of Bhairab) fronts the subnet, handling authentication, routing, billing, and schema optimization. Validators continuously challenge miners with cryptographic nonces to verify attestation, scoring them on integrity + latency + correctness; failing miners get slashed via on-chain EVM collateral contracts.

---

## 1. System architecture — the big picture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                                                                                │
│                              CUSTOMER SIDE                                     │
│                                                                                │
│   ┌────────────────┐    ┌────────────────┐    ┌────────────────────────┐      │
│   │ Crypto-Native  │    │  Enterprise    │    │ Regulated Fintech /    │      │
│   │ Agents         │    │  Agents        │    │ Compliance-Heavy       │      │
│   │ (Eliza, GOAT,  │    │  (custom       │    │ (MiCA-scoped, DAO      │      │
│   │  solana-agent- │    │  frameworks)   │    │  treasuries, health)   │      │
│   │  kit, Virtuals)│    │                │    │                        │      │
│   └───────┬────────┘    └───────┬────────┘    └───────────┬────────────┘      │
│           │                      │                          │                  │
└───────────┼──────────────────────┼──────────────────────────┼──────────────────┘
            │                      │                          │
            │ MCP + x402           │ MCP + x402/Stripe        │ MCP + DID + Stripe
            │                      │                          │
            ▼                      ▼                          ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                          SENTINEL GATEWAY LAYER                                │
│                                                                                │
│   ┌────────────────────────┐          ┌────────────────────────────────┐      │
│   │ Public Developer       │          │ Enterprise Gateway             │      │
│   │ Gateway                │          │                                │      │
│   │ api.sentinel.dev       │          │ enterprise.sentinel.dev        │      │
│   │                        │          │                                │      │
│   │ - Bearer key auth      │          │ - DID-based identity           │      │
│   │ - x402 per-query bill  │          │ - Nevermined Flex Credits      │      │
│   │ - Vercel x402-mcp      │          │ - Stripe metered billing       │      │
│   │   paidTool primitive   │          │ - Signed usage audit trail     │      │
│   │ - Code Mode schema     │          │ - SOC 2 / MiCA docs pathway    │      │
│   │   collapse (94% ctx    │          │ - White-label option           │      │
│   │   cost reduction)      │          │                                │      │
│   └──────────┬─────────────┘          └────────────────┬───────────────┘      │
│              │                                          │                      │
│              └──────────────────┬───────────────────────┘                      │
│                                 │                                              │
│                                 ▼                                              │
│              ┌─────────────────────────────────────────┐                       │
│              │      ROUTING & ATTESTATION CACHE        │                       │
│              │                                         │                       │
│              │  - Miner health + rank lookup           │                       │
│              │  - Attestation cache (60–120s TTL)      │                       │
│              │  - Load balancer to best miner          │                       │
│              │  - Zero-cache HTTP headers enforcement  │                       │
│              │  - Nonce generation + verification      │                       │
│              └────────────────────┬────────────────────┘                       │
│                                   │                                            │
└───────────────────────────────────┼────────────────────────────────────────────┘
                                    │
                                    │ Encrypted MCP tool request (JSON-RPC)
                                    │
                    ┌───────────────┼───────────────┬───────────────┐
                    │               │               │               │
                    ▼               ▼               ▼               ▼
              ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
              │ MINER 1 │     │ MINER 2 │     │ MINER 3 │     │ MINER N │
              │         │     │         │     │         │     │         │
              │ SEV-SNP │     │ SEV-SNP │     │ SEV-SNP │     │ SEV-SNP │
              │   VM    │     │   VM    │     │   VM    │     │   VM    │
              │         │     │         │     │         │     │         │
              │ ┌─────┐ │     │ ┌─────┐ │     │ ┌─────┐ │     │ ┌─────┐ │
              │ │ MCP │ │     │ │ MCP │ │     │ │ MCP │ │     │ │ MCP │ │
              │ │ SRV │ │     │ │ SRV │ │     │ │ SRV │ │     │ │ SRV │ │
              │ └──┬──┘ │     │ └──┬──┘ │     │ └──┬──┘ │     │ └──┬──┘ │
              │    │    │     │    │    │     │    │    │     │    │    │
              │ [creds │     │ [creds │     │ [creds │     │ [creds │
              │  in    │     │  in    │     │  in    │     │  in    │
              │  encl] │     │  encl] │     │  encl] │     │  encl] │
              │    │    │     │    │    │     │    │    │     │    │    │
              └────┼────┘     └────┼────┘     └────┼────┘     └────┼────┘
                   │               │               │               │
                   │               │               │               │
                   │ MCP tool call executes inside enclave         │
                   │ (Postgres query, Solana RPC, Salesforce, etc.)│
                   │                                               │
        ┌──────────┴─────────────┬─────────────────┬───────────────┴────┐
        │                        │                 │                    │
        ▼                        ▼                 ▼                    ▼
  ┌───────────┐          ┌──────────────┐   ┌──────────────┐    ┌──────────────┐
  │ CUSTOMER  │          │ CUSTOMER     │   │ CUSTOMER     │    │ CUSTOMER     │
  │ POSTGRES  │          │ SALESFORCE   │   │ SOLANA RPC   │    │ STRIPE / API │
  │           │          │              │   │              │    │              │
  └───────────┘          └──────────────┘   └──────────────┘    └──────────────┘


┌────────────────────────────────────────────────────────────────────────────────┐
│                          SUPPORTING INFRASTRUCTURE                             │
│                                                                                │
│   ┌───────────────────┐    ┌────────────────────┐    ┌───────────────────┐    │
│   │ KEY BROKER (KBS)  │    │  BITTENSOR         │    │  VALIDATOR NODES  │    │
│   │                   │    │  SUBTENSOR CHAIN   │    │                   │    │
│   │ Trustee + Vault   │    │                    │    │  Off-chain:       │    │
│   │                   │    │  - TEE Registry    │    │  - Nonce every    │    │
│   │ Releases customer │    │    (miner hotkey → │    │    360 blocks     │    │
│   │ credentials only  │    │    ephemeral       │    │  - Verify SEV-SNP │    │
│   │ to attested       │    │    TEE pubkey)     │    │    quote          │    │
│   │ miners            │    │                    │    │  - Score miners   │    │
│   │                   │    │  - EVM Collateral  │    │  - Trigger slash  │    │
│   │                   │    │    Contract        │    │                   │    │
│   │                   │    │    (slashable)     │    │                   │    │
│   └───────────────────┘    └────────────────────┘    └───────────────────┘    │
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Trust model — who trusts what

The whole design collapses into a single sentence: **the customer only has to trust silicon and cryptography — everything else (Sentinel, Dendrite equivalents, miners, cloud providers) is untrusted and constrained by hardware.**

### The trust hierarchy from customer's perspective

| Layer | Trusted? | Why |
|---|---|---|
| AMD (silicon vendor) | Yes | Root of trust; VCEK certificate chain terminates at AMD |
| AMD EPYC hardware in miner's data center | Yes | Attestation proves this is real hardware, unmodified firmware |
| Sentinel gateway | **Optional** | Customer can bypass and verify attestation independently |
| Sentinel operators (us) | **No** | We can't see queries, credentials, or responses — enforced by hardware |
| Miner operator (individual) | **No** | Same enforcement; miner runs the hardware but can't peek inside |
| Cloud provider (AWS/Azure/GCP hosting miner) | **No** | Hypervisor is explicitly outside trust boundary |
| Public network in transit | **No** | End-to-end encryption via TLS + attestation-bound keys |
| Other tenants on same physical CPU | **No** | Memory encryption isolates VMs from each other |

### The trust hierarchy from Sentinel's perspective

| Actor | Trusted for | Not trusted for |
|---|---|---|
| Miner attestation report | Proving the correct code is running | Anything else |
| Validator scores | Aggregate quality signal | Individual honesty (use Yuma consensus median) |
| Bittensor subtensor chain | Immutable slashing enforcement | Fast state (use off-chain for high-frequency) |
| KBS (self-hosted) | Releasing credentials to attested workloads | Data plane (never touches customer data) |

---

## 3. Component inventory

### 3.1 Customer-facing (Gateway Layer)

| Component | Purpose | Technology | Owner |
|---|---|---|---|
| Public Developer Gateway | api.sentinel.dev — per-query x402 billing, developer DX | Go (chi) + Vercel AI SDK x402-mcp compatible | Sentinel |
| Enterprise Gateway | enterprise.sentinel.dev — DID + Stripe + audit trails | TypeScript / Next.js + Nevermined SDK | Sentinel |
| Routing & Attestation Cache | Miner selection, nonce generation, attestation caching | Go service + Redis | Sentinel |
| Landing / Dashboard | User-facing site, API key management, usage reporting | Next.js on Vercel | Sentinel |

### 3.2 Miner-side (per-miner)

| Component | Purpose | Technology | Owner |
|---|---|---|---|
| Host OS + KVM | Bare-metal AMD EPYC running SEV-SNP guest VMs | Ubuntu 24.04 LTS + kernel 6.5+ + QEMU 8.0+ | Miner |
| Confidential VM | The SEV-SNP-protected guest running MCP server | Ubuntu 24.04 LTS inside SEV-SNP | Miner (image pinned by Sentinel) |
| MCP Server | The actual tool endpoints (Postgres, Salesforce, etc.) | Rust/Go, one process per tool type | Sentinel (published image) |
| Attestation Agent | Generates SEV-SNP reports on demand via `/dev/sev-guest` | Rust with `sev` crate | Sentinel (published image) |
| Ephemeral TEE Keypair | Ed25519 keypair generated at enclave boot | libsodium inside enclave | Miner enclave (never leaves) |
| Credential Store | Encrypted customer credentials for MCP tool connectors | Vault client, decrypted only in enclave | Sentinel (via KBS) |
| Miner CLI | `sentinel-miner` command for operator setup, ranking, earnings | TypeScript/Rust | Sentinel |

### 3.3 Supporting infrastructure

| Component | Purpose | Technology | Owner |
|---|---|---|---|
| Key Broker Service (KBS) | Attests miners before releasing credentials | Trustee project + HashiCorp Vault OSS | Sentinel |
| Attestation Verification Service | Validates SEV-SNP quotes at scale | Azure Attestation OR self-hosted verifier | Sentinel |
| Certificate/PKI cache | Caches AMD VCEK certificates offline | Self-hosted Vault or Fortanix | Sentinel |
| Validator Nodes | Challenge miners, score, trigger slashing | Rust (Bittensor SDK) + Redis | Sentinel (bootstrap), community over time |
| TEE Registry (on-chain) | Maps miner hotkey → ephemeral TEE public key | Substrate storage on Subtensor | On-chain, written by validators |
| Collateral Contract (on-chain) | Slashes miner TAO stake on failure | Solidity via Subtensor EVM | Sentinel (deployed once) |
| Facilitator (x402) | Verifies signatures, sponsors gas, settles on-chain | Self-hosted (Rust) or thirdweb | Sentinel or third-party |
| Audit Ledger | Immutable log of all tool calls (enterprise tier) | Hippius (SN75) or Postgres append-only | Sentinel |
| Monitoring / SIEM | Sentry + Grafana Loki + Better Uptime + audit search | SaaS + self-hosted stack | Sentinel |

---

## 4. Miner bootstrap flow (one-time, when miner comes online)

```
STEP 1: Miner operator provisions hardware
    │
    ├─► Bare metal: AMD EPYC 7003+ (Milan or newer), SEV-SNP capable BIOS enabled
    ├─► Or cloud: Azure DCasv5 / GCP N2D Confidential / Hetzner EPYC 9004
    ├─► Disable SMT (hyperthreading) on host — mitigates StackWarp attack
    └─► Install Ubuntu 24.04, KVM, QEMU 8.0+, CoCo runtime

STEP 2: Miner operator installs sentinel-miner CLI
    │
    ├─► `sentinel-miner init` — generates cold key, hot key, registers config
    └─► Deposits collateral TAO into the EVM collateral contract on Subtensor

STEP 3: Miner registers on Bittensor SN[Sentinel]
    │
    ├─► Standard Subtensor `register_neuron` extrinsic
    └─► Waits for UID assignment

STEP 4: Miner launches confidential VM
    │
    ├─► Pulls the approved Sentinel image (published SHA-384 hash)
    ├─► KVM boots the VM in SEV-SNP mode
    ├─► SEV-SNP hardware measures launch: firmware + kernel + initrd + container image
    ├─► Launch measurement stored in ASP; produces a launch digest
    └─► Guest OS boots inside the enclave

STEP 5: Enclave initializes
    │
    ├─► Generates ephemeral TEE keypair (SK_TEE, PK_TEE) via libsodium
    ├─► Requests SEV-SNP report via /dev/sev-guest ioctl
    ├─► Embeds PK_TEE into reportData field of the report
    └─► Report is signed by VCEK (unique to physical CPU)

STEP 6: KBS handshake for credential release
    │
    ├─► Attestation Agent sends signed report to Sentinel KBS
    ├─► KBS verifies:
    │      ├─► Signature validates against AMD certificate chain
    │      ├─► Launch measurement matches Sentinel's approved gold hash
    │      ├─► TCB level is current (not vulnerable microcode)
    │      └─► reportData contains PK_TEE
    └─► If ALL PASS: KBS releases encrypted credential bundle
             ├─► Encrypted with PK_TEE (only decryptable inside enclave)
             └─► Contains: DB URLs, API keys, TLS certs, wallet keys per tool

STEP 7: MCP server starts serving
    │
    ├─► Decrypts credentials inside enclave memory
    ├─► Starts listening on Streamable HTTP transport (2026-07-28 MCP spec)
    ├─► Registers PK_TEE + tool list on Bittensor TEE Registry
    └─► Announces ready for validator challenges

STEP 8: Continuous re-attestation begins
    │
    └─► Every 360 blocks (~72 min), validator sends fresh nonce
        └─► Miner regenerates attestation with new nonce
             └─► Validator verifies + scores
                  └─► Weights updated on-chain via Yuma consensus
```

---

## 5. End-to-end request lifecycle

The full trace from an agent making a tool call to the response arriving back, with attestation verified.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=0ms:  CUSTOMER AGENT prepares MCP tool call                              │
│                                                                             │
│  POST https://api.sentinel.dev/mcp/tools/call                              │
│  Headers: (none yet — no payment attached)                                 │
│  Body: {                                                                    │
│    "jsonrpc": "2.0",                                                        │
│    "method": "tools/call",                                                  │
│    "params": {                                                              │
│      "name": "postgres.query",                                              │
│      "arguments": {                                                         │
│        "connection_id": "cust_042_prod_readonly",                          │
│        "sql": "SELECT vulnerability_class, severity FROM vulns WHERE       │
│               contract_address = $1", "params": ["0xABC..."]                │
│      }                                                                      │
│    }                                                                        │
│  }                                                                          │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=15ms:  GATEWAY receives request                                          │
│                                                                             │
│  No bearer token, no x402 signature → responds 402 Payment Required        │
│                                                                             │
│  Response: 402                                                              │
│  Header: PAYMENT-REQUIRED: base64({                                         │
│    "x402Version": 2,                                                        │
│    "resource": {...},                                                       │
│    "accepts": [{                                                            │
│      "scheme": "exact",                                                     │
│      "network": "eip155:8453",                                              │
│      "amount": "1000",  // 0.001 USDC on Base                              │
│      "asset": "0x833589...", "payTo": "0x742d35..."                        │
│    }]                                                                       │
│  })                                                                         │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=20ms:  AGENT signs EIP-3009 payment authorization                        │
│                                                                             │
│  Local wallet signs (gasless):                                              │
│    {                                                                        │
│      "from": "0x981...",   // agent's wallet                                │
│      "to": "0x742d35...",  // Sentinel's payTo                              │
│      "value": "1000",                                                       │
│      "validAfter": 0,                                                       │
│      "validBefore": 1785590400,  // strict 300s TTL                         │
│      "nonce": "0x8fa37bc..."   // 32-byte random                            │
│    }                                                                        │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=40ms:  AGENT retries request with PAYMENT-SIGNATURE header               │
│                                                                             │
│  POST /mcp/tools/call                                                       │
│  Header: PAYMENT-SIGNATURE: base64({signature + auth})                     │
│  Body: (same as before)                                                     │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=60ms:  GATEWAY validates payment                                         │
│                                                                             │
│  - Extracts signature, checks nonce not previously seen (Redis lookup)     │
│  - Confirms validBefore is > now + 60s (avoid last-minute abuse)           │
│  - Calls x402 facilitator: /verify + /settle                                │
│  - Facilitator submits transaction, sponsors gas                            │
│  - Payment settled on Base (subsecond confirmation)                         │
│                                                                             │
│  Payment status: CONFIRMED                                                  │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=200ms:  GATEWAY selects best miner and forwards request                  │
│                                                                             │
│  - Queries routing cache: which miner has postgres.query capability +      │
│    highest validator score + lowest recent latency?                         │
│  - Selects miner UID_42                                                     │
│  - Generates request_id (uuid)                                              │
│  - Forwards MCP request to UID_42's Streamable HTTP endpoint               │
│    with request_id in _meta field (stateless per 2026-07-28 spec)          │
│  - Attaches fresh nonce for optional attestation refresh                    │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=220ms:  MINER receives request (inside SEV-SNP enclave)                  │
│                                                                             │
│  - MCP Server dispatches to postgres.query handler                          │
│  - Handler:                                                                 │
│      ├─► Retrieves customer's connection string from enclave-local creds   │
│      ├─► Opens/reuses TLS connection to customer Postgres                  │
│      ├─► Executes prepared statement with sanitized parameters             │
│      ├─► Reads result set                                                  │
│      └─► Serializes result to JSON                                         │
│  - Attestation Agent generates fresh SEV-SNP report:                       │
│      ├─► reportData = SHA-384(request_id || response_hash)                 │
│      └─► Signed by VCEK                                                    │
│  - Response wrapped:                                                        │
│      {                                                                      │
│        "result": [...],                                                    │
│        "attestation": {                                                    │
│          "quote": "base64(...)",                                           │
│          "signature": "0x...",                                             │
│          "boundHash": "..."                                                │
│        }                                                                    │
│      }                                                                      │
│  - Response signed with SK_TEE                                              │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=400ms:  GATEWAY validates response                                       │
│                                                                             │
│  - Verifies SK_TEE signature against registered PK_TEE (on-chain lookup)   │
│  - Optionally verifies fresh attestation quote (if cache expired)          │
│  - Sets Cache-Control: no-store, no-cache, must-revalidate, private        │
│  - Returns 200 OK with response + attestation to customer                  │
└─────────────────────────────────────────┬───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  T=420ms:  CUSTOMER AGENT receives result                                   │
│                                                                             │
│  {                                                                          │
│    "result": [                                                              │
│      {"vulnerability_class": "reentrancy", "severity": "high"},            │
│      {"vulnerability_class": "integer_overflow", "severity": "medium"}     │
│    ],                                                                       │
│    "attestation": {...}                                                    │
│  }                                                                          │
│                                                                             │
│  Agent optionally independently verifies attestation:                      │
│    - Extracts chipID from quote                                            │
│    - Fetches VCEK from AMD KDS (or cached)                                 │
│    - Walks ARK → ASK → VCEK certificate chain                              │
│    - Confirms launch measurement matches published Sentinel image hash     │
│    - Confirms boundHash matches SHA-384(request_id || response_hash)       │
│                                                                             │
│  If PASS: trust the result                                                  │
│  If FAIL: discard result, request different miner, flag failure to gateway │
└─────────────────────────────────────────────────────────────────────────────┘

Total latency budget: ~420ms typical (with cached attestation)
                       ~800ms if fresh attestation generated per-request
```

---

## 6. Payment lifecycle (x402 detailed flow)

Reproducing the standard x402 V2 wire flow, adapted for MCP:

```
    Agent                    Sentinel                     x402
                             Gateway                    Facilitator
      │                          │                          │
      │──── 1. POST tool call ──▶│                          │
      │     (no payment)         │                          │
      │                          │                          │
      │◀── 2. 402 Payment Req ───│                          │
      │    PAYMENT-REQUIRED      │                          │
      │    (base64 JSON)         │                          │
      │                          │                          │
      │── 3. Sign EIP-3009 ──────│                          │
      │    (local, gasless)      │                          │
      │                          │                          │
      │──── 4. POST retry ───────▶│                          │
      │    PAYMENT-SIGNATURE     │                          │
      │                          │                          │
      │                          │── 5. /verify + /settle ─▶│
      │                          │                          │
      │                          │                          │──► on-chain
      │                          │                          │
      │                          │◀─── 6. Settled ──────────│
      │                          │                          │
      │                          │── 7. Route to miner ─────│
      │                          │                          │
      │◀── 8. 200 OK + Data ─────│                          │
      │    PAYMENT-RESPONSE      │                          │
      │    (base64 tx receipt)   │                          │
      │                          │                          │
```

### Key hardening (mitigates the 5 published x402 attacks)

| Attack | Mitigation in Sentinel |
|---|---|
| Revert-Grant (I-A) | Two-tier finality: high-cost calls (>$0.10) wait for confirmation before response |
| Settlement Preemption (I-B) | Payment signatures scoped to specific facilitator (caller-bound) |
| Replay (II) | Nonce tracked in Redis with atomic check; TTL 300s |
| Cache Confusion (III) | All paid responses return `Cache-Control: no-store, no-cache, must-revalidate, private` |
| Bazaar Sybil (IV) | Only attestation-verified miners are discoverable in the routing cache |

---

## 7. Validator lifecycle (continuous re-attestation)

```
Every 360 blocks (~72 minutes):

    Validator                       Miner (SEV-SNP VM)
        │                                    │
        │─── 1. Generate random 32B nonce N ─│
        │                                    │
        │──── 2. POST /attest?nonce=N ──────▶│
        │                                    │
        │                                    │── 3. ioctl /dev/sev-guest
        │                                    │       reportData = SHA-384(N || PK_TEE)
        │                                    │
        │                                    │── 4. VCEK signs report
        │                                    │
        │◀── 5. Return signed report ────────│
        │                                    │
        │─── 6. Verify:                      │
        │      ├─► VCEK cert chain valid     │
        │      ├─► launchMeasurement matches │
        │      │   Sentinel gold hash        │
        │      ├─► TCB level is current      │
        │      ├─► reportData contains N     │
        │      └─► reportData contains PK_TEE│
        │                                    │
        │─── 7. Score miner:                 │
        │      ├─► Attestation validity: 40% │
        │      ├─► Response latency: 30%     │
        │      ├─► Correctness (mirrored     │
        │      │   real queries): 20%        │
        │      ├─► Cache-header hygiene: 5%  │
        │      └─► Nonce discipline: 5%      │
        │                                    │
        │─── 8. Yuma consensus aggregation:  │
        │      ├─► Compare to peer validators│
        │      ├─► Clip outlier scores       │
        │      └─► Weight-median for final   │
        │                                    │
        │─── 9. Write weights to chain       │
        │                                    │
        │─── 10. IF miner failed attestation │
        │      trigger slashCollateral()     │
        │      on EVM contract                │
        │                                    │
```

---

## 8. Failure modes & recovery

| Failure | Detection | Recovery |
|---|---|---|
| Miner crashes mid-request | Gateway timeout (5s) + no signed response | Retry to different miner; failed miner's rank drops next epoch |
| Miner's TEE VM fails to boot | KBS never receives valid attestation | Credentials never released; miner is inert; validator scores 0 |
| KBS goes offline | Newly-booted miners can't fetch credentials | Existing miners continue serving; new miners wait; failover KBS cluster |
| Validator disagreement on miner quality | Yuma consensus median clipping | Outlier validator's trust score decays; alignment restores over epochs |
| x402 facilitator downtime | Payment verification fails | Fall back to secondary facilitator (thirdweb + self-hosted); refund customers if extended |
| Bittensor subtensor chain congestion | On-chain slash txs queue | Slashing delayed but eventual; off-chain scoring continues |
| AMD KDS unreachable | Attestation verification pauses | Fall back to cached VCEK certs (72h TTL); flag to ops |
| Firmware CVE published for SEV-SNP | Detected via monitoring / community feed | Bump required TCB level; miners with old microcode auto-deregistered |
| Customer's upstream DB goes down | MCP query fails with isError:true | Structured error returned; agent gracefully degrades |
| Miner attempts credential exfiltration | Launch measurement mismatch on boot | KBS refuses credential release; miner can't serve; slash on next epoch |

---

## 9. Deployment topology (initial)

### Sentinel-operated infrastructure (Bootstrap phase, months 0–6)

```
                   REGION: US-EAST (primary)
                   ┌─────────────────────────────────────┐
                   │  api.sentinel.dev (Fly.io iad+ord)  │
                   │  enterprise.sentinel.dev (Vercel)   │
                   │  KBS + Vault (Fly.io iad)           │
                   │  Attestation service (Azure East US)│
                   │  Facilitator (self-hosted, Fly.io)  │
                   │  2 validator nodes (bare metal colo)│
                   │  Postgres (Neon US-East)            │
                   │  Redis (Upstash US-East)            │
                   └─────────────────────────────────────┘

                   REGION: EU-CENTRAL (secondary, month 4+)
                   ┌─────────────────────────────────────┐
                   │  api.sentinel.dev (Fly.io fra)      │
                   │  KBS replica (Fly.io fra)           │
                   │  1 validator node                    │
                   │  Postgres replica (Neon EU)         │
                   └─────────────────────────────────────┘

                   REGION: MINERS (distributed globally)
                   ┌─────────────────────────────────────┐
                   │  15–30 miners in bootstrap         │
                   │  Mix: 60% cloud (Azure/GCP/Hetzner) │
                   │       40% bare metal colo           │
                   │  Geographic diversity encouraged    │
                   │  Each miner: EPYC 7003+ w/ SEV-SNP  │
                   └─────────────────────────────────────┘
```

### Scaling target (month 12+)

- 3+ gateway regions (US-East, EU-Central, APAC)
- 50–100 active miners
- 5+ validator nodes (community-run by high-stake token holders)
- KBS cluster with 3-of-5 quorum for credential release
- Multi-facilitator redundancy for x402

---

## 10. Technology choices — with rationale

| Choice | Rationale | Rejected alternatives |
|---|---|---|
| **AMD SEV-SNP** (over Intel TDX, NVIDIA CC) | Better REST/DB workload perf, offline VCEK verification, lower cost premium | TDX: attestation infra complexity; H100 CC: over-provisioned for our use case |
| **MCP spec 2026-07-28** (stateless) | Enables horizontal scaling across miners; no sticky sessions | 2025-11-25 stateful spec: would fight our distributed architecture |
| **x402 V2** (over V1, over custom) | Standardized, Linux Foundation-stewarded, wallet demographics validate machine-native use | V1 X-PAYMENT: deprecated; custom: reinventing the wheel |
| **Vercel `x402-mcp` compatibility** | Drop-in DX for Vercel AI SDK users; large distribution channel | Custom SDK: fragments developer experience |
| **Cloudflare Code Mode pattern** | 94% context cost reduction on tool schemas | Standard MCP tool listing: bloats agent context |
| **Trustee KBS + HashiCorp Vault** | Open source, production-hardened, standard pattern | Fortanix: expensive; roll-our-own: security-critical, avoid |
| **AMD SEV-SNP over Nitro Enclaves (AWS)** | Nitro is AWS-only, single-vendor lock-in | Nitro: not portable across cloud providers |
| **Substrate EVM (Subtensor)** for slashing | Native to Bittensor chain; miners already have TAO on it | Ethereum L2: adds cross-chain complexity |
| **Streamable HTTP transport** (MCP) | Modern, works over standard load balancers | stdio: local-only; websocket: connection management overhead |
| **Rust for critical path (attestation, gateway hot path)** | Memory safety, no GC pauses, mature TEE ecosystem | Go: less mature crypto library ecosystem; TypeScript: too slow for hot path |
| **Ephemeral TEE keys (per-boot)** | Compromised long-lived keys can't be exploited across reboots | Persistent keys: replay attack surface |
| **Post-quantum signature migration path** | Aligns with x402 draft-vauban-consolidated-00 and NIST guidance | Classical only: 5-year obsolescence risk |
| **On-chain TEE Registry** | Trust-minimized mapping between hotkey and enclave identity | Off-chain registry: adds trusted party |

---

## 11. What's NOT in the architecture (explicit scope cuts)

For v1 (first 12 months), the following are intentionally deferred:

- **A2A (Agent-to-Agent) protocol support** — Google's horizontal peer protocol. Add in v2 after MCP is stable.
- **AP2 (Agent Payments Protocol)** — Google/Coinbase agent-to-agent commerce. Adjacent, not required for tool access.
- **Cross-chain settlement beyond Base + Solana** — thirdweb supports 170+ EVM networks but multichain complexity not worth it at MVP.
- **Compliance API as a separate product** — MiCA/VARA disclosures ship as documentation, not a paid API tier.
- **Multiple MCP servers per miner** — one MCP process per enclave keeps blast radius contained.
- **In-enclave LLM inference** — route to Chutes (SN64) or gm (SN28) upstream instead of running models in our enclaves.
- **Learned model router** — regex-based tool routing is good enough. Machine learning that decision is v2.
- **Consumer-tier miner support** (like TargonOS uses TPM 2.0 for RTX GPUs) — hardware attestation is our moat, don't compromise.
- **White-label / on-prem deployments** — enterprise contracts only, month 12+.

---

## 12. What has to be true to consider v1 shipped

Concrete checklist:

- [ ] SEV-SNP miner image published (signed, reproducible build)
- [ ] Postgres MCP tool live end-to-end (query executes, attestation verifies)
- [ ] Solana RPC MCP tool live end-to-end
- [ ] x402 payment flow working on Base + Solana
- [ ] Gateway routing operational, at least 10 miners live
- [ ] KBS releasing credentials only on valid attestation
- [ ] Validator scoring pipeline running, weights updating on-chain
- [ ] EVM collateral contract deployed, slashing tested on devnet
- [ ] Cache-Control + nonce discipline enforced (5-attack mitigations verified)
- [ ] Vercel `x402-mcp` compatibility confirmed via reference client
- [ ] Landing page + docs live at sentinel.dev (or chosen domain)
- [ ] First 3 paying design partners onboarded
- [ ] MRR > $2K/month sustained for 30 days

If those 13 boxes are checked, v1 is done. That's month 6 target under the $125K plan, month 5 under $300K.

---

## 13. Open architectural questions

To decide before or during engineering kickoff:

1. **Miner geography incentives** — do we boost rewards for underrepresented regions to ensure diversity, or let the market sort it?
2. **KBS decentralization plan** — start centralized (trusted Sentinel operator), migrate to threshold cryptography in v2?
3. **Attestation cache TTL** — 60s (aggressive) vs 300s (economic)? Trade-off between freshness and cost.
4. **Fallback for AMD KDS outage** — hard fail closed, or serve with degraded trust label?
5. **Tool schema versioning** — how do we roll out new MCP tools without breaking existing customers?
6. **On-chain vs off-chain reputation** — persistent miner reputation lives where?
7. **Fee tier for enterprise gateway** — 1% Nevermined-style, or 2-3% for the added enterprise features?
8. **When to open validator operation to community** — day 1 (permissionless, higher risk of gaming) or after 6 months (trusted bootstrap first)?

These get answered as we build. First engineer helps resolve #1–5; #6–8 are strategic and get resolved in ongoing product/business calls.

---

## Appendix A — Glossary

- **SEV-SNP** — AMD's Secure Encrypted Virtualization with Secure Nested Paging; hardware memory encryption + integrity for VMs
- **VCEK** — Versioned Chip Endorsement Key; unique cryptographic key per physical AMD EPYC CPU
- **ARK / ASK** — AMD Root Key / AMD SEV Key; the certificate chain roots for VCEK verification
- **KBS** — Key Broker Service; releases secrets only to attested workloads (Trustee project)
- **RTMR** — Runtime Measurement Register; extends launch measurement dynamically
- **MCP** — Model Context Protocol; standardized JSON-RPC interface between AI agents and external tools
- **x402** — HTTP 402 Payment Required-based machine payment protocol; Linux Foundation-stewarded
- **Yuma Consensus** — Bittensor's on-chain aggregation of validator scores with outlier clipping
- **TCB** — Trusted Computing Base; the version level of trusted firmware/microcode
- **CoCo** — Confidential Containers (CNCF project); Kubernetes-native TEE runtime
- **PK_TEE / SK_TEE** — Ephemeral asymmetric keypair generated inside the enclave at boot

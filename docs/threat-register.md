# Sentinel: Threat Register v0.1

A structured inventory of attack and failure modes, each scored by
**impact × likelihood** (1–5 each; risk = product, range 1–25), ranked, and
paired with an architecture-level mitigation. Scores reflect *inherent* risk
before the listed mitigation.

**Severity bands:** Low 1–6 · Medium 8–12 · High 15–25

## Attestation & TEE layer

| ID | Threat | Imp | Lik | Risk | Sev | Mitigation |
|----|--------|-----|-----|------|-----|------------|
| T1 | Malicious miner runs modified enclave image | 5 | 3 | 15 | HIGH | KBS verifies launch measurement before credential release; mismatch = no credentials + slash |
| T2 | Credential exfiltration from enclave memory | 5 | 2 | 10 | MED | SEV-SNP memory encryption; credentials sealed to PK_TEE |
| T3 | Spoofed / forged attestation report | 5 | 2 | 10 | MED | VCEK chain to AMD root; offline verification |
| T4 | Attestation replay | 4 | 3 | 12 | MED | Fresh nonce per challenge; reportData binds nonce + response hash |
| T5 | Vulnerable / outdated firmware (TCB) | 4 | 3 | 12 | MED | Minimum TCB enforced; old microcode auto-deregistered |
| T6 | Micro-architectural side-channel (SMT) | 3 | 2 | 6 | LOW | SMT disabled on host; minimal TCB; audit scope |

## Payment layer (x402)

| ID | Threat | Imp | Lik | Risk | Sev | Mitigation |
|----|--------|-----|-----|------|-----|------------|
| T7 | Revert-Grant | 3 | 3 | 9 | MED | Two-tier finality: high-value calls await confirmation |
| T8 | Settlement preemption | 3 | 2 | 6 | LOW | Caller-bound signatures scoped to a facilitator |
| T9 | Payment replay | 3 | 3 | 9 | MED | Atomic nonce tracking, 300s TTL |
| T10 | Cache confusion | 3 | 3 | 9 | MED | no-store headers on paid responses; scored |
| T11 | Bazaar Sybil (fake tool-servers) | 4 | 3 | 12 | MED | Only attested miners are discoverable |

## Subnet & consensus layer

| ID | Threat | Imp | Lik | Risk | Sev | Mitigation |
|----|--------|-----|-----|------|-----|------------|
| T12 | Validator collusion / weight gaming | 4 | 3 | 12 | MED | Yuma median clipping; outlier trust decay |
| T13 | Miner Sybil | 3 | 3 | 9 | MED | TAO collateral + attestation required to serve |
| T14 | Weight-copying | 2 | 3 | 6 | LOW | Commit-reveal; challenge-based scoring |
| T15 | Stake concentration / capture | 4 | 2 | 8 | MED | Nakamoto tracking; validator diversity plan |

## Infrastructure & operations

| ID | Threat | Imp | Lik | Risk | Sev | Mitigation |
|----|--------|-----|-----|------|-----|------------|
| T16 | KBS compromise | 5 | 2 | 10 | MED | Releases only to attested enclaves; v2 threshold release |
| T17 | AMD KDS outage | 2 | 2 | 4 | LOW | Cached VCEK (72h TTL) |
| T18 | x402 facilitator downtime | 3 | 2 | 6 | LOW | Secondary facilitator failover; refunds |
| T19 | Customer downstream failure | 2 | 3 | 6 | LOW | Structured isError; graceful degradation |

## Risk summary

- **High (15–25):** 1, T1, neutralised at root by the KBS.
- **Medium (8–12):** 11, payment, consensus, KBS, TCB.
- **Low (1–6):** 7, side-channel, outages, degradation.

The single high-severity threat is neutralised because the KBS refuses
credentials to any enclave whose launch measurement doesn't match the approved
image, a compromised miner physically cannot obtain the data it would need to
attack. Every remaining threat is medium or low with a named mitigation.

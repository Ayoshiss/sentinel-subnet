# Sentinel: Threat Register v0.1

A structured inventory of attack and failure modes, each scored by
**impact × likelihood** (1–5 each; risk = product, range 1–25), ranked, and
paired with an architecture-level mitigation. Scores reflect *inherent* risk
before the listed mitigation.

**Severity bands:** Low 1–6 · Medium 8–12 · High 15–25

## Attestation & TEE layer

| ID | Threat | Imp | Lik | Risk | Sev | Mitigation |
|----|--------|-----|-----|------|-----|------------|
| T1 | Malicious miner runs modified enclave image | 5 | 3 | 15 | HIGH | KBS verifies launch measurement before credential release; mismatch = no credentials. Read with T23: this holds for a modified *boot* image and not for modified application code |
| T23 | Miner modifies application code without changing the launch measurement | 5 | 4 | 20 | HIGH | **Not closed, and it is the root of T20 and T22.** SEV-SNP measures boot state (kernel, initrd, command line), not the root filesystem, so editing the served code, the CA trust store or the Python packages leaves the measurement identical. Demonstrated: a tampered miner scored 1.0 on real silicon. Fix requires the rootfs to be covered by measured state, which is **not** just enabling dm-verity: on our current cloud the kernel command line that would carry a root hash is itself unmeasured, so the hash needs an anchor that is measured (unified kernel image measured by firmware, or measured direct boot with kernel hashes, which needs host support). Numbered out of sequence because IDs are stable |
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
| T20 | Miner operator reads the credential from its own broker | 5 | 4 | 20 | HIGH | Only closed by running the broker elsewhere: `run_broker.py` on the customer's host, miner started with `--broker-url`. Self-brokering remains the default and the miner warns at startup, so on the subnet this threat is open and accepted because the data is seeded |
| T21 | Miner supplies a forged certificate chain to its remote broker | 5 | 3 | 15 | HIGH | AMD's root SPKI is pinned in `CertChain.verify_self` on the broker side, so a self-signed chain is refused; tested in `test_a_miner_supplied_chain_with_its_own_root_is_refused` |
| T22 | Miner operator intercepts the released credential by MITM of its own guest | 5 | 4 | 20 | HIGH | **Not closed.** `RemoteBroker` does not pin the broker's certificate, so TLS is validated against the guest's CA store, which the operator owns. Combined with T23 (the launch measurement does not cover the root filesystem) the operator can install a CA, proxy the broker, and read the DSN without changing the measurement. Requires both: a dm-verity root hash in the measured kernel command line, then a pinned broker certificate inside the measured image. Encrypting the credential to the enclave's ephemeral report key is also needed, and is worth little before the rootfs is measured, since whoever can edit the code can read what it decrypts |

## Risk summary

- **High (15–25):** 1, T1, T20, T21, T22, T23.
- **Medium (8–12):** 11, payment, consensus, KBS, TCB.
- **Low (1–6):** 7, side-channel, outages, degradation.

T1 is only partly neutralised. The KBS does refuse credentials to any enclave
whose launch measurement doesn't match, which stops a miner booting a different
image. It does not stop a miner editing the code inside the approved image, which
is T23, and earlier versions of this file claimed the former as though it covered
the latter.

T20 and T22 are the two to read carefully, because both were missing from this
table and both undercut T1. If the broker runs in the miner's own process, the
operator holds the secret and the measurement check is a formality performed on
themselves. The code to close it exists and is tested; what closes it is a
deployment decision, and on testnet 554 it is deliberately not taken, because the
database is seeded data and nobody is harmed. Against a real database, running
the broker on the miner's host makes T1's mitigation void. T21 is the attack that
separation invites, and the pinned root answers it.

T22 is where the current claim is weakest, and an earlier version of this file
scored it MED on the assumption that TLS protects the credential from the miner's
operator. It does not. The client validates the broker's certificate against the
guest's own trust store, and the operator owns that store. So the separation
achieved by T20's mitigation raises the cost of theft from reading a local
variable to actively intercepting one's own guest, which is a real improvement and
leaves unambiguous evidence, but it does not yet make the credential unobtainable.

T20, T22 and T23 reduce to one missing control: the launch measurement does not
cover the root filesystem. A dm-verity root hash in the measured kernel command
line closes T23, makes a pinned broker certificate trustworthy and so closes
T22, and is the precondition for credential encryption
being worth building at all. Until it lands, do not describe the operator as
unable to obtain the credential. Describe them as unable to obtain it without
tampering that leaves evidence.

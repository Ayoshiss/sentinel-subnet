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
| T23 | Miner modifies anything above the firmware without changing the launch measurement | 5 | 4 | 20 | HIGH | **Not closed, and it is the root of T20 and T22.** Verified on our own host 2026-10-04: the boot chain is shim then GRUB then kernel, all read from the disk, `/proc/cmdline` carries `BOOT_IMAGE=`, and Secure Boot is disabled. The launch measurement is fixed at launch, so nothing GRUB loads afterwards is in it: not the kernel, not the initrd, not the command line, not the bootloader, and not the root filesystem, so editing the served code, the CA trust store or the Python packages leaves the measurement identical. Demonstrated: a tampered miner scored 1.0 on real silicon. Fix is a change of boot chain, not a flag: measured direct boot where the hypervisor injects kernel/initrd/cmdline hashes into the firmware, or a unified kernel image measured before launch, and only then is a dm-verity root hash worth carrying. Whether this is achievable on our provider is open and is the next thing to establish. A vTPM exists at /dev/tpm0 and measures the boot chain into PCRs, but it is emulated by the host, and our threat model (section 2 of the whitepaper) does not trust the host, so it cannot anchor this. Numbered out of sequence because IDs are stable |
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
| T22 | Miner operator intercepts the released credential by MITM of its own guest | 5 | 4 | 20 | HIGH | **Not closed.** `RemoteBroker` does not pin the broker's certificate, so TLS is validated against the guest's CA store, which the operator owns. Combined with T23 (the launch measurement covers the firmware and nothing above it) the operator can install a CA, proxy the broker, and read the DSN without changing the measurement. Requires both: a boot chain whose kernel and rootfs are actually measured, then a pinned broker certificate inside that measured image. Encrypting the credential to the enclave's ephemeral report key is also needed, and is worth little before the rootfs is measured, since whoever can edit the code can read what it decrypts |

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

## T23: can the boot chain be fixed on our provider? Answered 2026-10-04

**No, not on GCP Confidential VM as offered.** Established three ways rather than
one, because the answer determines whether Sentinel's integrity claim is
achievable on this platform at all.

**1. Experiment on our own host.** Added an inert kernel parameter, rebooted, and
the launch measurement was byte-identical (`docs/results.md`). The kernel command
line is not in the measurement.

**2. Google's own documentation.** The launch measurement is "a SHA-384 digest,
based on its initial launch measurements taken before the Confidential VM instance
UEFI executes". A launch endorsement binds that digest to a firmware build and a
vCPU count, and nothing else. Bootloader, kernel and userspace measurements are
explicitly routed elsewhere: Google calls the launch measurement "hardware
attested" and the vTPM-based measurements "software attested". That split is the
whole answer.

**3. Why the vTPM cannot substitute.** Misono et al., *Confidential VMs Explained*
(ACM, 2024), section 3.1: "the traditional vTPM is inappropriate for CVMs since the
VMM manages it". Our threat model does not trust the host, and the host emulates
the vTPM, so a PCR chain through it proves nothing against the adversary we
actually named.

The same section describes the fix and why it is not ours to apply: "AMD proposes a
measured direct boot, where the VMM additionally inserts the hash of the kernel,
initrd, and kernel parameters into the initial guest memory. Thus, they become part
of the measurement in the attestation report." The VMM is the hypervisor. It is the
provider's, not ours, so this is a platform choice and no amount of guest-side work
substitutes for it.

### What follows

Sentinel cannot make an application-integrity claim on GCP Confidential VM. Not
"has not yet"; cannot, with the current offering. Three options, and they are
strategic rather than technical:

1. **Move to a platform whose VMM does measured direct boot.** Reported to exist
   elsewhere, including Azure via IGVM and self-hosted QEMU/KVM, which is the
   obvious path since AMD's own flow supports it. **Unverified by us.** Do not
   plan around it until someone reproduces the command-line experiment there and
   sees the measurement move.
2. **Self-host on bare metal**, where we control the VMM and can enable kernel
   hashes. Maximum control, and a different business.
3. **Stop claiming application integrity and sell what is actually true.** The
   attestation proves a genuine AMD processor running SEV-SNP at VMPL0 in a known
   firmware state, with the credential released only to that environment, scoped
   so it cannot read beyond its views, and consensus catching a miner that lies
   about data. That is a real product. It is confidential *access*, not
   confidential *compute integrity*.

Option 3 is available today and costs nothing. Options 1 and 2 are the only ones
that close T23, and both are moves, not patches.

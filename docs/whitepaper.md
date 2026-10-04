# Sentinel: confidential access for autonomous agents

**v1.0, October 2026.** Releasing a database credential to a program identified
by hardware, rather than to a person or a company.

Netuid 554 on Bittensor testnet, live since 2026-08-29. AMD EPYC, SEV-SNP.

> This document describes the system that exists. Section 9 separates what is
> built from what is designed, and section 12 lists the commands that reproduce
> every number in it. **Where this document and the code disagree, the code is
> correct.**

---

## Abstract

An AI agent that can act on real systems needs a credential, and a credential
inside a running process is readable by every layer that hosts it. Sentinel
changes the recipient: the credential is released only to code whose launch
state a processor has measured and signed. Miners run Model Context Protocol
servers inside AMD SEV-SNP enclaves; a broker releases a database credential only
against an approved launch measurement; every response carries a signature from
the chip bound to that request. Verification depends on no third party at query
time, because AMD's root is pinned at build time rather than fetched. The network
is a Bittensor subnet, so independent operators run the enclaves and validators
challenge them continuously, which is what prevents the guarantee reducing to
trust in one company.

---

## 1. The problem is delegation, not access

A customer already has their data. What they cannot do is let an autonomous agent
touch it.

Give an agent a database credential and it lands in a running process. From that
moment it is readable by the process itself, the host operating system, anyone
with SSH, the logs, a memory dump, and the cloud provider. None of those readers
is the agent, and the customer controls almost none of them.

So the question is never *do I trust this agent*. It is **do I trust every layer
underneath it**.

Both available answers fail. Lock the agent down with a sandbox or a stale
replica and it answers questions about data that is not real, so nothing is
automated. Hand over the credential and the trust boundary now contains a
vendor's operations team, their cloud account, and every engineer with production
access. For a regulated institution the second is a disqualification rather than
a trade.

## 2. Threat model

Sentinel assumes the operator of the machine is not trusted, and that the cloud
provider hosting it is not trusted. It does not assume the processor vendor is
untrusted: AMD's root is the anchor, and a system that distrusted it would have
nothing to stand on.

**Defended.** A host or hypervisor reading enclave memory. An operator
substituting modified code to obtain the credential. A forged certificate chain
presented in place of AMD's. A replayed attestation. A response that did not come
from the approved image.

**Not defended.** An operator with root modifying the application *after* boot,
which the launch measurement does not cover. Micro-architectural side channels. A
vulnerability in AMD firmware below the enforced floor. Anything the customer's
own database exposes to a legitimate query.

## 3. Mechanism

The processor computes a 48-byte measurement over everything loaded into the
virtual machine before it starts, and signs attestation reports with a key
derived from chip secrets and firmware version. A broker holding the customer's
credential releases it only when that measurement equals an approved value.

1. The chip measures what booted and signs it.
2. The enclave sends that signed report to the customer's broker.
3. The broker releases the credential, only on a matching measurement.
4. The query runs inside the enclave, against the customer's own database.
5. The answer leaves signed by the chip and bound to that exact request.

Two attestations happen and they prove different things. The first controls
access to the secret. The second makes an individual answer checkable by someone
who was not party to the first.

The response binding matters as much as the release. A valid signature over the
wrong claim is still the wrong claim, so the report's `report_data` carries a
hash of the request identifier and the response body.

The firmware is also policed. Sentinel enforces `TCB[SNP] >= 0x1D` on EPYC 7003,
the level AMD names in bulletin AMD-SB-3030. A downgrade cannot be faked: the
signing key is derived from the firmware version, so a rolled-back chip signs
with a different key and the chain breaks before the floor is consulted.

## 4. Verification without a trusted third party

A report is verified through AMD's chain: the chip-unique VCEK, signed by the AMD
SEV key, signed by the AMD root. The host supplies those certificates alongside
the report, which sounds like asking the suspect for the evidence. It is not,
because the root is compared against a public-key hash compiled into the
verifier. A substituted root fails before any field of the report is read.

That design was forced by an outage: AMD's key distribution service refused
connections during development, which would have meant a validator unable to
score honest miners because a third party was down. Verification now contacts
nobody at query time.

**A forged chain used to pass.** An earlier version checked only that the root
was self-signed, and anyone can self-sign, including with AMD's exact subject
line. An attacker-generated root, intermediate, leaf and report claiming any
measurement verified completely. Roots are now pinned by SPKI hash and unpinned
product lines fail closed. Found internally, before deployment.

## 5. Attestation state synchronisation

A verifier needs to know which measurements are approved. That sounds
administrative and is the hardest unsolved problem in running a decentralised
confidential network, because the measurement is not derivable from source.

AMD's specification builds the launch digest from inputs the hypervisor supplies:
page contents, page type, permissions, guest physical address, insertion order,
and the saved CPU state, which means the vCPU count is in it. The firmware the
hypervisor loads is not part of the operator's disk image.

We observed the consequence directly. The same boot disk, restored from a
snapshot and started on a different host, produced a different measurement, and
the miner correctly refused to serve:

```
2d24cf96…c773  →  ccdc5cf0…26fa
same disk, same commit, different host firmware
```

So a single pinned value describes one machine, not a fleet. Two honest operators
running identical images on hosts at different firmware levels measure
differently, and a validator pinning one scores the other zero. Under Yuma that
validator then accrues no bond in the miner everyone else rewards, and because
bonds are an exponential moving average the loss outlives the mistake.

The registry answers it. A manifest on chain carries a SHA-256 of the approved
list and an **effective block height**; the list itself is served as a file and
checked against that digest. Two separate problems need two mechanisms: the
effective height means every validator switches at the same block rather than
whenever it polled, and **block-pinned reads** mean two validators polling
seconds apart across an update see identical bytes. Reading at an epoch boundary
substitutes for neither, because the epoch fire block is not deterministic in
advance.

Each entry carries the recipe that produced it: image name, machine type, and
where it was observed. That is what makes the list verifiable rather than merely
authoritative. Whoever controls the list controls who can mine, and publishing
the recipe is how that power is made checkable instead of hidden.

## 6. Incentive mechanism

Validators challenge miners with a fresh nonce, verify the attestation, and score
five axes: attestation, cache hygiene, nonce discipline, correctness and latency.
Weights are submitted under timelock commit-reveal, so no validator can copy
another's round before it reveals.

The first version averaged all five, and the benchmark showed that was wrong:
getting caught forfeited only the points for the axis that caught you.

| Miner | Behaviour | Averaged | Gated |
|---|---|---|---|
| cacheable | lets attested replies be cached | 0.9500 | **0.0000** |
| fabricator | invents rows | 0.8000 | **0.0000** |
| slow | honest, 907 ms link | 0.8872 | 0.8874 |
| honest | honest, fast | 1.0000 | 1.0000 |

The fix was to stop averaging two different kinds of question. Whether a miner
cheated is yes or no; how good it is is a matter of degree. Attestation, cache
hygiene and nonce discipline are deterministic facts about a single response, so
they **gate**: fail one and the miner earns nothing. Latency still scores.

Correctness is decided by agreement between miners, which makes it a vote rather
than a fact, so it gates only once a round has three or more verified miners.

The flaw survived for weeks because the tests asserted that cheats were
*detected* and never what detection *cost*. Detection was always 100 percent. The
penalty was the bug.

## 7. Results

Nine miners, two honest, one honest but slow, and six attacks: a backdoored
image, a replayed report, a corrupt signature, fabricated rows, cacheable
attested replies, and an unreachable endpoint.

```
detection rate                   100.0%
caught by the expected cause     100.0%
false rejections                 0  (0.0%)
honest mean weight               1.0000
degraded (slow) mean weight      0.8874
dishonest mean weight            0.0000
worst honest / best dishonest    1.0000 / 0.0000
```

**The honest limit of this result:** every attacker in that field was written by
us, so it demonstrates the defences catch what we anticipated. In September an
independent operator running his own validator on 554 found a defect we had not:
the miner verified a caller's signature but never checked whether that caller was
permitted, so any keypair could query the enclave. Fixed and deployed the same
day.

## 8. Operating confidential hardware

Two behaviours matter in production and appear in neither the marketing nor the
specification sheets.

**Attestation can die while the process lives.** A request to the AMD security
processor timed out, and the kernel disabled the guest's message key permanently
rather than risk reusing an initialisation vector after an ambiguous failure:

```
sev-guest: Detected error from ASP request. rc: -110
sev-guest: Disabling vmpck_id 0 to prevent IV reuse.
```

That decision is correct, and the consequence is that attestation is dead until
the guest reboots while the service keeps answering. Ours reported healthy for
ten hours in that state, because health served cached identity and never asked
whether the chip still answered. Health now fails closed, and a watchdog reboots
after repeated failures and stops after two reboots in an hour rather than
looping on degraded hardware. It has since recovered a miner unattended.

**Capacity is scarce and the measurement follows the host.** SEV-SNP instances
are available in a minority of cloud zones and a zone can refuse. Moving a miner
is routine, and moving a miner changes its measurement, which is why section 5
exists.

## 9. What is not built

Stated plainly, because a reader can check the repository in minutes.

**Application integrity after boot.** The launch measurement covers what booted,
not what runs afterwards. An operator with root can modify the miner after boot
and still produce a valid attestation. We demonstrated this against our own live
miner: full marks while serving fabricated rows. dm-verity does not close it on
our cloud, because the kernel command line is not covered. Credential scoping
(section 10) bounds the damage without closing the hole.

**Payment.** There is no payment path. Earlier material described per-query
micropayments; no such code exists. Validators challenge miners and miners earn
emissions.

**Collateral and slashing.** Not implemented. Dishonesty costs a miner its
weight, which is the only economic penalty in force.

**Correctness beyond consensus.** Correctness is decided by miners agreeing with
each other, which requires them to hold identical data. Real customers break that
by definition.

**Independent miners.** One independent validator is running. There are no
independent miners, because mining requires a confidential VM somebody must pay
for.

**The broker and the enclave have never been separated in deployment.** The
architecture places the broker with the customer; today the miner runs both in
one process.

## 10. Limiting what a caller can read

Attestation decides which code runs. The allowlist decides who may call.
Read-only decides whether they may write. None of those limit the scope of a
read.

Scopes do. Each is its own restricted credential, unlocked by its own
attestation, exposed as its own tool `<scope>.query`. An API key can be limited
to a subset, and a caller's tool list is filtered to exactly what it may reach.
`docs/scoping.sql` is a worked example of the views and roles a DBA creates.

This is also the answer to "how does the system know which data is sensitive". It
does not, and it does not need to: data out of scope is unreachable rather than
merely unrequested.

Callers who are not on Bittensor authenticate with an API key rather than a
hotkey signature, since an enterprise customer has no hotkey. Only digests are
stored, comparison is constant time, and a rejected key never falls through to
the signature path. A bearer token carries no replay protection, unlike a signed
request; that is a real difference and an operator should choose it knowingly.

## 11. Two deployment shapes

The same software serves two situations with different trust properties, and
conflating them causes most of the confusion about what Sentinel is.

**Self-hosted.** A customer runs the broker and the enclave over their own
database. The operator is the customer's own infrastructure team, so section 9's
first limitation does not apply to them: the threat they are buying protection
against is the cloud provider reading their memory, and that is covered.

**Subnet.** Independent operators run enclaves and validators challenge them.
This is where the open problems live, and also where the argument for
decentralisation is real: if one company operated every enclave, the customer
would be trusting that company, which is what the product exists to remove.

The decentralised case pays when the data owner and the agent owner are different
parties who do not trust each other. Where they are the same party, a single
enclave is sufficient and simpler.

## 12. Reproducing every claim

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet
python -m pytest -q                       # 247 passing
python -m pytest tests/test_sevsnp.py -q  # real report, AMD chain, offline
python scripts/benchmark.py --rounds 100  # the table in section 6
btcli subnets metagraph 554 --network test
```

A captured attestation report and AMD's real certificate chain are committed as
fixtures, so the hardware verification re-runs without hardware.

The approved launch measurement, the firmware floor and the registry are in
`TESTNET.md` and `measurements.json`. Known limitations are in `SECURITY.md`.

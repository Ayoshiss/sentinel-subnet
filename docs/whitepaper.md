# Sentinel: confidential access for autonomous agents

**v2.0, November 2026.** Releasing a credential to a program identified by
hardware, rather than to a person or a company.

Netuid 554 on Bittensor testnet, live since 2026-08-29. Intel TDX on Google
Cloud since 2026-11-09.

> This document describes the system that exists. Section 9 separates what is
> built from what is designed, and section 13 lists the commands that reproduce
> its claims. **Where this document and the code disagree, the code is
> correct.**
>
> v1.0 (October 2026) described an AMD SEV-SNP deployment whose measurement
> covered the firmware and nothing above it. That gap is closed on Intel TDX,
> and section 9 says what changed and what did not.

---

## Abstract

An AI agent that can act on real systems needs a credential, and a credential
inside a running process is readable by every layer that hosts it. Sentinel
changes the recipient: the credential is released only to code a processor has
measured and signed. Miners run Model Context Protocol servers inside Intel TDX
trust domains, booted from a signed, reproducible image whose kernel, command
line and read-only root filesystem are all in the measurement. A key server
held by the data owner releases a credential only to an approved image, sealed
to a key that exists only inside it. Every answer carries a quote from the
processor bound to that request, the TLS key it was served under and the key
server that released the credential. The network is a Bittensor subnet, so
independent operators can run the trust domains and validators challenge them
continuously, which is what keeps the guarantee from reducing to trust in one
company.

---

## 1. The problem is delegation, not access

A customer already has their data. What they cannot do is let an autonomous agent
touch it.

Give an agent a database credential or an API key and it lands in a running
process. From that moment it is readable by the process itself, the host
operating system, anyone with SSH, the logs, a memory dump, and the cloud
provider. None of those readers is the agent, and the customer controls almost
none of them.

So the question is never *do I trust this agent*. It is **do I trust every layer
underneath it**.

Both available answers fail. Lock the agent down with a sandbox or a stale
replica and it answers questions about data that is not real, so nothing is
automated. Hand over the credential and the trust boundary now contains a
vendor's operations team, their cloud account, and every engineer with production
access. For a regulated institution the second is a disqualification rather than
a trade.

The middle answer, a vendor that holds every customer's keys and attaches them
on the agent's behalf, moves the problem rather than solving it: the vendor's
store becomes the target, and a breach there exposes every customer at once,
with revocation left to each of them.

## 2. Threat model

Sentinel assumes the operator of the machine is not trusted, and that the cloud
provider hosting it is not trusted. It does not assume the processor vendor is
untrusted: Intel's root is the anchor, and a system that distrusted it would
have nothing to stand on.

**Defended.** A host or hypervisor reading trust-domain memory. An operator
substituting modified code, at boot or on disk, to obtain the credential or to
answer falsely. An operator relaying the traffic between the trust domain and
the key server, or between the agent and the trust domain. A key server run by
the operator in place of the customer's. A replayed quote. An answer that did
not come from an approved image.

**Not defended.** Micro-architectural side channels. A vulnerability in Intel's
TDX module or the platform below the TCB level Intel reports as current. A
compromise of our image signing key (section 9). Anything the customer's own
database or API exposes to a legitimate request.

**Trusted, and worth naming.** Intel. Google's TD firmware, whose hash (MRTD) we
approve as observed rather than rebuild (section 9). The image signing key,
held by us today.

## 3. Mechanism

The image is one signed EFI binary carrying the kernel, the initrd and the
kernel command line, plus a read-only root filesystem. The root filesystem is
under dm-verity, and its root hash is on that command line. TDX measures the
firmware into MRTD and the boot chain into runtime registers, and records each
step in a boot log. Secure Boot runs under our own keys, so only a binary we
signed boots, and boot entries cannot override the embedded command line.

1. The processor measures what booted and signs a quote over it.
2. The trust domain sends that quote, with its boot log and a fresh public key,
   to the customer's key server.
3. The key server checks the quote and releases the credential only to an
   approved release, encrypted to that key and signed with its own identity.
4. The query runs inside the trust domain, against the customer's own database
   or API, under the scope the customer set.
5. The answer leaves with a quote bound to that exact request.

Two attestations happen and they prove different things. The first controls
access to the secret. The second makes an individual answer checkable by someone
who was not party to the first.

The answer binding matters as much as the release. A valid signature over the
wrong claim is still the wrong claim, so the quote's `REPORT_DATA` is a hash
over the canonical answer, the caller's nonce, the key server's identity and the
TLS key the answer was served under. Changing any of them breaks the proof.

**TLS ends inside the trust domain.** The image makes its TLS key in memory and
binds it into the attestation; the customer's key server certifies only that
key. An agent that checks the certificate is talking to the approved image, not
to a proxy in front of it. Captured traffic between agent and miner contained
the API key, the query and the results zero times.

The firmware is also policed. The verifier accepts only quotes whose TCB status
Intel reports as `UpToDate`, rejects debug trust domains, and accepts only
approved MRTD values.

## 4. Verification without trusting us

A quote is verified against Intel's root with Phala's dcap-qvl: the PCK
certificate chain, Intel's revocation lists, and Intel's signed TCB and quoting
enclave documents. Those documents are fetched from Intel or a caching relay
and cached; everything they contain is signed by Intel and checked, so a relay
cannot vouch for a machine Intel does not.

Then the boot log is replayed into the registers the quote signs. The replay
has to match exactly, and the log must show Secure Boot on, our certificate in
the signature database, and an approved release loaded. A log that does not
replay is rejected, whatever it claims.

The same checks run in three places: the validator, the customer's key server
before it releases a credential, and `scripts/check_miner.py`, which a customer
runs against a miner before trusting it. A fourth copy runs in a browser:
**sentinelsubnet.com/verify** takes a pasted answer and runs every check
locally, with the approved list fetched from the public repository. It is
tested against the Python verifier on the same captured answers.

## 5. The approved list

A verifier needs to know which releases are approved. On AMD this was the
hardest unsolved problem in running the network, because the measurement was
not derivable from source: the same disk on two hosts measured differently.

On TDX it is derivable. The release measurement is the Authenticode SHA-384 of
the signed boot file, the same on any host, and the build is reproducible: two
independent builds of the same commit produced the same measurement. So anyone
can rebuild a release and check that the published value is honest, rather
than take it from whoever published it.

The registry carries it. A manifest on chain holds a SHA-256 of the approved
list and an **effective block height**; the list itself is served as a file and
checked against that digest. The effective height means every validator switches
at the same block rather than whenever it polled, and block-pinned reads mean
two validators polling seconds apart see identical bytes. A change takes effect
720 blocks (about 2.4 hours) after it is published, so miners and validators see
it coming.

Each entry carries the recipe that produced it: the image, the commit, the
machine type. Whoever controls the list controls who can mine, and publishing
the recipe is how that power is made checkable instead of hidden.

In practice: five releases have gone through this, v1 to v5. Moving the subnet
from v3 to v5 on 2026-11-12 took one machine at a time, each scored 1.00 by the
validator before the next, then a list with v5 alone.

## 6. Incentive mechanism

Validators challenge miners with a fresh nonce about every 22 minutes, verify the
attestation, and score five axes: attestation, cache hygiene, nonce discipline,
correctness and latency. Weights are submitted under timelock commit-reveal, so
no validator can copy another's round before it reveals.

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
On AMD it was the only thing that caught a miner running edited code. On TDX,
edited code fails the attestation gate itself, and consensus is a second line.

## 7. Results

Full method and numbers for each are in `docs/results.md`, with the raw
evidence under `docs/evidence/`.

**Simulated rounds.** Nine miners, two honest, one honest but slow, and six
attacks: a backdoored image, a replayed report, a corrupt signature, fabricated
rows, cacheable attested replies, and an unreachable endpoint.

```
detection rate                   100.0%
caught by the expected cause     100.0%
false rejections                 0  (0.0%)
honest mean weight               1.0000
degraded (slow) mean weight      0.8874
dishonest mean weight            0.0000
```

Every attacker in that field was written by us, so it shows the defences catch
what we anticipated. In September an independent operator running their own
validator found a defect we had not: the miner checked a caller's signature but
not whether that caller was permitted. Fixed and deployed the same day.

**On Intel TDX hardware, November 2026.**

| Date | Experiment | Result |
|---|---|---|
| 2026-10-05 | The command-line change that left the AMD measurement identical | Moved two TDX registers |
| 2026-11-06 | One character changed in the signed boot file's command line | Different measurement, identical across two zones |
| 2026-11-06 | A boot entry overriding the command line | Accepted with Secure Boot off; ignored under our keys |
| 2026-11-06 | Unsigned and Microsoft-signed binaries | Refused under our keys |
| 2026-11-06 | One file changed on the root filesystem | Refused by the kernel; the miner never served |
| 2026-11-06 | Two independent builds of one commit | Same measurement |
| 2026-11-07 | An operator relaying all traffic to the key server | Credential seen zero times |
| 2026-11-07 | A miner pointed at the operator's own key server | Refused by the customer's check |
| 2026-11-08 | Captured agent-to-miner traffic | API key, query and results seen zero times |
| 2026-11-10 | API key held in the enclave, off-list requests | Key never in a response; off-list refused |
| 2026-11-12 | Subnet moved to v5, then to a v5-only list | Every round since: all three miners 1.00 |

**A gap we found in our own work.** Until v5, each answer named its TLS key but
the processor did not sign the name, so a proxy could have renamed it in the
proof. Agents set up as our pilot guide describes were never exposed, because
their certificate check pins the key. Fixed in v5, tested on hardware, recorded
as part of T25 in the threat register.

## 8. Operating confidential hardware

**The image has no shell.** No SSH, no guest agent, no login. What an operator
chooses (their hotkey, who may call them, the approved values the miner checks
itself against) arrives as instance metadata, read as data and never as code:
unknown keys, wrong types and values that look like flags are refused, and the
miner does not start. Upgrading means booting the next release, not editing the
running one.

**Capacity and cost.** A TDX miner is a `c3-standard-4`, about $168 a month on
demand from Google's list prices on 2026-11-06. TDX machines cannot live
migrate, so they restart after host maintenance; the miner comes back on its
own.

**Firmware rotates.** Google updated its TD firmware between October and
November, changing MRTD. The approved list holds overlapping firmware values
for exactly this, and a rotation is a list update, not an outage.

**Lessons carried over from AMD.** Attestation can die while the process lives:
on SEV-SNP a timed-out request to the security processor disabled the guest's
message key until reboot, and health served cached identity for ten hours. On AMD, health
now asks the hardware on every check and fails closed.

## 9. What is not built

Stated plainly, because a reader can check the repository in minutes.

**We hold the signing key.** The approved list means "images we signed". The
builds are reproducible, so the list is checkable, but no one outside has
rebuilt a release and compared yet. Moving the key to an arrangement we do not
solely control is open.

**Google's TD firmware is approved as observed.** MRTD covers the firmware
Google ships; we approve the values we see on their machines and do not build
that firmware ourselves.

**Independent miners.** Every miner on 554 is ours. Consensus between three
machines we run is not consensus between independent operators. The mining
guide (`docs/mining.md`) exists to change that.

**Custody on the subnet.** Subnet miners release the test database credential
to themselves. That proves the mechanism, not custody. Custody comes from a key
server the customer runs, which is how the pilot deployment works.

**Agents that trust only public certificate authorities.** The certificate
comes from the customer's own authority, so a hosted agent platform that cannot
add one cannot connect to a miner yet.

**Correctness beyond consensus.** Correctness is decided by miners agreeing with
each other, which requires identical data. Real customers break that by
definition.

**Payment, collateral and slashing.** Not implemented. Section 11 has the
design. Dishonesty costs a miner its weight and nothing more.

**External security review.** None yet. The scope is the image and its build,
the key server, and the verifier.

**AMD SEV-SNP.** The gap described in v1.0 stands on AMD: the launch
measurement covers the firmware and nothing above it, so an operator with root
can change the code without changing the measurement. That is why the subnet
requires TDX. The AMD verifier is kept and tested.

## 10. Limiting what a caller can read

Attestation decides which code runs. The allowlist decides who may call.
Read-only decides whether they may write. None of those limit the scope of a
read.

Scopes do. Each is its own credential, released by its own attestation and
exposed as its own tool. A database scope is a restricted role, exposed as
`<scope>.query`; `docs/scoping.sql` is a worked example of the views and roles a
DBA creates. An API scope is a key plus the methods and paths it may be used
for, exposed as `<scope>.request`; anything off the list is refused before the
key is used, and the key never appears in a response.

This is also the answer to "how does the system know which data is sensitive". It
does not, and it does not need to: data out of scope is unreachable rather than
merely unrequested.

Callers who are not on Bittensor authenticate with an API key rather than a
hotkey signature. Only digests are stored, comparison is constant time, and a
rejected key never falls through to the signature path. A bearer token carries
no replay protection, unlike a signed request; an operator should choose it
knowingly.

## 11. Payment, as designed and not as built

> **None of this section is implemented.** It is included because a subnet that
> intends to earn external revenue rather than farm emissions owes a reader the
> mechanism it means to use.

The intent is per-query settlement over **x402**, so that reaching a tool costs
a few cents at the moment of use rather than a contract and an onboarding cycle.
A gateway sits between the agent and the trust domain and handles settlement, so
the miner is never in the payment path:

```
agent                 gateway                trust domain         customer system
  │  POST tool call      │                      │                      │
  │ ───────────────────► │                      │                      │
  │  402 Payment Required│                      │                      │
  │ ◄─────────────────── │                      │                      │
  │  retry + payment     │                      │                      │
  │ ───────────────────► │ verify + settle      │                      │
  │                      │ ──────────────────►  │  execute              │
  │                      │                      │ ───────────────────► │
  │                      │                      │ ◄─────────────────── │
  │                      │                      │  quote + answer       │
  │  200 + result + proof                       │                      │
  │ ◄─────────────────────────────────────────  │                      │
```

**Miner collateral** belongs to the same unbuilt layer: stake posted on chain
and slashed when a miner is caught. On TDX this design is sound in a way it was
not on AMD, where a tampered application left the measurement unchanged and so
could not have been slashed for.

**Why none of it is built yet.** A payment rail meters demand, and there is no
demand to meter yet. The self-hosted deployment in the next section needs none
of it: a customer running Sentinel over their own systems pays under a
contract.

## 12. Two deployment shapes

**Pilot, for one customer.** One script boots an approved release on TDX
against a key server the customer runs on their own machine. Their agent calls
the miner with an API key; the customer checks the miner with `check_miner.py`
before trusting it. Only the customer's ranges reach the port. Rehearsed end to
end against a real Postgres database (`docs/pilot-install.md`).

**Subnet.** Independent operators run trust domains and validators challenge
them. This is where decentralisation earns its place: if one company operated
every machine, the customer would be trusting that company, which is what the
product exists to remove.

The decentralised case pays when the data owner and the agent owner are different
parties who do not trust each other. Where they are the same party, a single
trust domain is sufficient and simpler.

## 13. Reproducing the claims

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet
cd sentinel-subnet
python -m pytest -q                                   # 483 passing
python -m pytest tests/test_tdx_verifier.py tests/test_verify_page.py -q
python scripts/benchmark.py --rounds 100              # the table in section 6
btcli subnets metagraph 554 --network test
```

Captured TDX quotes, boot logs and Intel's signed documents are committed as
fixtures, so the hardware verification re-runs without hardware. To check a
real answer in a browser, open **sentinelsubnet.com/verify** and load the
sample. To check a release, build it (`image/release.sh build` on its commit)
and compare the measurement with `measurements.json`.

The approved list is `measurements.json`, its on-chain hash is published by the
subnet owner, and known threats are in `docs/threat-register.md`.

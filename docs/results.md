# Validator results

*100 rounds, 1000 challenges, re-run 2026-10-04. Reproduce with:*

```bash
python scripts/benchmark.py --rounds 100
```

One passing round proves a mechanism exists. It says nothing about how often it
works, whether honest miners get wrongly rejected, or how cleanly the two
populations separate. These are rates.

The subnet these components run on is public: **netuid 554** on Bittensor
testnet (`btcli subnets metagraph 554 --network test`).

---

## The field

Two honest miners, one merely slow, six ways of being dishonest that this design
defends against, and one it does not, each isolated so that a failure names one
specific defence rather than a vague "something was wrong".

| Miner | Behaviour | Defence under test |
|---|---|---|
| `honest-a`, `honest-b` | correct | baseline |
| `slow` | honest, answers ~900 ms late | latency scoring |
| `backdoored` | boots a different image | launch measurement |
| `replay` | reuses a stale attestation | nonce binding |
| `malformed` | returns a corrupt signature | signature verification |
| `fabricator` | approved image, invents rows | consensus correctness |
| `exfiltrator` | approved image, correct rows, leaks what it reads | **none** |
| `cacheable` | allows attested replies to be cached | cache hygiene |
| `unreachable` | does not answer | liveness |

Two honest miners rather than one, so consensus has a majority that is not a
single voice, and nine verified miners in total, which is well above the three the
correctness gate needs before it will gate anything. Every round issues fresh nonces; nothing carries between rounds.

---

## Results

| Miner | Verified | Caught | By expected cause | Mean weight | p50 latency |
|---|---|---|---|---|---|
| honest-a | 100.0% | 0.0% |: | **1.0000** | 1 ms |
| honest-b | 100.0% | 0.0% |: | **1.0000** | 1 ms |
| slow | 100.0% | 0.0% |: | 0.8873 | 908 ms |
| **exfiltrator** | 100.0% | **0.0%** | : | **1.0000** | 1 ms |
| cacheable | 100.0% | 100.0% | 100.0% | **0.0000** | 1 ms |
| fabricator | 100.0% | 100.0% | 100.0% | **0.0000** | 1 ms |
| backdoored | 0.0% | 100.0% | 100.0% | **0.0000** | 1 ms |
| replay | 0.0% | 100.0% | 100.0% | **0.0000** | 1 ms |
| malformed | 0.0% | 100.0% | 100.0% | **0.0000** | 2 ms |
| unreachable | 0.0% | 100.0% | 100.0% | **0.0000** |: |

```
detection rate                   100.0%
caught by the expected cause     100.0%
false rejections                 0  (0.0%)
UNDETECTED BY DESIGN             1 miner, mean weight 1.0000
honest mean weight               1.0000
degraded (slow) mean weight      0.8873
dishonest mean weight            0.0000
worst honest / best dishonest    1.0000 / 0.0000
```

## Read the 100% before you read anything else

**`exfiltrator` scored full marks and is dishonest.** It runs the approved
measurement and returns correct rows, so every defence here passes it, while it
leaks what it reads. Consensus will never catch it, because its answers are right.
It is in the field deliberately: a detection rate computed over a population
chosen to be fully detectable is a statement about the population, not about the
design.

So `detection rate 100.0%` means *of the attacks this design defends against,
every one was caught*. It does not mean the design is complete. The gap is
`T23` in `docs/threat-register.md`, and it is bounded by credential scoping rather
than detected.

**Two further things not to read into this table.** `backdoored` boots a
*different image*, so it reports a different launch measurement and attestation
rejects it. An operator modifying application code inside the approved image
changes no measurement at all, because the measurement covers boot state and not
the root filesystem. That attack is `fabricator`, and what catches it is consensus,
not attestation.

Which leads to the second thing: consensus needs
`MIN_MINERS_FOR_CORRECTNESS_GATE = 3` verified miners before it gates anything, so
below three miners `fabricator` would score 1.0000 too. This benchmark has nine verified.
**Testnet 554 has had two**, so the defence that catches the realistic attack has
never fired in production. Arming it needs a third enclave, and that is why the
count matters more than it looks.

**Detection was perfect and correctly attributed, within the attacks this design
defends against.** Every such dishonest miner was caught in all 100 rounds, and
each was caught by the defence intended to catch it, a miner failing for the wrong reason would be a bug wearing a success as a
disguise, so the harness checks the cause, not just the outcome.

**No honest miner was ever rejected.** Zero false positives across 1000
challenges, including the slow one, which is the case most likely to be
mistreated by an aggressive rule.

**Attestation failures cost everything.** `backdoored`, `replay`, `malformed`
and `unreachable` all score exactly zero. Attestation gates the weight rather
than contributing to it, so a miner that cannot prove its enclave earns nothing
regardless of how fast or well-behaved it otherwise is.

---

## The rubric was wrong, and what fixed it

**Earlier runs of this same benchmark had the populations overlapping.**
`cacheable` averaged 0.9500 and `fabricator` 0.8000, against the honest-but-slow
miner's 0.8872. Both cheats outranked an honest miner with a slow link. Being
dishonest cost less than being far away.

Detection was never the problem: *both were caught 100% of the time*, then and
now. The penalty was. Getting caught forfeited only the points for the axis that
caught you, so a cheat kept the other 95%.

**The fix was to stop averaging two different kinds of question.** Whether a
miner cheated is a yes or no. How good it is is a matter of degree. So the
integrity axes gate and only quality scores:

- **Attestation, cache hygiene and nonce discipline gate.** Each is a
  deterministic fact about a single response, measured directly rather than
  voted on, so there is no noise to smooth and nothing to average. Fail one and
  the miner earns nothing.
- **Correctness gates only once a round has three or more verified miners.** It
  is decided by majority, and a majority of one is just a miner agreeing with
  itself. Below three, a disagreement is a tie rather than evidence, so
  correctness stays as points.
- **Latency still scores.** Being slow is a quality problem and should cost
  points, not everything.

That last split is what took time to see. The reason the fix stalled was the
worry that consensus correctness is probabilistic, so gating it would punish an
honest miner for one unlucky epoch. True, and it does not apply to cache hygiene
or nonce discipline, which are not votes. Those could have been gated
immediately, and separating them from correctness is what unblocked it.

**Both rubrics are still computed.** Every round logs the new weight and what
the old one would have paid, so a miner that behaves in a way the old rubric
rewarded shows up in the record with a number attached rather than as an
argument.

## What these numbers still do not show

**Attestation in this benchmark is `MockSilicon`.** These numbers measure the
challenge-verify-score protocol, which is what catches each attack. Real
hardware changes where a signature originates, not whether a mismatched launch
measurement is detected.

The real SEV-SNP path is no longer hypothetical: as of 2026-08-31 a genuine
report captured from an AMD EPYC 7B13 verifies end to end, VCEK → ASK → ARK →
report signature, against AMD's root, offline. That report and AMD's real
certificate chain are committed under `tests/fixtures/`, so the verification
runs in CI on every push and can be confirmed without any hardware.

What is still true is that the miners on netuid 554 run the mock, so the two
halves have not yet been joined on a live subnet.

**A single validator, a small field, one machine.** Latency figures are
loopback and say nothing about the internet. Nine miners is not a network.

---

## Reproducing

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet
cd sentinel-subnet
python -m venv .venv && .venv/bin/pip install pytest -r requirements.txt
.venv/bin/python scripts/benchmark.py --rounds 100
```

Full per-miner output is written to `results.json`. The suite behind it is 167
tests, weighted toward the refusals, green on every push.

---

## The correctness gate firing on real hardware, 2026-10-04

Everything above is `scripts/benchmark.py`, nine simulated miners in one process.
This is netuid 554 with three real enclaves, and it is the first time the
correctness gate has executed in production, because the gate needs
`MIN_MINERS_FOR_CORRECTNESS_GATE = 3` verified miners and 554 had one serving
miner until today.

Three miner processes on one AMD EPYC 7B13 confidential VM, chip
`1D1F823A4C32…E40B`, all reporting launch measurement `ccdc5cf01ba2…26fa`:

| uid | port | code |
|---|---|---|
| 1 | 8091 | the production miner, unmodified |
| 3 | 8092 | unmodified, second checkout |
| 4 | 8093 | **`/opt/sentinel-tampered`, query tool patched to return rows that never came from the database** |

The tamper is the attack an operator would actually run: edit the served code on a
machine you control. It changes no launch measurement, because the measurement
covers boot state and not the root filesystem. Reproduce it with
`scripts/tamper_checkout.py` against a copy of the deployment; the tampered tree
was deleted afterwards rather than left on the miner host.

The extra miners are permanent, as `sentinel-miner@8092` and `sentinel-miner@8093`
from `deploy/sentinel-miner@.service`, so the gate stays armed across restarts
rather than only during a demonstration. Verified by rebooting the host: all three
instances came back, the measurement was unchanged, and `dmesg` showed only the
driver's boot line. That last part was the thing worth testing rather than
assuming, because boot is when three processes contend for the SEV firmware
channel at once, and concurrent requests there permanently disable the VMPCK.
Three miners on one chip is only safe because of the lock in `/run/lock`, which
had itself been inactive in production until the same day.

One validator round, dry run so no weights were submitted:

```
sentinel.chain: discovered 3 serving miners on netuid 554
sentinel.validating: uid=1 verified=True weight=1.0000
sentinel.validating: uid=3 verified=True weight=1.0000
sentinel.validating: uid=4 verified=True weight=0.0000
sentinel.validating: uid=4 scored 0.8000 under the old rubric and 0 under the new
  one; gates: attestation=1.00 cache=1.00 nonce=1.00 correctness=0.00
sentinel.validator: uid=4   attest=1.00 latency=1.00 correct=0.00 cache=1.00
  nonce=1.00 weight=0.0000
sentinel.validator: dry run, not submitting: {1: 0.5, 3: 0.5, 4: 0.0}
```

### The line that matters is `uid=4 attest=1.00`

The tampered miner **passed attestation on genuine AMD silicon**. `verified=True`.
Its VCEK chained to AMD's root, its measurement matched the approved one, its
nonce was fresh. Every hardware check said yes, while it served fabricated rows,
because editing a file on the root filesystem changes nothing the chip measures.

So this is one round that demonstrates both halves honestly:

- **Attestation cannot detect modified application code.** T23. Anyone who reads
  "the chip checks the code" into this project is reading something we do not
  claim.
- **Consensus can, and did.** `correctness=0.00` zeroed it while the two honest
  miners agreed. That is what makes mining not worth gaming for emissions.

### What this does not show

**Sybil resistance.** Three miners on one chip, all ours. Consensus among three
processes we control is not independent verification, and a majority we own could
agree on anything. What it establishes is that the gate fires and that the
mechanism zeroes a liar, not that the majority cannot be bought.

**Protection against a quiet attacker.** `uid=4` was caught because it lied about
the data. An enclave running tampered code that returns *correct* rows while
leaking them passes this round with 1.0000, which is the `exfiltrator` row in the
benchmark above and `T23` in the register.

---

## What the launch measurement covers, measured rather than argued, 2026-10-04

The documents used to say that a dm-verity root hash on the kernel command line
would not help "because the command line is not covered". That was reasoning about
the boot chain, not a result, and two published documents leaned on it. So it was
tested, with `scripts/probe_measurement_scope.sh`.

Method: add an inert kernel parameter, reboot, compare the measurement. The
parameter went into `/etc/default/grub.d/99-sentinel-measurement-probe.cfg`,
numbered to sort after GCP's own `50-cloudimg-settings.cfg`, which otherwise
overwrites `GRUB_CMDLINE_LINUX_DEFAULT` wholesale. Confirmed in all six generated
boot entries before spending the reboot, so that an unchanged measurement could not
be an artifact of GRUB ignoring the file.

Command line before:

```
BOOT_IMAGE=/boot/vmlinuz-6.8.0-1069-gcp root=PARTUUID=92cd8db3-… ro
  console=ttyS0,115200 panic=-1
```

and after:

```
BOOT_IMAGE=/boot/vmlinuz-6.8.0-1069-gcp root=PARTUUID=92cd8db3-… ro
  console=ttyS0,115200 sentinel.probe=1 panic=-1
```

Measurement before and after:

```
baseline: ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa
now:      ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa
```

Identical. **The kernel command line is not in the launch measurement.**

Taken with the boot chain on this host, which is shim then GRUB then kernel, all
read from the disk after launch, with Secure Boot disabled, this establishes what
`ccdc5cf0…26fa` actually attests: a genuine AMD processor, running SEV-SNP at
VMPL0, in a particular firmware state. It is not a statement about the kernel, the
initrd, the command line, the bootloader, or the root filesystem, and therefore not
about the application either.

So `T23` is not closed by enabling dm-verity, because the hash would sit somewhere
unmeasured. The boot chain itself has to change, so that kernel, initrd and command
line hashes are folded into the measurement before the guest runs: measured direct
boot, or a unified kernel image measured before launch. Whether that is available on
this provider for a confidential VM is the open question. The guest's vTPM does
measure the chain into PCRs, but the host emulates it, and the threat model does not
trust the host.

The three miners stayed up throughout, because the measurement did not change and so
nothing failed closed. Had it changed, every instance would have exited rather than
serve under a value nobody approved, which is the behaviour you want from this
experiment going the other way.

---

## Intel TDX measures what AMD SEV-SNP does not, 2026-10-05

The same experiment that showed the kernel command line is absent from the
SEV-SNP launch measurement was run on an Intel TDX confidential VM, on the same
cloud and the same project: `c3-standard-4`, `--confidential-compute-type=TDX`,
us-central1-a, Ubuntu 24.04. The guest reported `tdx: Guest detected`,
`Memory Encryption Features active: Intel TDX`, and exposed `/dev/tdx_guest` and
the ConfigFS TSM interface at `/sys/kernel/config/tsm/report`.

An 8000-byte quote was read from `provider=tdx_guest`, before and after adding a
single inert kernel parameter (`sentinel.probe=1`) and rebooting.

| Register | Before | After | |
|---|---|---|---|
| MRTD | `c1ee9c16…70a5` | `c1ee9c16…70a5` | unchanged |
| RTMR0 | `2eccde06…61c9` | `2eccde06…61c9` | unchanged |
| RTMR1 | `0ce9ed87…095e` | `28d79edd…0129` | **changed** |
| RTMR2 | `05625e4f…3df6` | `0af57d4d…3448` | **changed** |
| RTMR3 | all zero | all zero | unused |

**One kernel parameter moved two registers that are carried inside the
hardware-signed quote.** MRTD is the build-time measurement of the initial trust
domain and correctly did not move; RTMR0 covers firmware and configuration and
also did not move.

Compare with the AMD result on the same cloud, where the identical change left
the launch measurement byte-identical. **Intel TDX on Google Cloud measures the
guest boot chain in hardware-rooted attestation. AMD SEV-SNP on Google Cloud does
not.**

### Why this matters more than it first appears

On SEV-SNP the recommended fix, a dm-verity root hash passed on the kernel
command line, is worthless, because the command line is not measured and the hash
would be as forgeable as the filesystem it describes. On TDX the command line
**is** measured, so that hash is anchored. The standard approach becomes viable
on a platform we already use.

### Honest limits of this result

**Runtime extension was not available.** This kernel (7.0.0-1011-gcp) exposes
`/sys/kernel/config/tsm/report` but no `rtmr` interface, so a process cannot
extend a measurement of itself into RTMR3 from userspace. That is a smaller
problem than it sounds: if the application is covered by the measured boot chain,
through a dm-verity root hash on the measured command line or a unified kernel
image, then RTMR1 and RTMR2 already cover it and no runtime extension is needed.

**Measurement is provenance, not honesty.** A correctly measured application can
still contain an exfiltration path. This closes T23. It does not close the
`exfiltrator` case above, and nothing in any platform does.

**The signature was not verified here.** This experiment establishes what the
quote measures, not the Intel PCK chain. Verifying a TDX quote end to end against
Intel's roots is separate work, equivalent to what `sentinel/sevsnp/` already does
for AMD.

## TDX feasibility spike: are the measurements pinnable? 2026-10-05

Knowing TDX measures the boot chain is not enough to build on. The operational
question is whether a value can be computed once, published, and matched by every
honest miner. On SEV-SNP the answer was no: the measurement changed when the
miner moved between zones, because host firmware is folded in, which is why the
measurement registry exists at all.

Three TDX VMs, identical machine type, image and configuration:

| VM | Zone |
|---|---|
| `sentinel-tdx-a` | us-central1-a |
| `sentinel-tdx-b` | us-central1-a, different host |
| `sentinel-tdx-c` | **europe-west4-a**, different continent |

All three returned byte-identical values:

```
MRTD  = c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5
RTMR0 = 2eccde064b5da2462c73d3a51fbc22ce6ed4559f62b6ebbca3d37b4d0d3daa9854fb1024990b6044114ce5edfca061c9
RTMR1 = 0ce9ed8770bb1184759929745f9aa80efa687c68b05bde3bd58853c8005c5fda887fe955b48572f0b5ca6964191d095e
RTMR2 = 05625e4f23b67aec47d02e33d11698e14f21396b4c3285d1ceb9d03c4538bc89d755d0eadee0b58b0a80bdddc4013df6
```

**Reproducible across hosts and across continents.** The opposite of the SEV-SNP
behaviour, where one pinned value described one machine rather than a fleet.

### And a change is reproducible too

The same inert parameter (`sentinel.roothash=deadbeef`) was added to the kernel
command line on the us-central1 and europe-west4 VMs, and both rebooted:

```
RTMR1 = 28d79edd08188dcf07fe95c974f9caa32beaf29574a06970ff19a0680c24790e05b393106184dfc72804c9e5eece0129
RTMR2 = ba80a2714bb8a7c2baa1f7cf7459869d386bcb88af7cdd205638a26b72679ff61b20d6c6ac5d36bb2284e1f85fa0a42e
```

Identical on both, on different continents. So an approved value can be computed
once and will match every honest miner, which is the property the whole design
needs and which SEV-SNP did not provide.

### The nuance, recorded because it will matter later

`RTMR1` took the **same** value (`28d79edd…`) for two *different* command-line
parameters, while `RTMR2` differed between them. So `RTMR2` is the register that
tracks the command-line contents; `RTMR1` tracks kernel and boot components.

The likely reason RTMR1 moved from its baseline at all is that these images set
`GRUB_FORCE_PARTUUID` and attempt an initrdless boot, and adding a
`GRUB_CMDLINE_LINUX_DEFAULT` override changes which boot components GRUB loads.
**That explanation is inferred, not proven**, and should be confirmed before any
approved value is published, because it means RTMR1 can move for reasons that
have nothing to do with the application.

### What this means for the port

A dm-verity root hash placed on the kernel command line lands in `RTMR2`,
deterministically, identically on every host. That is the exact fix that is
worthless on SEV-SNP, and it is operationally simpler there than what we have
today, because one approved set describes the fleet.

### Availability and cost

`c3-standard-4` is listed in **67 zones**, against 12 for SEV-SNP, and TDX
instances were created without a quota request in both us-central1 and
europe-west4. So moving the subnet toward TDX widens the hardware a prospective
miner can use rather than narrowing it, which was the main worry about this path.

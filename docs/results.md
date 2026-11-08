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

## A natural experiment, 2026-10-09

Eleven days after the deliberate probe, production supplied a better version of
it without being asked.

The miner's chip stopped answering. The watchdog saw three consecutive 503s,
rebooted the host, and the miner came back unattended. That is the second time
this failure has occurred (the first was 2026-09-24) and the second time it was
recovered without anyone watching.

The reboot also picked up a kernel upgrade:

```
reboot  system boot  6.8.0-1070-gcp  Fri Oct  9 17:07   still running
reboot  system boot  6.8.0-1069-gcp  Sun Oct  4 12:03 - 17:07
```

The launch measurement after that upgrade:

```
ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa
```

Byte-identical to the value pinned on 2026-10-04, before the upgrade.

**An entire kernel binary was replaced and the measurement did not move.** The
deliberate experiment above changed one inert command-line parameter; this
changed the kernel itself. It is the same conclusion arrived at by accident, on
the production miner, with a real change rather than a synthetic one, and it is
the clearest demonstration available that the kernel is not covered.

It also means the approved measurement survives routine patching, which is
operationally convenient and epistemically alarming in equal measure: miners can
take security updates without re-approval, precisely because the thing being
updated is not attested.

## The watchdog's blind spot, 2026-11-03

Fourth chip death. The first three were recovered unattended. This one was not,
and the reason is worth recording because the failure was in the recovery
mechanism rather than the chip.

Previously the chip died while the miner was running. `/health` latched a
`GuestError`, returned 503, the watchdog counted three and rebooted.

This time it died while the miner was stopped. So the miner crashed during
startup instead:

```
GuestError: ioctl failed: [Errno 25] Inappropriate ioctl for device (exitinfo2=0x0)
```

It never bound a port, so `/health` was connection-refused rather than 503, and
the watchdog did this:

```
watchdog: health returned 000 (3/3)
watchdog: not a 503, leaving the host alone; systemd restarts the service
```

That reasoning is sound for an ordinary crash and wrong here. systemd restarted
the miner every ten seconds, it crashed every ten seconds, and nothing escalated.
A disabled VMPCK is cleared by a reboot and by nothing else, so the loop would
have continued indefinitely.

**The fix is to stop inferring the chip's state from an HTTP code.** `dmesg` says
it outright, so the watchdog now checks for `VMPCK is disabled` directly and
treats that as a reboot condition regardless of what `/health` returned.

The general lesson is the one this project keeps relearning: a guard that was
verified against the failure you had seen does not necessarily cover the next
shape of the same failure. The three successful recoveries were real, and they
quietly established confidence in a mechanism that only handled one of the two
ways the chip can die.

---

## A unified kernel image anchors the boot chain on Intel TDX, with one hole, 2026-11-06

The question from the measurement gap (T23): can a single measured image put the
kernel, the initrd and the command line into the signed quote on GCP, so that a
dm-verity root hash in that command line anchors the root filesystem? A unified
kernel image (UKI) is one EFI binary carrying all three. Two throwaway TDX VMs,
`c3-standard-4`, Ubuntu 24.04 image `ubuntu-2404-noble-amd64-v20261104a`, one in
us-central1-a and one in us-central1-b. UKIs were built with `systemd-ukify` on
host a from the image's own kernel and initrd and copied byte for byte to host b.
The only difference between UKI A and UKI B is one character of the embedded
command line (`sentinel.uki=A` against `sentinel.uki=B`).

Raw quotes, nonces and firmware event logs are in
`docs/evidence/tdx-uki-2026-11-06/`, and every claim below is asserted against
them in `tests/test_tdx_uki_evidence.py`. Guest script: `scripts/probe_tdx_uki.sh`.
Offline analysis: `scripts/tdx_eventlog.py`.

| Boot | Host | RTMR0 | RTMR1 | RTMR2 |
|---|---|---|---|---|
| Stock GRUB | a and b | `b2458d27…` | `9d18b819…` | `e7ea1a58…` |
| UKI A | a | `ee1ac051…` | `43982fac…` | zero |
| UKI A | b | `ee1ac051…` | `43982fac…` | zero |
| UKI B | a | `ee1ac051…` | `1e0824f2…` | zero |
| UKI B | b | `ee1ac051…` | `1e0824f2…` | zero |
| UKI A, command line overridden | a | `949ea24c…` | `43982fac…` | zero |

MRTD was `f21e6b48…` throughout, on both hosts.

### What held

**GCP's TDX firmware boots a custom UKI directly.** No shim, no GRUB. The serial
console shows the firmware loading `\EFI\sentinel\uki.efi` and the kernel starting
with the embedded command line.

**One changed character moves RTMR1, identically on both hosts.** Same image, same
value in two zones; one character different, a different value, again the same in
both zones. Rebuilding UKI A from the same inputs gave a byte-identical file.

**RTMR1 can be computed from the file without booting it.** Replaying the firmware
event log reproduces RTMR0, RTMR1 and RTMR2 exactly as signed. RTMR1's inputs are
fixed action strings, the boot disk's partition table, and two image loads: the
Authenticode SHA-384 of the UKI and of the kernel inside it. Both digests computed
offline from the files match the log. So an approved value can be rebuilt from
source and checked, rather than taken from whoever published it.

### The hole

**A boot entry can replace the embedded command line without moving RTMR1.** With
Secure Boot off, the stub accepted the load options of a new boot entry pointing at
UKI A. The guest booted with `sentinel.uki=EVIL`, and RTMR1 was the approved
UKI A value. A policy that pins RTMR1 alone would accept a boot with dm-verity
removed from the command line, which is T23 again by another route. Logged as T24.

It did not go unrecorded. The firmware measures every boot variable into RTMR0, and
the log shows `Boot0043`, carrying the override, among them. So pinning RTMR0
alongside RTMR1 catches this case. The cost is that the approved value then fixes
the exact set of boot entries, so provisioning has to create that set
deterministically. The cleaner fix removes the override path: Secure Boot with our
own key, under which the stub is documented to ignore load options, or a stub that
ignores them regardless. Neither has been tested here.

### Details an approved value has to fix

- **Boot disk size.** The measured partition table carries the last usable block
  and the root partition's extent, so two honest miners with different disk sizes
  would differ in RTMR1.
- **Boot variables.** Adding a boot entry moved RTMR0 from the stock value, as
  expected, since RTMR0 is the boot configuration.
- **TD firmware.** MRTD was `c1ee9c16…` on 2026-10-05 and is `f21e6b48…` now, so
  Google updated the TD firmware in between. Both zones agreed on the day. The
  registry's overlapping approved sets exist for exactly this rotation.
- **RTMR2 carries nothing under a UKI.** The stub's own measurements did not reach
  any RTMR. A vTPM is present at `/dev/tpm0`, emulated by the host, and is the
  likely destination; that was not verified.

### Honest limits

The quotes' signatures were not verified against Intel's PCK chain; that is part of
the port. No dm-verity root filesystem was built: this establishes that a hash in
the embedded command line would be measured, not that the image which carries one
boots and serves. The override test was run on one host.

### What it means for the plan

The path for closing T23 holds on GCP TDX: a UKI with a dm-verity root hash in its
embedded command line, built reproducibly, with an approved value that anyone can
recompute. It needs two things the plan did not have: closing or pinning the
command line override (T24), and a recipe that fixes the boot disk size. The two
VMs were deleted after capture.

---

## Secure Boot under our own key closes T24, 2026-11-06

The UKI experiment above left one hole: with Secure Boot off, a boot entry could
replace the image's embedded command line and RTMR1 did not move (T24). The fix
proposed there was Secure Boot under our own key, since the stub is documented to
ignore a boot entry's command line when Secure Boot is on. Tested the same day.

**Setup.** Three throwaway self-signed TEST certificates (PK, KEK, db). On a TDX
builder VM, UKI A from the experiment above was rebuilt (byte-identical to the
earlier build, on a different VM), signed with the db key using `sbsign`, and
placed at `\EFI\BOOT\BOOTX64.EFI`. The db private key was shredded on the builder,
then a custom image was made from its disk with `--platform-key-file`,
`--key-exchange-key-file` and `--signature-database-file`. A TDX VM was created
from that image with `--shielded-secure-boot`. Raw quotes, nonces, event logs and
the public test certificates are in `docs/evidence/tdx-uki-secureboot-2026-11-06/`,
and every claim below is asserted in `tests/test_tdx_secureboot_evidence.py`.

| Test | Result |
|---|---|
| Signed UKI boots under Secure Boot on TDX | Booted. Kernel: `Secure boot enabled`, lockdown active |
| Boot entry with `sentinel.uki=EVIL` as load options | Firmware booted that entry; the kernel ran with the embedded `sentinel.uki=A`. **Override ignored** |
| Unsigned EFI binary | `Security Violation`, refused, firmware fell through |
| Microsoft-signed shim (stock Ubuntu boot) | `Security Violation`, refused, because db holds only our key |
| Operator turns Secure Boot off in the VM settings | Override takes effect again, and the log records `SecureBoot=00` with no verifying key, so the policy below refuses it |

### RTMR1 cannot be pinned as a value; the log has to be read

Two Secure Boot boots of the same image gave different RTMR1 values (`f80b12e7…`
and `b868c611…`). The second came after the refused attempts, and the firmware logs
a fixed "Returning from EFI Application" and "Calling EFI Application" pair into
RTMR1 for each one. An honest miner whose first boot attempt failed would fail a
pinned value. RTMR0 has the same problem with boot entries, which operators are
free to have.

So the check is a policy over the event log, after replaying it to the signed
registers (`boot_policy` in `scripts/tdx_eventlog.py`):

- `SecureBoot` is 1;
- every image was verified by our db certificate (the firmware logs the verifying
  certificate as an authority event);
- exactly one image was loaded, and its Authenticode digest is the approved UKI;
- RTMR1 holds nothing but fixed actions, separators, the partition table and that
  image.

Boot entries and retry actions are ignored. Run against this experiment's logs, the
three Secure Boot boots pass, including the one from the override entry, and the
Secure-Boot-off boot is refused for all three reasons. Every boot from the earlier
experiment is refused too.

### Details

- **Under Secure Boot only the UKI is logged as an image.** The kernel inside it is
  not loaded as a separate image, unlike with Secure Boot off.
- **Signing does not change the measured digest.** Authenticode excludes the
  signature, so signed UKI A measures the same as unsigned UKI A.
- **The ESP is about 100 MB** on this image, so one 67 MB UKI fits. Our own image
  build will size it.

### Honest limits

Still no quote signature verification against Intel's chain, and still no dm-verity
root filesystem. The keys were test keys handled on a laptop; production keys need
a real custody plan, because whoever holds the db key decides what miners can boot.
That is a governance point for the registry as much as a technical one. The VMs and
the image were deleted after capture.

## A TDX miner scored end to end by the validator, 2026-11-06

Same day, after the two experiments above: the miner side of TDX was written
(`sentinel/tdx/guest.py`, quotes through configfs-tsm) and the validator side
(`sentinel/tdx/verifier.py`), then run together on hardware.

**Setup.** Fresh throwaway TEST Secure Boot keys. A builder TDX VM built and signed
a UKI (`c13d7aa6…`, same command line as UKI A, newer kernel), installed the miner
code on the root filesystem, and was imaged with the keys. A TDX VM booted from that
image under Secure Boot and ran `scripts/run_miner.py` brokering to itself. A
validator round ran against it. The miner's `/health` and its reply to the probe are
in `docs/evidence/tdx-miner-2026-11-06/`, asserted offline in
`tests/test_tdx_miner_evidence.py`.

**What the validator checks.** Intel's signature and TCB status through dcap-qvl
(UpToDate only), no debug TD, MRTD approved, the miner's event log replayed to the
signed RTMR0-2, the boot policy above, then the quote bound to these exact rows.

| Case | Result |
|---|---|
| Miner's own broker, before serving | Verified the quote and released the credential |
| Validator with the image, firmware and key approved | **Verified, attestation 1.0, weight 1.0, 41 ms** |
| Validator not configured for TDX | Refused |
| Image not approved | Refused |
| Firmware (MRTD) not approved | Refused |

MRTD was `f21e6b48…` again, the same value as every earlier quote on this cloud.

**One bug found only on hardware.** dcap-qvl's collateral fetch has to be created
inside a running event loop. Unit tests used committed collateral and never fetched,
so the first live run refused its own credential. Fixed, with a regression test.

### Honest limits

The root filesystem is still not measured, so the code that answered is not yet
covered by the quote: this proves the TDX path works end to end, not that T23 is
closed. That needs the dm-verity image. MRTD and the db certificate are validator
flags, not yet in the on-chain registry, and every validator must pass the same
values. The firmware is Google's: on this cloud the trust is Intel and Google, not
the miner operator. The VMs and the image were deleted after capture.

## The measured miner image: dm-verity root, reproducible, on GCP TDX, 2026-11-06

The last piece of the integrity path. `image/` builds the miner as one signed UKI
and a read-only erofs root under dm-verity, with the root hash on the UKI's
embedded command line. The firmware measures the UKI, so the quote now covers the
kernel, the initrd, the command line and, through the root hash, every file the
miner runs. Evidence in `docs/evidence/tdx-verity-image-2026-11-06/`, asserted in
`tests/test_tdx_verity_evidence.py`.

**How it is built.** mkosi 25.3, every package from one dated Ubuntu snapshot
(including the security pocket, which mkosi otherwise takes live), Python
dependencies locked by hash with no source builds, fixed timestamp and partition
seed, and the build toolchain itself built from the same snapshot. The image is
built unsigned; `image/sign.sh` signs it separately, which does not change the
digest. No SSH, no guest agent, no getty, root locked: the operator configures the
miner through instance metadata, read as data by `scripts/miner_from_metadata.py`.

| Test | Result |
|---|---|
| Two builds of commit `7e5cdea` on independent VMs in different zones, one with no cache | **Identical UKI digest `60c5a2b9…` and root hash `8d380973…`** |
| Boot on TDX under our test Secure Boot keys | Secure Boot on, root mounted through dm-verity as erofs, miner started from metadata |
| Validator round from a laptop over the internet | **Verified, attestation 1.0** |
| Image not approved / someone else's Secure Boot key | Refused / refused |
| Same disk with bytes of the miner's code changed, same keys and UKI | **dm-verity refused the blocks, the miner crash-looped and never served** |

Any later change to the miner's code or locked dependencies changes the root hash and so the digest; that is the point of measuring it. To reproduce these values, build commit `7e5cdea`.

### Honest limits

- **Test keys.** The Secure Boot keys were throwaway. Production keys need a custody
  plan, since whoever holds the db key decides what can boot.
- **Google's firmware is trusted.** MRTD is Google's TD firmware, as before.
- **Not yet registry-governed.** MRTD and the db certificate are still validator
  flags rather than registry entries.
- **The broker leg is still self-brokered here.** Credential release to a
  customer's broker with a pinned certificate and an attested key (T20, T22) is
  the next step, and only now meaningful, because the code doing the release is
  finally measured.
- **Two rough edges.** The UKI is 203 MB because the default initrd carries every
  kernel module, and the unused TPM2 units fail at boot. Neither affects the
  guarantee.
- **Exfiltration is unchanged.** Code that answers correctly while copying data
  is still invisible to scoring. What changed is that such code would now have to
  be in the approved, reproducible image, where anyone can read it.

## Sealed credential release to a customer's broker, on GCP TDX, 2026-11-07

The second critical finding: the operator chooses the miner's broker URL, so
they can put a relay of their own between the miner and the customer's broker,
let the real broker approve a genuine attestation, and read the credential on
its way back. TLS does not stop it, because the relay has a valid certificate
for its own name. And pinning the customer's certificate inside the measured
image would mean a different image, and digest, for every customer.

**What changed.** The enclave generates an X25519 key in memory and binds the
public half into the attestation it sends the broker. The broker checks the
attestation as before, then seals the credential to that key (X25519, HKDF,
AES-256-GCM) and signs the release with its own key (`sentinel/sealing.py`).
The enclave names that broker's key in every answer it attests afterwards, inside
the signed binding. A real broker refuses to release in the clear. In place of a
pinned certificate, the customer checks answers name their broker.

**Setup.** The measured image rebuilt with this code (UKI `9a009b7f…`), booted
on TDX under test Secure Boot keys. The customer's broker on a separate VM,
approving only that image, firmware and key. An operator relay on a third VM
between them, over plain HTTP, recording every byte. The credential was a
working database path carrying the marker `customer-7f3a9c41`. Evidence in
`docs/evidence/tdx-sealed-broker-2026-11-07/`, asserted in
`tests/test_tdx_sealed_broker_evidence.py`; the protocol and attacks are also
tested on sockets in `tests/test_sealing.py`.

| Test | Result |
|---|---|
| Miner unlocks through the operator's relay | Unlocked and served. **The relay's log holds the whole exchange and the marker 0 times**; the release is a sealed blob |
| Customer's validator round, expecting their broker | Verified, attestation 1.0 |
| Subnet validator round, no expectation | Verified |
| Customer expecting a different broker | Refused: answered from broker `24c9aafb…`, not ours |
| Operator repoints the miner at a broker of their own | Unlocked and served, and every answer names `1ffa0c94…`; **the customer's round refused it**, the subnet's verified it, because the claim is honest |
| Relay substitutes its own key, or a miner claims a broker it did not use | Refused (sockets and offline evidence) |

### Honest limits

- **TDX only.** On AMD SEV-SNP the code is not measured, so whoever can change
  the code can read what it decrypts. Every live miner on 554 is still AMD.
- **The customer has to check.** A subnet validator cannot know every customer's
  broker, so it verifies only that the claim is honest. Which broker is
  acceptable is the customer's call, by fingerprint.
- **Still not covered:** exfiltration by approved code (now readable in a
  reproducible image), the production key custody, and deployment.

## TLS that ends inside the enclave, on GCP TDX, 2026-11-08

T25: the credential was sealed to the enclave, but the miner served plain
HTTP, so the agent's API key and every query result crossed the network
readable, including by whoever runs the machine. TLS in front of the miner does
not fix it, since the operator would hold that key.

**What changed.** The enclave generates a TLS key in memory and binds its
fingerprint into the attestation it sends the key server, next to the sealing
key. A key server started with `--tls-ca` checks the attestation as before and
signs a certificate for that key with the customer's own CA, and refuses an
enclave that sends no TLS key (`sentinel/tls.py`). Every answer's proof names the
TLS key it was served under. `check_miner.py` requires https and refuses a
connection that did not meet that key. The measured image always serves TLS;
metadata cannot turn it off.

**Setup.** Release `sentinel-miner-v2`, built from commit `a1587cd`
(UKI `08193cb8…`), signed with the production db key, booted on TDX under
Secure Boot. The customer's key server on a separate VM, approving only that
image and firmware, with a fresh CA. The agent ran on the key server's VM and
called the miner by its internal host name, with every packet on port 8091
recorded. Evidence in `docs/evidence/tdx-tls-2026-11-08/`; the attacks are also
tested on sockets in `tests/test_tls.py`.

| Test | Result |
|---|---|
| Miner unlocks and gets its certificate | Credential released sealed; certificate issued for key `9743e342…`; serving https |
| MCP call, agent trusting only the customer CA | Answered, `isError` false. Proof names TLS key `9743e342…`, broker `26b2f9c4…`, our nonce |
| Key the connection met (`openssl s_client`) | `9743e342…`, the same key the proof names. TLS 1.3, AES-256-GCM, verify OK |
| Agent trusting only public CAs | Refused: unable to get local issuer certificate |
| Plain http to the miner | Empty reply |
| `check_miner.py --ca`, expecting our key server | Verified, attestation 1.0, correctness 1.0 |
| `check_miner.py` expecting another key server | Refused: answered from broker `26b2f9c4…`, not ours |
| Recording of the MCP call, searched for the API key, the query, the result rows, `Bearer`, the nonce | **0 matches each** (21,919 bytes recorded) |

The first boot found a bug the socket tests did not: the key server put the host
name in the certificate's common name, which is capped at 64 characters, and
GCP's internal names are longer. Fixed in `3a8fa3c` on the key server only; the
image did not change.

### Honest limits

- **The agent has to trust only the customer's CA.** An agent that accepts any
  certificate, or a public CA, can be pointed at a machine the operator runs.
  `check_miner.py` checks the key against the proof regardless.
- **Hosted agent platforms** that only trust public CAs cannot use this yet.
- **The recording is not published**, because the host name in it carries our
  cloud project ID. The counts above come from it.

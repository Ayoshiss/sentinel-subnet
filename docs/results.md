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
rather than only during a demonstration.

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

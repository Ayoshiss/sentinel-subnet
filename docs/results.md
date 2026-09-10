# Validator results

*100 rounds, 900 challenges, 2026-08-30. Reproduce with:*

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

Two honest miners, one merely slow, and six ways of being dishonest, each
isolated so that a failure names one specific defence rather than a vague
"something was wrong".

| Miner | Behaviour | Defence under test |
|---|---|---|
| `honest-a`, `honest-b` | correct | baseline |
| `slow` | honest, answers ~900 ms late | latency scoring |
| `backdoored` | runs a modified image | launch measurement |
| `replay` | reuses a stale attestation | nonce binding |
| `malformed` | returns a corrupt signature | signature verification |
| `fabricator` | invents database rows | consensus correctness |
| `cacheable` | allows attested replies to be cached | cache hygiene |
| `unreachable` | does not answer | liveness |

Two honest miners rather than one, so consensus has a majority that is not a
single voice. Every round issues fresh nonces; nothing carries between rounds.

---

## Results

| Miner | Verified | Caught | By expected cause | Mean weight | p50 latency |
|---|---|---|---|---|---|
| honest-a | 100.0% | 0.0% |: | **1.0000** | 1 ms |
| honest-b | 100.0% | 0.0% |: | **1.0000** | 1 ms |
| slow | 100.0% | 0.0% |: | 0.8874 | 907 ms |
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
honest mean weight               1.0000
degraded (slow) mean weight      0.8874
dishonest mean weight            0.0000
worst honest / best dishonest    1.0000 / 0.0000
```

The last line is the one that matters, and it used to read the other way round.

**Detection was perfect and correctly attributed.** Every dishonest miner was
caught in all 100 rounds, and each was caught by the defence intended to catch
it, a miner failing for the wrong reason would be a bug wearing a success as a
disguise, so the harness checks the cause, not just the outcome.

**No honest miner was ever rejected.** Zero false positives across 900
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

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
| slow | 100.0% | 0.0% |: | 0.8872 | 909 ms |
| cacheable | 100.0% | 100.0% | 100.0% | 0.9500 | 1 ms |
| fabricator | 100.0% | 100.0% | 100.0% | 0.8000 | 1 ms |
| backdoored | 0.0% | 100.0% | 100.0% | **0.0000** | 1 ms |
| replay | 0.0% | 100.0% | 100.0% | **0.0000** | 1 ms |
| malformed | 0.0% | 100.0% | 100.0% | **0.0000** | 2 ms |
| unreachable | 0.0% | 100.0% | 100.0% | **0.0000** |: |

```
detection rate                   100.0%
caught by the expected cause     100.0%
false rejections                 0  (0.0%)
honest mean weight               1.0000
dishonest mean weight            0.2917
```

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

## What these numbers do not show

**The populations overlap.** `cacheable` averages 0.9500 while the honest-but-slow
miner averages 0.8872. A miner allowing attested responses to be cached
currently outranks an honest miner with a slow link, which is the wrong ordering:
a cached attested response is served to someone else without the proof that
belongs to it, and that is a correctness problem, not a hygiene nicety.

`fabricator` keeps 0.8000. It passes attestation honestly, genuine chip,
approved image, and simply lies about the data, losing only the 20% correctness
axis. A miner returning fiction should not retain four fifths of its weight.

Both follow from the rubric rather than from a failure of detection: *both were
caught 100% of the time*. The defences work; the penalties are too small. The
fix is to raise those weights or gate on them, and the reason it has not been
done yet is that consensus correctness is probabilistic, a replica with lag or a
non-deterministic query can make an honest miner disagree once, so the right
correction is a moving average across epochs rather than an instant cliff. That
needs multi-epoch data from a live subnet, which 554 now produces.

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

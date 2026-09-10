# Run a Sentinel validator

About thirty minutes. No confidential hardware required: a validator *checks*
attestations, it does not produce them, so an ordinary VM or laptop is enough.

Read [mining.md](mining.md) first if you have not. A validator's job only makes
sense alongside what it is judging, and the known limitation described there
applies to what you will be verifying.

---

## What a validator actually does

Once per interval it:

1. Reads the metagraph and finds every miner advertising an endpoint. Miners are
   never configured by hand; if it is not on-chain, it is not challenged.
2. Picks a fresh random nonce and sends the same query to each miner, signed with
   your hotkey.
3. Verifies each attestation against AMD's certificate chain, offline. No call to
   AMD, no call to us.
4. Scores five axes and submits weights through Yuma.

**The nonce is the point.** The validator chooses it, so a miner cannot prepare an
answer before being asked. A reply that arrives without the right nonce bound
into its proof is not a fast miner, it is a replayed one.

**Correctness is decided by agreement, not by us.** A validator cannot know the
right answer to a query against a private database. It sends the same query to
every miner and notices who disagrees with the majority. This is also the part of
the design that does not survive real customers, and it is honest to say so.

---

## Prerequisites

- Python 3.11+ on any Linux box or Mac. No SEV-SNP needed.
- A Bittensor wallet with a hotkey registered on netuid 554.
- Testnet TAO. Registration burn is about τ0.0005.
- Stake, if you want your weights to count. See the permit note below.

---

## 1. Get the code

```bash
git clone https://github.com/Ayoshiss/sentinel-subnet.git
cd sentinel-subnet
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 2. Register a hotkey on 554

```bash
.venv/bin/btcli wallet new-hotkey --wallet <your-wallet> --wallet-hotkey sentinel-validator
```

```bash
.venv/bin/btcli subnet register --netuid 554 --network test --wallet <your-wallet> --hotkey sentinel-validator
```

## 3. Get the approved measurement

The validator needs to know which image miners are supposed to be running. It is
published in [TESTNET.md](../TESTNET.md), and a miner running anything else
scores zero on attestation.

Do not read this value from a miner. A miner reporting its own approved
measurement is grading its own homework.

## 4. Do a dry run first

Score the subnet without submitting anything:

```bash
.venv/bin/python scripts/run_validator.py \
  --netuid 554 --network test \
  --wallet <your-wallet> --hotkey sentinel-validator \
  --measurement <the measurement from step 3> \
  --once --dry-run
```

You should see each miner scored across five axes. `--once` runs a single round
and exits, `--dry-run` skips the on-chain submission. Together they let you check
your setup without spending a transaction or publishing a bad weight set.

## 5. Run it continuously

```bash
.venv/bin/python scripts/run_validator.py \
  --netuid 554 --network test \
  --wallet <your-wallet> --hotkey sentinel-validator \
  --measurement <the measurement>
```

Default interval is 22 minutes. The limit that actually bites is
`weights_rate_limit`, 100 blocks on 554, which is almost exactly 20 minutes at
12s blocks. Running at 20 would sit on that boundary and lose submissions to
block-time jitter, so the default leaves a margin. Check the subnet's own value
before changing it:

```bash
.venv/bin/btcli subnet hyperparameters 554 --network test
```

Two other parameters are worth knowing. `activity_cutoff` is 5000 blocks, about
16h40m, after which a validator that has set no weights counts as inactive. And
`immunity_period` is the same, so a newly registered miner cannot be pruned for
its first 17 hours.

For a long-lived deployment, adapt `deploy/sentinel-miner.service`. The same
`Restart=always` reasoning applies.

---

## The validator permit

Weights from a hotkey without a validator permit are rejected on-chain. Permits
go to the top validators by stake, so a freshly registered hotkey has none.

The daemon checks this every round rather than once at startup, because permits
move with stake and can be lost between rounds. If you see
`no validator permit, weights would be rejected on-chain`, that is what happened.
Stake to the hotkey and wait for an epoch boundary.

You can still run with `--dry-run` without a permit, and the scoring output is
useful on its own.

---

## Reading the scores

```
uid=1  attest=1.00 latency=0.99 correct=1.00 cache=1.00 nonce=1.00 weight=0.9983
```

- **attest** is a gate, not a weight. Zero here means zero overall, whatever else
  the miner did.
- **latency** scores full marks under 250ms and zero at the ceiling, which is
  5000ms. **Do not change this.** It is protocol rather than preference: two
  validators using different ceilings produce different weights for the same
  miner, and Yuma penalises whoever ends up outside consensus.
- **correct** is agreement with the majority of verified miners.
- **cache** is zero if the miner allowed its attested reply to be cached. A
  cached body reaches the next caller without the proof that belongs to it.
- **nonce** is scored separately from attestation, so a miner replaying an old
  report is distinguishable from one with no valid report at all.

If every miner scores zero, the daemon submits nothing rather than a uniform
distribution. Rewarding everyone equally for failing is worse than rewarding
no one.

---

## When it goes wrong

**No miners advertising an endpoint.** Either nobody is mining, or ServeAxon is
rate limited (50 blocks per neuron) and a miner has not published yet.

**Every miner fails with an attestation error.** Most likely your `--measurement`
is wrong or stale. Check it against TESTNET.md before assuming the miners are
dishonest.

**Nothing is discovered at all.** Almost always the wrong network. 554 is
testnet, so every command needs `--network test`.

---

## Feedback worth sending

- Did the scoring match what you would have judged by hand?
- Is a fixed interval right, or should it track tempo and weights_rate_limit
  from the chain instead of being configured?
- The single-pinned-measurement model means every miner must run a byte-identical
  image. Workable, or does it break the moment a cloud provider rotates an image?
- What would stop you running one of these on mainnet?

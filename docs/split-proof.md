# Proof that the broker and the enclave are separate

Everything else in this repository exercises the split inside one Python process.
The sockets are real and the refusals are real, but a single process shares
memory, so inside one the custody claim can only be asserted. The product's whole
value is that the operator of the miner's host does not possess the database
credential, and that is a claim about two machines.

This is the transcript of two OS processes. Reproduce it with:

```bash
bash scripts/demo_split.sh
```

It runs in CI on every push, so if the miner ever goes back to brokering to
itself, the build fails rather than the documentation going quietly stale.

**One honest caveat.** With no `/dev/sev-guest` the chip is `MockSilicon`,
signing in software. What this transcript proves is the custody separation and
the refusal path. It does not prove the hardware root of trust; that is proved
separately in `docs/results.md` and in the SEV-SNP tests against the real report
and real AMD certificates captured from an EPYC 7B13.

Step 5 is the one to read. Without it, "the secret is not on the miner's command
line" is not evidence of anything, so the script also runs the default
self-brokering mode and shows the secret sitting there in plain sight. That
control caught a real bug while this was being written: `ps` truncates its output
unless passed `-ww`, and the first version of step 2 was passing partly because
of truncation rather than because of the split.

Captured 2026-10-04 at commit `e41b2c0`.

```
1. The broker starts, on what would be the customer's machine
  OK  broker answering on port 8100, pid 14122
  OK  it holds the secret: 1 scope(s)

2. The miner starts holding no credential, and has to earn one
  OK  miner answering on port 8101, pid 14132
  OK  the secret appears nowhere in the miner's command line
  OK  the secret is on the broker's command line, where it belongs
  OK  broker log: released the credential to an attested enclave

3. An agent queries the miner and gets an attested answer
  tools visible to this key: {"tools":[{"name":"analytics.query","description":"Run a read-only SQL query against the 'analytics' scope inside a confidential enclave. Returns columns and rows; the response is attested.","inputSchema":{"type":"object","properties":{"sql":{"type":"string","description
  OK  the tool is namespaced to the scope the broker released
{"request_id":"demo-split-1","result":{"columns":["live"],"rows":[[1]],"row_count":1},"attestation":{"chip_id":"MOCK-EPYC-d94904f7","launch_measurement":"45728c4f72189e5fd9d8ca40769c8e5cff08e32c6bcb361154aa3ba60f0eb388838c7fc2d030849e6570b4d3de4ad60c","tcb_level":7,"nonce":"e6892db086ad7f9ec82f39c287465b20","report_data":"69431a753fabd834ff8d9c20e42a3f0d7309d501f77df0676fb0dfe90a5742a8392a36821b33
  OK  the answer carries an attestation
  OK  the response does not contain the credential

4. The negative control: the same miner, a different image
  OK  the tampered miner exited 1 instead of serving
  OK  refused for the right reason: launch measurement mismatch (code was tampered)
  OK  nothing is listening on port 8101
  OK  the refusal message does not contain the credential

5. The control: what the default does instead
  OK  self-brokering: the secret IS on the miner's command line, as expected
  OK  and the miner warns about it at startup

Broker log
2026-10-04 13:22:18,302 WARNING MOCK CHIPS TRUSTED: 1. Reports from these are Ed25519, not signed by any processor. Never point this at a real database.
2026-10-04 13:22:18,302 INFO holding a secret for scope 'analytics'
2026-10-04 13:22:18,305 INFO broker listening on http://127.0.0.1:8100, 1 approved measurement(s)
2026-10-04 13:22:19,156 INFO released 'analytics' to an attested enclave
2026-10-04 13:22:20,852 WARNING refused release of 'analytics': attestation rejected: launch measurement mismatch (code was tampered)

The miner held no credential until it proved what it booted, and the
process that checked the proof was not the process that wanted the secret.
```

## The same thing on real silicon

Everything above runs on `MockSilicon`, because CI has no `/dev/sev-guest`. That
is a fair constraint for a test suite and it was not a fair basis for calling the
split proven, so this section is the run on the hardware.

Two machines on 2026-10-04, both at commit `aa755e1`:

- broker on `sentinel-validator-1`, `10.128.0.7:8100`, bound to the private VPC
  address only, holding the secret
- a second miner process on `sentinel-miner-2`, AMD EPYC 7B13, chip
  `1D1F823A4C32…E40B`, measurement `ccdc5cf01ba2…26fa`

The production miner on port 8091 was left running throughout. The test process
used a spare port, so testnet 554 kept being served and scored.

The broker trusted **no mock chips at all**. It was started with
`--product Milan` and nothing else, so `verifier_factory` had to build a verifier
from certificates the enclave handed over, and a software-signed report would
have been refused for presenting an unknown chip.

Miner:

```
SEV-SNP guest detected, chip 1D1F823A4C3294E2B92FC45B5368A08A4D70C19141E62E7521…
brokering to http://10.128.0.7:8100; this host stores no credential for analytics
credential released to the enclave for 'analytics'
miner serving on 127.0.0.1:8092
```

Broker, on the other machine:

```
sentinel/kbs.py:242: vcek=x509.load_der_x509_certificate(leaf)
released 'analytics' to an attested enclave
```

That `kbs.py:242` line is the useful part. It only executes inside
`_verify_sevsnp`, so it is first-hand evidence that the real hardware path ran
rather than the mock one, and that the VCEK, ASK and ARK crossed the network and
chained to AMD's pinned root on a machine with no access to the miner's host.
Until this run, that path had only ever been exercised against fixture
certificates inside a single process.

Negative control, the same real chip against a broker approving a different
measurement:

```
the broker refused to release 'analytics': broker refused: attestation rejected:
launch measurement mismatch (code was tampered): got ccdc5cf01ba25526bd65503d9…
MINER EXIT: 1
```

### What this run cost, and what it found

It was blocked before it started. The SEV firmware channel is guarded by a file
lock in `/run/lock`, and `sentinel-miner.service` set `ProtectSystem=strict`
without granting that path, so the lock could not be created and the fallback
path continued silently. The live miner had been running with no cross-process
lock since deployment. Concurrent requests to the firmware permanently disable
the VMPCK until a reboot, which is what took a miner down on 2026-09-24, so
running a second attesting process on that host would have repeated the outage.

Fixed in `aa755e1` before this run: the unit grants `/run/lock`, the fallback
logs an error naming the consequence and the fix, and `tests/test_sev_guest_lock.py`
asserts against the unit file rather than only the code, because the unit was
where it was broken. Afterwards, three processes having attested, `dmesg` still
shows only the boot line and no disable:

```
[    1.589355] sev-guest sev-guest: Initialized SEV guest driver (using vmpck_id 0)
```

### Still not proven by this run

**TLS.** This went over plain HTTP inside the VPC with `--broker-insecure`, so
the transport is untested and the credential crossed the wire in the clear. That
is a smaller gap than it sounds, for the bad reason given in T22: TLS would not
have protected the credential from the miner's operator anyway.

**Custody.** Both machines are ours. What this run proves is the hardware path
across a network boundary, not that a party who cannot reach the miner's host
holds the secret. That needs someone else's machine.

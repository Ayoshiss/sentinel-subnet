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

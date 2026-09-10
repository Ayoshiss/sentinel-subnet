# Reporting a vulnerability

Sentinel invites people to break it, so it should say where to send what you find.

**Use GitHub's private vulnerability reporting**, on the Security tab of this
repository. That opens a private thread visible only to you and the maintainer.

Please do not open a public issue, and do not post it in the Discord channel,
for anything that would let someone read a credential, forge an attestation, or
extract data from an enclave. Everything else is fine in the open and the
subnet channel is the better place for it.

Expect a first reply within 72 hours. This is a one-person project, so that is a
realistic promise rather than a generous one.

## What is in scope

- Forging or replaying an attestation that a validator accepts.
- Obtaining a credential the Key Broker should have withheld.
- Reading enclave state, queries or responses from outside the enclave.
- Making an honest miner score badly, or a dishonest one score well.
- Anything that lets one neuron affect another's weights improperly.

## What is already known

Please do not spend time on these. They are real, they are ours, and they are
documented.

**The launch measurement covers the image that booted, not the application on
top of it.** An operator with root in their own VM can modify the miner after
boot and still produce a valid attestation. We tested this on our own live miner
and it scored full marks while serving fabricated data. dm-verity does not fix it
on GCP, because the kernel command line is not covered by the measurement there.

**The scoring rubric under-punishes dishonesty.** A caching cheat scores 0.95
against an honest but slow miner's 0.887. Published in `docs/results.md`.

**Correctness is decided by agreement between miners**, which is meaningless
with one miner and fragile with few. It also cannot survive real customers, where
no two miners see the same data.

**Latency is measured from the validator**, so a miner far from it is penalised
for geography rather than performance.

If you can make any of these worse than we think, or show that a fix we have
proposed does not work, that is very much worth reporting.

## What is not a vulnerability

- Testnet has no emissions, so there is nothing to steal economically.
- The subnet is open source and forkable. That is intentional.
- Miners must run a specific image. That is the mechanism, not a bug, though the
  coordination problem it creates is a fair thing to complain about.

## Credit

Tell us how you want to be credited and we will, in the commit that fixes it and
in the subnet channel. If you would rather not be named, that is fine too.

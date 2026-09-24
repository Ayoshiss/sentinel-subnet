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

**Correctness is decided by agreement between miners**, which is meaningless
with one miner and fragile with few. It also cannot survive real customers, where
no two miners see the same data.

**Latency is measured from the validator**, so a miner far from it is penalised
for geography rather than performance.

If you can make any of these worse than we think, or show that a fix we have
proposed does not work, that is very much worth reporting.

## Hardware operational limits

Not vulnerabilities, and not ours to fix. Worth knowing before you run a miner,
because both cost availability rather than confidentiality.

**A guest can lose attestation permanently while still running.** If a request
to the AMD security processor times out, the kernel driver disables the VMPCK
rather than risk reusing an initialisation vector, and nothing short of a reboot
restores it. The refusal is correct: after a timeout the driver cannot know
whether the firmware consumed that sequence number, and IV reuse would be far
worse than downtime.

Observed in production on 2026-09-24:

```
sev-guest: Detected error from ASP request. rc: -110, exitinfo2: 0x200000000
sev-guest: Disabling vmpck_id 0 to prevent IV reuse.
```

`rc -110` is a timeout. The miner had been unable to attest for ten hours.

**Which made the failure shape the real problem.** `/health` reported `ok: true`
throughout, because it served cached identity and never asked whether the chip
still answered. A miner that looks alive, stays discoverable and proves nothing
is worse than one that is plainly down. `/health` now returns **503** once a
`GuestError` has been seen, and the latch is never cleared, because the
condition it reports cannot clear without a reboot.

**Recovery is a reboot of the guest.** Restarting the service does not help;
the VMPCK is disabled for the life of the VM.

`deploy/sentinel-watchdog.sh` automates it: it polls `/health`, reboots after
several consecutive 503s, and stops after two reboots in an hour. The limit
matters more than the automation. A host with a failing security processor will
fail again immediately, and a watchdog without a ceiling turns broken hardware
into a boot loop that reads as flapping. When the limit trips it leaves the
miner down, which is louder and easier to diagnose. Move to another host.

An unreachable miner, as opposed to a 503, is left alone: systemd already
restarts the service, and rebooting the host for that would be a large hammer.

## What is not a vulnerability

- Testnet has no emissions, so there is nothing to steal economically.
- The subnet is open source and forkable. That is intentional.
- Miners must run a specific image. That is the mechanism, not a bug, though the
  coordination problem it creates is a fair thing to complain about.

## Credit

Tell us how you want to be credited and we will, in the commit that fixes it and
in the subnet channel. If you would rather not be named, that is fine too.

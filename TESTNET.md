# Sentinel on Bittensor testnet

**netuid 554**, created 2026-08-29, block 7,894,075.

| | |
|---|---|
| Network | Bittensor **testnet** |
| Netuid | **554** |
| Owner coldkey | `5DvbHKF4E8To8zhGdEfgZKSZQCAqD2xVacE9y6GQmqw1E1Ut` |
| uid 0, validator | `5H5uDA7TRyisfPLgRJaFYhVZEQ7mhKPb2mZJVwSw6UvKo3RV` |
| uid 1: miner | `5Ea1gDXZj7pJgy8b4QSh1Umotr75THFoBAQDVDT9zahpFzjK` |
| Tempo | 360 blocks (~72 min) |

## Approved launch measurement

Miners must boot this image; a miner reporting anything else scores zero on
attestation. Validators pin this value, and should take it from here rather than
from a miner, since a miner supplying its own approved measurement is grading its
own homework.

```
ccdc5cf01ba25526bd65503d95931b787b4385a3277cfe4448addf9c3e894948ae8cf7b099620e3e22717de2fb5d26fa
```

GCP image `ubuntu-2204-jammy-v20260826` on `n2d-standard-2` with SEV-SNP, AMD
Milan, in `us-central1-c`. The exact image name matters, not the `ubuntu-2204-lts`
family: the family moves, and a different image measures differently.

Read it on your own VM with:

```bash
sudo .venv/bin/python scripts/run_miner.py --print-measurement
```

### The measurement is not stable across zones, and that is a real problem

Until 2026-09-23 this file published `2d24cf96...c773`, measured in
`us-central1-a`. That value was confirmed identical across three launches on two
different chips, so within one zone it is genuinely reproducible.

Then the VM was rebuilt from a **snapshot of the same disk** in `us-central1-c`,
because `us-central1-a` and `-b` had no SEV-SNP capacity. Same image, same bytes,
same code. The measurement came back different, and the miner refused to serve,
which is the control behaving correctly.

What changed is the host side, the firmware the hypervisor loads into the guest
at launch, which the measurement covers and the operator does not control.

**The consequence is not small.** A single pinned value cannot describe a fleet
of miners. Two honest operators running byte-identical images in two zones of the
same cloud produce two different measurements, and a validator pinning one of them
scores the other zero. Everything below follows from that:

- Validators currently pin exactly one value, so today the subnet only works if
  every miner runs in the same zone of the same cloud on the same image.
- The fix is for validators to accept a **set** of approved measurements, one per
  platform and zone, published here and verifiable by anyone who rebuilds.
- Until that ships, a miner elsewhere will be refused however honest it is. This
  is tracked as open work rather than solved.

If you are running a miner and your measurement does not match, that is expected,
and it is worth saying so in the subnet channel so the value can be published
alongside this one rather than treated as a failure.

**What it does and does not cover.** It covers the image that booted. It does not
cover the application running on top of it, so an operator with root in their own
VM can change the miner's code after boot and still produce a valid attestation.
Tested, not assumed. See the honest section on sentinelsubnet.com.

## Required firmware

A measurement says the right code booted. It says nothing about the firmware
underneath it, and approved code on firmware with a known hole is still
exploitable. So there is a floor, and a report below it is refused:

```
Milan   TCB[SNP] >= 0x1D
```

That is AMD's number, not ours. [AMD-SB-3030][sb3030] (May 2026) requires
`TCB[SNP] >= 0x1D` on EPYC 7003 to mitigate CVE-2025-61971, where missing lock
bits on NBIO registers let a host-privileged attacker alter MMIO routing and
break SEV-SNP guest integrity. Reported by Benedict Schlüter, Philipp Giersfeld
and Shweta Shinde at ETH Zurich.

The floor is a constant in `sentinel/sevsnp/verifier.py`, not a per-validator
setting, because two validators on different floors would accept different
miners and Yuma penalises whichever one falls out of consensus. The miner's own
Key Broker reads the same constant, so firmware below the floor never receives
the database credential at all rather than merely scoring zero.

A downgrade cannot be faked. The VCEK is derived from the TCB version, so a chip
rolled back to older firmware signs with a different key and the certificate
chain breaks before the floor is ever consulted.

**Only SNP is floored, and that is deliberate.** AMD publishes TCB floors for the
components where one is meaningful, and for Milan that is SNP alone. Microcode
in particular cannot be floored globally: AMD patches Milan microcode per
stepping, B1 `0x0A0011DE` and B2 `0x0A001247`, and the TCB field carries the low
byte, so a fully patched B1 reports 222 and a fully patched B2 reports 71. Those
do not compare. Flooring microcode properly means reading CPUID stepping from
the report and keeping a per-stepping table; until that exists, a wrong floor
would lock out patched hardware, which is worse than no floor.

**What it does and does not prove.** It stops downgrade, and it enforces the
level AMD currently names for this product. It does not prove `0x1D` is free of
holes, only that it is the level AMD has published to date. A CVE disclosed
against `0x1D` tomorrow needs a manual bump here, and nothing yet watches AMD's
bulletins to tell us to make it.

Our own hosts report `0x1D` exactly, so the floor is met with no margin. When AMD
raises it, our miners fail their own floor until the host fleet updates, and the
correct response then is to update, not to lower the number.

Milan is the only product line with a pinned AMD root, so it is the only one
with a floor. Any other product fails earlier, at the certificate chain.

[sb3030]: https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3030.html

Verify independently:

```bash
btcli subnets metagraph 554 --network test
```

Needs **bittensor >= 11**. An older `bittensor_cli` install answers to the same
name and will fail on an unrelated OpenSSL error, so check with `btcli --version`
first, or call the one in this repo's virtualenv directly:

```bash
.venv/bin/btcli subnets metagraph 554 --network test
```

## What is running

The neurons are the same code the tests cover: miners serve attested MCP tool
calls over hotkey-signed HTTP, and the validator challenges them with a fresh
nonce, verifies the attestation, scores five axes, and submits weights through
Yuma's timelock-encrypted commit path.

## Honest status

Attestation is **mock-first on this subnet**. The real SEV-SNP path is done and
confirmed on hardware: a genuine report from an AMD EPYC 7B13 verifies end to
end against AMD's pinned root, offline, and is committed as a fixture so CI
re-checks it on every push.

What has not happened is joining the two on this subnet, the miners registered
here still run `MockSilicon`, because putting them on real silicon means
persistent confidential VMs and ongoing cost, which is deferred until there is
someone to serve. See `sentinel/sevsnp/`, `docs/hardware-run.md` and ROADMAP.md.

## Notes for anyone reproducing this

Things the chain enforces that cost time to discover:

- `burned_register` is MEV-shielded; the inner extrinsic expires if retried too
  fast. Space attempts ~30s, and use `btcli` rather than a hand-rolled
  `execute()`, which gets the nonce sequencing wrong.
- Never set `max_spend_tao` in a policy for registration, the cost cannot be
  bounded in advance, so the policy blocks the call outright.
- A new subnet has no alpha liquidity, so staking trips the slippage guard at
  any size. Bootstrapping legitimately needs `slippage_protection=False`.
- Creating a subnet auto-registers the signing hotkey as uid 0.
- Loopback axons are rejected; publish an address peers can reach.
- Validator permits are recalculated on epoch boundaries, not on stake.

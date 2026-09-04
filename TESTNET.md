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

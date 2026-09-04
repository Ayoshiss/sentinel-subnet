# Sentinel: Bittensor Mechanics v0.1

How Sentinel plugs into Yuma Consensus, configures weights, allocates emissions,
and stays sustainable under Taoflow.

## 1. Yuma Consensus compatibility

Sentinel produces a scalar weight in [0,1] per miner, the input Yuma expects.
Validators score on the rubric (attestation 40%, latency 30%, correctness 20%,
cache 5%, nonce 5%) and submit weights; Yuma aggregates via stake-weighted median
with outlier clipping. Standard Yuma with a domain-specific scoring function.

## 2. Commit-reveal

Weights are submitted under commit-reveal (v3), reveal interval one epoch. This
prevents a lazy validator from copying a competitor's revealed weights instead of
running its own attestation challenges.

## 3. ActivityCutoff & challenge cadence

| Parameter | Setting | Rationale |
|---|---|---|
| Tempo | 360 blocks | ~72 min re-attestation freshness |
| Commit-reveal | v3, 1 epoch | Prevents weight-copying |
| ActivityCutoff | Aligned to tempo | Prunes miners missing challenges |
| Max validators | 64 | Bootstrap with Lamida + diversify |
| Max miners (UIDs) | 256 | Competitive attested capacity |

## 4. Emissions allocation

Standard dTAO split: miners (majority, by attestation-quality weights),
validators (~41% class share), owner (18%, funds audits + connectors + gateway).
Emissions are the bootstrap subsidy; external customer revenue is the design
center.

## 5. Stake concentration analysis

- **Bootstrap:** Lamida's validator seeds early stake; concentration is
  intentionally high at genesis and temporary.
- **Metric:** track effective Nakamoto coefficient; raise it each epoch.
- **Path:** community validator onboarding after ~6 months, weighted to diversity.
- **Safeguard:** attestation is verifiable by anyone, so a captured validator set
  can only mis-score, not forge a valid attestation.

## 6. Taoflow impact modelling

Taoflow ties emissions to net TAO inflow, repricing emission-farming subnets
toward zero.

| Signal | Network reality | Sentinel position |
|---|---|---|
| Subnets with positive external inflow | 6 of ~128 | Built to be #7 |
| Network coverage (demand vs extraction) | ~19% | USDC → TAO buys directly |
| Inflow to reach top-5 by real revenue |: | ~$20–30K/month |
| No-revenue subnet emissions | Repriced to zero | Insulated by real inflow |

**Flywheel:** customer USDC → TAO buys into alpha pool → net inflow → Taoflow
sustains/raises emissions → more miners → more capacity → more customers. Revenue
is both income and the ranking mechanism.

## Summary

| Item | Status |
|---|---|
| Yuma Consensus compatible | Yes, scalar weights, standard aggregation |
| Commit-reveal configured | Yes: v3, 1-epoch reveal |
| ActivityCutoff set | Yes: aligned to 360-block tempo |
| Emissions allocation documented | Yes, standard dTAO split, owner 18% |
| Stake concentration analysed | Yes, bootstrap-then-diversify + Nakamoto |
| Taoflow impact modelled | Yes: revenue-as-inflow flywheel |

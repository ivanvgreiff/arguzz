# Phase III.6 — Local validation campaign (PIGGYBACK VARIANT) — Implementation Plan

**Status:** PLAN  
**Created:** Jun 4, 2026 (afternoon)  
**Depends on:** III.0 (global-aware reward), III.1 (global DB schema), III.2 (uniform-arm), III.2.5 (circuit_debug fix), III.3 (reward persistence), III.4 (run_replicates), III.5 (cold-start audit)  
**Blocks:** Phase IV.POS.0 (POS access + constraint confirmation) — III.6 is the master plan's pre-testbed gate. *(Jun 4 evening: phase name updated from "IV.0 cloud" to "IV.POS.0" per the GCP → POS testbed pivot; the gate semantics are unchanged.)*

## 1 — Why "piggyback" instead of the original §10.2 protocol

The master plan §10.2 prescribes **3 strategies × 3 seeds × 250 muts = 9 campaigns ≈ 5h wall**. That was drafted before we had:

- the **postfix 1000-mut bandit-16 campaign** (single seed=1234), which is **at production N**, on the fixed binary, with zero false positives, 87% arm-UCB — a stronger data point than any 250-mut bandit replicate would be.

Piggybacking off that existing data, III.6's real outstanding need shrinks from "9 campaigns" to **"the two missing strategies at comparable N"**: one `uniform-arm` and one `zoned` at N=1000, seed=1234, on the fixed binary. This produces:

| Strategy | N | Seed | Source |
|---|---|---|---|
| `bandit-16` | 1000 | 1234 | already done (postfix campaign, Jun 3–4) |
| `uniform` | 1000 | 1234 | **NEW** this phase |
| `zoned` | 1000 | 1234 | **NEW** this phase |

This trades **statistical replication (R=3)** for **realistic scale (N=1000) and apples-to-apples seed pairing**. Both are valid choices. ProG_Report_1.md §6.4 requires R=5 only for the **main A/B campaign (now IV.POS.5)**, not the local validation gate (§5 step 3). The testbed will then provide the full statistical answer.

**Cost**: 2 × ~6h = ~12h wall clock if sequential, or ~6h if parallel-2 (CPU permits — `risc0-host` uses 1 core, machine has 8).

**What we lose vs original §10.2 protocol**:
- Within-strategy variance can't be estimated (R=1 per strategy). For III.6 gate, this is fine: we only need to see between-strategy *direction*; within-strategy variance is what IV.POS.5 (R=5) is for.

**What we gain**:
- Direct apples-to-apples comparison at N=1000 same seed.
- ~12h instead of ~5–9h, but the existing 1000-mut campaign is already in hand (saved another ~6h vs running all 3 fresh).
- All-fixed-binary, all-post-III.0/III.1/III.2/III.3 code path validated end-to-end.

## 2 — Goals (carried from master plan §10.1, refined)

Before launching anything against the POS testbed, prove on a small local run that:

1. $F^{\text{glob}}$ is **non-empty and varies per kind** across all three strategies (Hook 3 firing as designed).
2. The reward signal **differs across arms** (`std(r)` per arm > 0; in bandit, `corr(reward, pulls) > 0.5`).
3. The three selectors produce **distinguishable distributions** of `kind` allocation.
4. SQL queries (`get_extended_contexts_for_campaign`, `get_global_contexts_for_campaign`, `get_reward_diag_for_campaign`) return non-empty sets on **post-III.3 campaigns** (uniform and zoned only; the bandit was pre-III.3 so its `mutation_rewards` is empty, which is the documented backward-compat case).

## 3 — Acceptance criteria (= pre-IV.POS gate, per amended master plan §10.4)

All must hold across the 3 campaigns:

| # | Criterion | How measured |
|---|-----------|--------------|
| 1 | All 3 campaigns succeed (no crashes; all DBs > 0 bytes; recorded mutation count = 1000) | `sqlite3` count + manifest exit codes |
| 2 | **Arm-level UCB fraction > 50%** in the bandit campaign | parse `Arm selections: X coldstart + Y UCB`; require `Y / (X+Y) > 0.5` (postfix bandit already shows 87%) |
| 3 | `corr(reward, pulls) > 0.5` at the arm level in the bandit campaign | per-arm aggregation from `mutations` JOINed with reward stream |
| 4 | $C_F^{\text{ext}}$ curves separate visibly between the 3 strategies (eyeball / one-line spread metric) | `count(DISTINCT failures.constraint_loc \|\| failures.major \|\| failures.minor)` + `count(DISTINCT global_failures.family\|\|address)` accumulated over `mutations.id` |
| 5 | $F^{\text{glob}}$ non-empty in at least 2 of 3 campaigns | `SELECT COUNT(*) FROM global_failures` per DB |
| 6 | For the bandit campaign: `std(reward) > 0` per arm (i.e. reward is not constant on any arm) | per-arm aggregation; report % arms with non-zero std |
| 7 | **Zero verifier-accepted** mutations across all 3 campaigns | (confirms circuit_debug fix holds on uniform + zoned, not just bandit) |

## 4 — Protocol

### 4.1 Pre-flight (5 min, before launching campaigns)

1. **Move backup off `/tmp`**: `mv /tmp/risc0-host.WITH_CIRCUIT_DEBUG.bak ~/arguzz_backups/`
2. **Pin the fixed binary sha256**: `sha256sum workspace/output/target/release/risc0-host > ~/arguzz_backups/risc0-host.FIXED.sha256` — used in IV.POS.1 `prepare_bundle.sh` and `run_campaign_pos.sh` to fail-loud if the bundle is built off the wrong binary. (The same hash is also referenced by the deferred `a4/cloud/Dockerfile` should we revisit Docker later.)
3. **Sanity-check `run_replicates.py`** is callable.

### 4.2 Launch (one shell command, ~10h sequential)

**Sequential (`--parallel 1`) chosen over parallel-2 after empirical CPU-contention measurement** (Jun 4 PM): a single `risc0-host` saturates ~3–4 cores; two concurrent processes oversubscribe the 8-core machine, raising per-mutation wall time from ~22s to ~55s (3× slowdown). Sequential = same total CPU but no cache thrash. **Net: ~10h sequential beats ~15h parallel-2.**

```bash
python3 -m a4.standalone.run_replicates \
  --host /root/arguzz/workspace/output/target/release/risc0-host \
  --strategies uniform zoned \
  --replicates 1 --seed-base 1234 \
  --num 1000 \
  --parallel 1 \
  --out-dir /root/arguzz/iii6_piggyback/ \
  -- --in1 5 --in4 10
```

Produces:
```
iii6_piggyback/
├── manifest.json
├── uniform/seed_1234.db   uniform/seed_1234.log
└── zoned/seed_1234.db     zoned/seed_1234.log
```

### 4.3 In-parallel work (while the two campaigns run, ~6h)

These do not depend on campaign output and have already largely been completed:

1. ✅ **IV.POS prep — pin fixed-binary sha256**: `~/arguzz_backups/risc0-host.FIXED.sha256` written (Jun 4 PM). Referenced by both `a4/pos/prepare_bundle.sh` and the deferred `a4/cloud/run_campaign.sh`.
2. ✅ **IV.POS prep — dispatcher scaffold drafted** at `a4/pos/dispatch_pos.py` (dry-run smoke verified). GCP dispatcher kept at `a4/cloud/dispatch.py` as deferred optional backend.
3. ✅ **DB retention policy decided** (CARRY_FORWARD_TO_TESTBED §G.2): keep all raw DBs forever on local archive + POS result folder; `collect_results_pos.py` pulls without deletion.
4. ✅ **Log `tau_g` per campaign** (CARRY_FORWARD §G.3): new `campaign_params` table + `_persist_campaign_params` fuzzer hook. 9 unit tests passing.
5. ✅ **III.6 validation notebook stub**: `a4/notebooks/precloud_validation.ipynb` — loads 3 DBs + 3 logs, computes the 7 acceptance criteria, renders the $C_F^{\text{ext}}(t)$ plot.
6. ✅ **POS scaffolding** (Jun 4 evening, post-pivot): `a4/pos/` with prepare_bundle, run_campaign_pos, dispatch_pos, collect_results_pos, benchmark_pos. POS access details + workflow consolidated into `POS_PLAYBOOK.md` (Jun 5 PM2).

### 4.4 Post-campaigns (≤30 min)

1. Run `analyze_campaign.py` on each new log; check no crashes, mutation count = 1000.
2. Compute the 7 acceptance criteria; produce a one-page table.
3. If all 7 pass → write `PHASE_III_6_IMPLEMENTATION_REPORT.md`, mark III.6 ✅, declare IV.POS.0 the next active phase (still externally blocked on advisor reply, but locally there is nothing more to do until the advisor responds).
4. If any fail → diagnose. Do NOT proceed to IV.POS.0/1; document in tracker §J.

## 5 — Risks + mitigations

| Risk | Mitigation |
|---|---|
| One of the new campaigns crashes mid-run | `run_replicates.py` already captures per-job exit code in manifest; we'd see it in the §4.4 check. Easy to re-run a single seed. |
| ~~Parallel-2 causes memory pressure~~ → CPU-contention oversubscribes 8 cores | **Switched to sequential** (Jun 4 PM): empirical 55s/mut at parallel-2 vs 18s/mut single-process. Net wall time 10h sequential beats 15h parallel-2. |
| Acceptance criterion #4 ($C_F^{\text{ext}}$ separation) is ambiguous | Define a quantitative spread metric: `(max - min) / mean` of final $C_F^{\text{ext}}$ across the 3 strategies. If ≥ 0.1, considered separated. |
| Postfix bandit DB lacks `mutation_rewards` rows | Acknowledged in §2.4 above — notebook falls back to `analyze_campaign.parse_terminal` for the bandit row; uniform + zoned use SQL. Both paths produce comparable numbers. |

## 6 — What this phase does NOT do

- **Does not provide statistical CIs**. Single seed per strategy. IV.POS.5 (3×5×N on testbed) is where statistical claims will be made.
- **Does not test step-level UCB activity**. Per the III.5 amendment and CARRY_FORWARD §E, step-UCB at N=1000 is structurally dead and that's accepted. The acceptance criteria intentionally do not gate on it.
- **Does not run the originally-planned 9 campaigns**. Piggyback variant chosen with user approval; cost-benefit favours the realistic-scale comparison over the small-N replicated comparison.

## 7 — Estimated effort

- Pre-flight (§4.1): 5 min ✅
- Launch (§4.2): 5 min to kick off ✅
- Wall time for both campaigns **sequential** (revised Jun 4 PM): ~10h
- In-parallel work (§4.3): 4–6h of focused work ✅ (done during initial parallel attempt + relaunch)
- Post-campaigns (§4.4): 30 min
- Report: 30 min
- **Total**: ~10h wall (most of which is unattended). Compared to original 5h master-plan estimate: about 2× longer wall, but produces a stronger result (N=1000 vs N=250 per replicate) for free since the postfix bandit is reused.

## 8 — Files this phase will produce

```
A  a4/docs/precloud/PHASE_III_6_IMPLEMENTATION_PLAN.md     (this file)
A  a4/docs/precloud/PHASE_III_6_IMPLEMENTATION_REPORT.md   (after campaigns finish)
A  a4/notebooks/precloud_validation.ipynb                  (gate-criterion notebook)
A  /root/arguzz/iii6_piggyback/                            (campaign outputs, gitignored)
M  a4/docs/precloud/PRECLOUD_MASTER_PLAN.md                (mark III.6 ✅, log decisions on §H)
M  a4/docs/precloud/CARRY_FORWARD_TO_TESTBED.md            (mark items resolved; was CARRY_FORWARD_TO_CLOUD)
```

For IV.POS.* (post-III.6):
```
A  a4/pos/prepare_bundle.sh                                (Jun 4 PM)
A  a4/pos/run_campaign_pos.sh                              (Jun 4 PM)
A  a4/pos/dispatch_pos.py                                  (Jun 4 PM)
A  a4/pos/collect_results_pos.py                           (Jun 4 PM)
A  a4/pos/benchmark_pos.sh                                 (Jun 4 PM)
A  a4/docs/precloud/POS_PLAYBOOK.md                        (single source of truth for POS, Jun 5 PM2)
A  ~/arguzz_backups/risc0-host.FIXED.sha256                (pinned hash)

(Deferred optional backend, kept for reproducibility but not in primary path:)
A  a4/cloud/Dockerfile                                     [DEFERRED — banner added]
A  a4/cloud/run_campaign.sh                                [DEFERRED — banner added]
A  a4/cloud/dispatch.py                                    [DEFERRED — banner added]
```

## 9 — In simple terms

Master-plan §10 originally said "run 9 small campaigns to validate things look right before cloud". We already have one very-large-campaign result (the postfix bandit-16 1000-mut run); rather than throw it away and run 9 new small ones, we **piggyback**: keep that result as the bandit row, add a uniform-arm and zoned run at the same N and seed, compare. This gives us a direct apples-to-apples answer at production scale for ~6 hours of wall-clock instead of 5 + 7. Statistical replication (R=5) is what IV.POS.5 is for; the local gate just needs to confirm the system isn't broken at scale. *(Note: post-pivot, IV.POS.4 is a second-stage validation on the testbed itself — distinct from this III.6 local gate, which still runs.)*

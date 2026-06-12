# Phase II.4 Implementation Report: Campaign Loop Integration

This report describes the implementation and testing of Phase II.4 (Campaign Loop Integration), deviations from the plan, key variables and functions, and insights for Phase II.5.

**Reference plan**: [PHASE_II_4_IMPLEMENTATION_PLAN.md](./PHASE_II_4_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.4 was implemented as specified. The fuzzer (`fuzzer.py`) was modified to support a new `--selector bandit` mode that runs the full coverage-guided pipeline: baseline capture, arm universe construction, pilot calibration, bandit-driven mutation selection with per-run reward computation. The CLI (`cli.py`) was updated. A 200-mutation bandit campaign completed successfully (exit_code=0, 6681s, 200 mutations, 0 crashes, 0 ACCEPTED, 23 unique constraints, 2003 distinct touched).

**Goal**: Wire all previously-built standalone components into the real fuzzer campaign loop so that `python -m a4.standalone.cli fuzz --selector bandit` executes a fully coverage-guided campaign.

---

## 2. Deviations from Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Pilot execution | Reusing _create_mutation + run_a4_mutation in a loop | Compact loop inside _setup_bandit | Cleaner: pilot self-contained rather than calling _run_single_mutation (which triggers non-bandit selector). |
| Pilot coverage merging | Iterate pilot_bitmap into coverage_state | Conditional: only set freq=1 for new buckets, max() for already-seeded | Handles baseline-seeded vs pilot-discovered buckets correctly. |
| _classify_outcome | Inline derivation | Separate reusable method | Both _run_bandit_mutation and _print_mutation_result need the outcome string. |
| No other deviations | - | - | All steps as specified |

---

## 3. What Was Implemented

### 3.1 New imports in fuzzer.py

All Phase II components: `DiscountedUCBScheduler`, `ArmUniverse`, `CalibratedParams`, `calibrate_from_pilot`, `collect_pilot_stat`, `compute_N_pilot`, `CoverageState`, `compute_reward`, `update_state`, `capture_baseline_touch`, `ZonedStepSelector`.

### 3.2 Modified __init__

When `selector_strategy=="bandit"`: `self.selector=None`, initializes `scheduler`/`coverage_state`/`arm_universe`/`_pilot_count` to None/0. Stores `selector_strategy` for branching. Non-bandit mode unchanged.

### 3.3 _classify_outcome(result) -> str

Derives outcome string ("ACCEPTED"/"CRASH"/"REJECTED"/"NO_EFFECT") from MutationResult fields. Used by both `_run_bandit_mutation` and `_print_mutation_result`.

### 3.4 _setup_bandit(num_mutations, stats)

Full bandit initialization pipeline:

1. **Baseline capture**: `capture_baseline_touch(host, args)`. Result: 1599 bitmap buckets.
2. **Arm universe**: `ArmUniverse(data, budget, MUTATION_KINDS)`. For N=200: B_count=16, B=246, 128 arms.
3. **Pilot calibration**: 30 mutations with uniform-random kind + `ZonedStepSelector`. Each run: create mutation, execute, collect `PilotRunStats`, merge bitmap, record in DB. Pilot runs count toward budget and stats.
4. **Parameter calibration**: `calibrate_from_pilot(pilot_stats, budget)`. Result: tau_T=42.0, tau_d=2.8, K_T_rare=31, gamma=0.9862.
5. **Coverage state**: Created with calibrated params, seeded from baseline, pilot incremental touch merged in.
6. **Bandit construction**: `DiscountedUCBScheduler(arm_universe, params, seed)`.

### 3.5 Modified run_campaign

Branches on `selector_strategy=="bandit"`: calls `_setup_bandit`, computes `main_budget = num_mutations - pilot_count`, runs main loop using `_run_bandit_mutation`. Mutation numbering continuous across pilot + bandit.

### 3.6 _run_bandit_mutation(mutation_num, total, stats)

Full reward pipeline:
1. `(kind, step) = scheduler.select()`
2. Retry within same bucket if `_create_mutation` fails (up to 10)
3. Execute mutation
4. Classify outcome
5. `reward, diag = compute_reward(bitmap, failures, exit_code, outcome, proof_generated, coverage_state)`
6. `scheduler.update(kind, step, reward)`
7. `update_state(bitmap, failures, exit_code, coverage_state)`
8. DB recording + touch tracking

**Ordering**: compute_reward (reads state) -> scheduler.update (uses reward) -> update_state (writes state).

### 3.7 MutationResult additions

Two new fields: `reward: float = 0.0` and `reward_diag: Optional[dict] = None`.

### 3.8 Enhanced diagnostic output

Per-run: prints `r=0.265 T_new=0.05 F_new=0.39 F_rare=1.00 Z=0 Q=0.70` when reward_diag present.

Campaign summary: appends `scheduler.summary()` showing top/bottom arms.

### 3.9 CLI update

Added `"bandit"` to `--selector` choices.

---

## 4. Campaign Results (200 mutations, seed=42, bandit mode)

### 4.1 Overview

| Metric | Value |
|--------|-------|
| Total mutations | 200 (30 pilot + 170 bandit) |
| Wall-clock time | 6681s (~111 min) |
| REJECTED | 200 |
| CRASH | 0 |
| ACCEPTED | 0 |
| Unique constraints | 23 |
| Distinct touched | 2003 |

### 4.2 Calibrated Parameters

| Parameter | Value |
|-----------|-------|
| tau_T | 42.0 |
| tau_d | 2.8 |
| K_T_rare | 31 |
| gamma | 0.9862 |

### 4.3 Mutations by Kind

| Kind | Count |
|------|-------|
| PRE_EXEC_REG_MOD | 30 |
| COMP_OUT_MOD | 28 |
| INSTR_TYPE_MOD | 27 |
| INSTR_WORD_MOD_FULL | 26 |
| LOAD_VAL_MOD | 25 |
| INSTR_WORD_MOD_SUR | 23 |
| MEM_VAL_MOD | 22 |
| STORE_OUT_MOD | 19 |

Distribution is relatively uniform (19-30), expected in a short campaign where UCB exploration dominates.

### 4.4 Bandit Arm Statistics

Active arms (N > 0.5): 61 out of 128

Top 5 arms by mean reward:
1. INSTR_TYPE_MOD bucket=12: mu=0.265
2. INSTR_WORD_MOD_SUR bucket=9: mu=0.265
3. INSTR_WORD_MOD_FULL bucket=12: mu=0.241
4. INSTR_WORD_MOD_SUR bucket=15: mu=0.240
5. INSTR_WORD_MOD_SUR bucket=11: mu=0.240

INSTR_WORD_MOD_SUR dominates top arms (6/10), consistent with II.2V findings.

---

## 5. Testing

### 5.1 Smoke test (N=5)

Completed successfully. compute_N_pilot(5)=30 consumed entire budget (main_budget=-25 handled by empty range()). Edge case works.

### 5.2 Full campaign (N=200)

Completed without errors (exit_code=0). All 200 mutations recorded. Reward diagnostics for all 170 bandit runs. Campaign summary includes bandit arm stats.

### 5.3 Existing tests

All 99 non-host-dependent tests pass. Non-bandit code path unchanged.

---

## 6. Insights for Phase II.5

### 6.1 n_min=0 with small budgets

With N=200 and 128 arms, n_min=0. Bandit relies on UCB bonus only. 67/128 arms unexplored. Larger campaigns will explore more.

### 6.2 Uniform distribution in short campaigns

Kind distribution (19-30) is nearly uniform because UCB exploration dominates in 170 rounds across 128 arms. Longer campaigns should show clearer exploitation.

### 6.3 gamma=0.9862 gives short memory

H=clamp(200//5,50,300)=50, gamma=0.9862, half-life ~50 iterations. For N=200 this may forget too fast. Larger budgets give larger H and longer memory.

### 6.4 Phase II.5 infrastructure ready

Running `--selector zoned` vs `--selector bandit` produces directly comparable campaigns. No new code needed.

---

## 7. Completion Checklist

- [x] Step II.4.1: Bandit infrastructure in A4Fuzzer.__init__
- [x] Step II.4.2: _setup_bandit method
- [x] Step II.4.3: run_campaign modified for bandit mode
- [x] Step II.4.4: _run_bandit_mutation method
- [x] Step II.4.5: reward and reward_diag fields in MutationResult
- [x] Step II.4.6: Enhanced diagnostic output
- [x] Step II.4.7: CLI --selector bandit option
- [x] Step II.4.8: 200-mutation integration test (completed, exit_code=0)

---

## 8. Variable Reference

### 8.1 New A4Fuzzer Instance Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `selector_strategy` | str | Strategy string ("zoned"/"guided"/"bandit"). Stored for branching. |
| `scheduler` | Optional[DiscountedUCBScheduler] | Bandit scheduler. None in non-bandit mode. Provides select()/update(). |
| `coverage_state` | Optional[CoverageState] | Global coverage state for reward. None in non-bandit mode. |
| `arm_universe` | Optional[ArmUniverse] | Action space. None in non-bandit mode. |
| `_pilot_count` | int | Pilot mutations executed. main_budget = num_mutations - _pilot_count. |

### 8.2 New MutationResult Fields

| Variable | Type | Meaning |
|----------|------|---------|
| `reward` | float | Bandit reward from compute_reward. 0.0 in non-bandit mode. Range [0, 1]. |
| `reward_diag` | Optional[dict] | Full diagnostic breakdown. Keys: T_new, T_rare, F_new, F_rare, Z, Q_dist, Q_rep, Q, S, r, delta_T, delta_F, d_fail, n_fail, r_rep, mode. None in non-bandit mode. |

### 8.3 _setup_bandit Key Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `baseline` | BaselineTouch | Baseline touch capture. .bitmap (65536 bytes), .distinct_buckets. |
| `N_pilot` | int | Pilot count: max(30, min(100, budget//20)). For N=200: 30. |
| `pilot_selector` | ZonedStepSelector | Temporary selector for pilot (seeded seed+1000). |
| `pilot_bitmap` | bytearray | Global bitmap during pilot. Initialized from baseline. |
| `pilot_stats_list` | List[PilotRunStats] | Per-pilot statistics for calibrate_from_pilot. |
| `params` | CalibratedParams | Calibrated parameters frozen for the campaign. |

### 8.4 _run_bandit_mutation Key Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `kind` | str | Mutation kind from scheduler.select(). |
| `step` | int | Step from scheduler.select() (may change during retry). |
| `bucket` | int | Step bucket: arm_universe.bucket_for_step(step). |
| `bucket_steps` | List[int] | Valid steps in selected arm bucket (for retry). |
| `outcome` | str | "REJECTED"/"CRASH"/"ACCEPTED"/"NO_EFFECT". |
| `reward` | float | From compute_reward. Passed to scheduler.update. |
| `diag` | dict | Reward diagnostic. Stored in result.reward_diag. |

### 8.5 Campaign Flow Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `main_budget` | int | Bandit mutations: num_mutations - _pilot_count. For N=200: 170. |
| `start_idx` | int | Offset for numbering (= _pilot_count). Pilot 1-30, bandit 31-200. |
| `mutation_num` | int | Current mutation number (1-indexed, continuous). |

### 8.6 Calibrated Parameters (frozen for campaign)

| Parameter | Value (N=200) | Type | Meaning |
|-----------|--------------|------|---------|
| tau_T (tau_new) | 42.0 | CALIBRATE | Touch novelty scaling. |
| tau_d | 2.8 | CALIBRATE | Distinct-failure penalty. |
| K_T_rare | 31 | CALIBRATE | Touch rarity top-K. |
| gamma | 0.9862 | DERIVED | Discount factor. Half-life ~50 for N=200. |
| tau_F_new | 2.0 | HARD | Failure novelty scaling. |
| K_F_rare | 2 | HARD | Failure rarity top-K. |
| r_0 | 10 | HARD | Cascade threshold. |
| tau_r | 25.0 | HARD | Cascade penalty slope. |
| c_explore | 0.25 | HARD | UCB exploration coefficient. |
| a_Tn, a_Tr, a_Fn, a_Fr, a_Z | 1.0, 0.25, 1.0, 1.0, 1.0 | HARD | Reward component weights. |

---

## 9. For Anyone New

Phase II.4 is the **integration** phase. It connects all standalone components from Phases II.0-II.3 into the real fuzzer's campaign loop. Before II.4, the bandit, reward function, pilot calibration, arm universe, and baseline touch existed as separate modules with unit tests but no connection to the fuzzer. Phase II.4 wires them into a pipeline: baseline -> arm universe -> pilot calibration -> bandit selection -> reward computation -> bandit update. The user runs `python -m a4.standalone.cli fuzz --selector bandit` for a coverage-guided campaign. This is the only phase that modifies the main fuzzer.

---

*End of Phase II.4 Implementation Report.*

# Phase II.4 Implementation Report: Campaign Loop Integration

**Reference plan**: PHASE_II_4_IMPLEMENTATION_PLAN.md

## 1. Summary

Phase II.4 was implemented as specified. The fuzzer (fuzzer.py) was modified to support --selector bandit mode with the full coverage-guided pipeline. The CLI (cli.py) was updated. A 200-mutation bandit campaign completed successfully (exit_code=0, 6681s, 200 mutations, 0 crashes, 0 ACCEPTED, 23 unique constraints, 2003 distinct touched).

**Goal**: Wire all standalone components into the fuzzer campaign loop.

## 2. Deviations from Plan

- Pilot execution: compact loop inside _setup_bandit (cleaner than calling _run_single_mutation)
- Pilot coverage merging: conditional logic for baseline-seeded vs pilot-discovered buckets
- _classify_outcome: factored into separate reusable method

## 3. What Was Implemented

### 3.1 New imports
All Phase II components: DiscountedUCBScheduler, ArmUniverse, CalibratedParams, calibrate_from_pilot, collect_pilot_stat, compute_N_pilot, CoverageState, compute_reward, update_state, capture_baseline_touch, ZonedStepSelector.

### 3.2 Modified __init__
When selector_strategy=="bandit": selector=None, initializes scheduler/coverage_state/arm_universe/_pilot_count. Stores selector_strategy for branching.

### 3.3 _classify_outcome(result) -> str
Returns "ACCEPTED"/"CRASH"/"REJECTED"/"NO_EFFECT" from MutationResult fields.

### 3.4 _setup_bandit(num_mutations, stats)
Pipeline: baseline capture (1599 buckets) -> arm universe (128 arms, B_count=16) -> pilot (30 runs, uniform random) -> calibrate (tau_T=42, tau_d=2.8, K_T_rare=31, gamma=0.9862) -> seed coverage state -> construct bandit.

### 3.5 Modified run_campaign
Branches on bandit mode. main_budget = num_mutations - pilot_count. Continuous mutation numbering.

### 3.6 _run_bandit_mutation
select() -> retry within bucket -> execute -> classify outcome -> compute_reward -> scheduler.update -> update_state -> DB record.

### 3.7 MutationResult additions
reward: float = 0.0, reward_diag: Optional[dict] = None

### 3.8 Enhanced output
Per-run: r=0.265 T_new=0.05 F_new=0.39 F_rare=1.00 Z=0 Q=0.70
Campaign end: scheduler.summary() with top/bottom arms.

### 3.9 CLI
Added "bandit" to --selector choices.

## 4. Campaign Results (200 mutations, seed=42)

- 200 mutations (30 pilot + 170 bandit), 6681s, all REJECTED
- Calibrated: tau_T=42, tau_d=2.8, K_T_rare=31, gamma=0.9862
- Kind distribution: PRE_EXEC_REG_MOD 30, COMP_OUT_MOD 28, INSTR_TYPE_MOD 27, INSTR_WORD_MOD_FULL 26, LOAD_VAL_MOD 25, INSTR_WORD_MOD_SUR 23, MEM_VAL_MOD 22, STORE_OUT_MOD 19
- Active arms: 61/128. Top arms: INSTR_TYPE_MOD bucket=12 mu=0.265, INSTR_WORD_MOD_SUR bucket=9 mu=0.265

## 5. Testing

- Smoke test (N=5): pilot consumed budget, handled gracefully
- Full campaign (N=200): exit_code=0, all mutations recorded, reward diagnostics visible
- All 99 non-host tests pass

## 6. Insights for Phase II.5

- n_min=0 with N=200 (budget < arms): UCB-only exploration, 67/128 arms unexplored
- Uniform kind distribution in short campaigns (UCB exploration dominates)
- gamma=0.9862 (half-life 50): may forget fast for N=200; larger budgets give longer memory
- --selector zoned vs --selector bandit ready for direct comparison

## 7. Completion Checklist

All 8 steps complete. 200-mutation campaign succeeded.

## 8. Variable Reference

### New A4Fuzzer fields
- selector_strategy (str): "zoned"/"guided"/"bandit"
- scheduler (Optional[DiscountedUCBScheduler]): bandit, None in non-bandit
- coverage_state (Optional[CoverageState]): reward state, None in non-bandit
- arm_universe (Optional[ArmUniverse]): action space, None in non-bandit
- _pilot_count (int): pilot mutations executed

### New MutationResult fields
- reward (float): from compute_reward, 0 in non-bandit, range [0,1]
- reward_diag (Optional[dict]): T_new, T_rare, F_new, F_rare, Z, Q, S, r, etc.

### _setup_bandit variables
- baseline (BaselineTouch): .bitmap, .distinct_buckets
- N_pilot (int): max(30, min(100, budget//20))
- pilot_selector (ZonedStepSelector): temp selector seeded seed+1000
- pilot_bitmap (bytearray): global bitmap during pilot
- pilot_stats_list (List[PilotRunStats]): fed to calibrate_from_pilot
- params (CalibratedParams): frozen for campaign

### _run_bandit_mutation variables
- kind (str): from scheduler.select()
- step (int): from scheduler.select(), may change in retry
- bucket (int): arm_universe.bucket_for_step(step)
- bucket_steps (List[int]): retry alternatives
- outcome (str): REJECTED/CRASH/ACCEPTED/NO_EFFECT
- reward (float): from compute_reward
- diag (dict): reward diagnostics

### Campaign flow
- main_budget (int): num_mutations - _pilot_count (170 for N=200)
- start_idx (int): = _pilot_count, for continuous numbering
- mutation_num (int): 1-indexed continuous

### Calibrated parameters (N=200 campaign)
- tau_T=42.0, tau_d=2.8, K_T_rare=31, gamma=0.9862 (calibrated/derived)
- tau_F_new=2.0, K_F_rare=2, r_0=10, tau_r=25.0, c_explore=0.25 (HARD)
- a_Tn=1.0, a_Tr=0.25, a_Fn=1.0, a_Fr=1.0, a_Z=1.0 (HARD weights)

- [x] Step II.4.5: `reward` and `reward_diag` fields in `MutationResult`
- [x] Step II.4.6: Enhanced diagnostic output (per-run reward line + campaign-end bandit summary)
- [x] Step II.4.7: CLI `--selector bandit` option
- [x] Step II.4.8: 200-mutation integration test campaign (completed, exit_code=0)

---

## 8. Variable Reference

### 8.1 New `A4Fuzzer` Instance Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `selector_strategy` | str | The strategy string ("zoned", "guided", or "bandit"). Stored for branching in `run_campaign`. |
| `scheduler` | Optional[DiscountedUCBScheduler] | The bandit scheduler. `None` in non-bandit mode. Populated by `_setup_bandit`. Provides `select() → (kind, step)` and `update(kind, step, reward)`. |
| `coverage_state` | Optional[CoverageState] | Global coverage state for the reward function. `None` in non-bandit mode. Seeded from baseline, updated by `update_state` after each run. |
| `arm_universe` | Optional[ArmUniverse] | The action space. `None` in non-bandit mode. Provides arm lists and step lookups. |
| `_pilot_count` | int | Number of pilot mutations that were successfully executed. Used to compute `main_budget = num_mutations - _pilot_count`. |

### 8.2 New `MutationResult` Fields

| Variable | Type | Meaning |
|----------|------|---------|
| `reward` | float | Reward from `compute_reward` for this run. 0.0 in non-bandit mode or for crash/missing-bitmap. Range [0, 1]. |
| `reward_diag` | Optional[dict] | Full diagnostic breakdown from `compute_reward`. Contains T_new, T_rare, F_new, F_rare, Z, Q_dist, Q_rep, Q, S, delta_T, delta_F, d_fail, n_fail, r_rep, mode. `None` in non-bandit mode. |

### 8.3 `_setup_bandit` Local Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `baseline` | BaselineTouch | Result of `capture_baseline_touch`. Contains `.bitmap: bytes` (65536 bytes) and `.distinct_buckets: int`. |
| `N_pilot` | int | Number of pilot mutations: `max(30, min(100, budget // 20))`. For N=200: 30. |
| `pilot_selector` | ZonedStepSelector | Temporary step selector used only during pilot (seeded with `seed + 1000` to avoid correlation with the main RNG). |
| `pilot_bitmap` | bytearray | Global touch bitmap for pilot phase. Initialized from baseline, then merged with each pilot run's bitmap. Used for `collect_pilot_stat`. |
| `pilot_stats_list` | List[PilotRunStats] | Statistics from each pilot run. Fed to `calibrate_from_pilot`. |
| `params` | CalibratedParams | Calibrated parameters from pilot. Stored as `self.coverage_state` constructor arg and passed to `DiscountedUCBScheduler`. |

### 8.4 `_run_bandit_mutation` Local Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `kind` | str | Mutation kind selected by `scheduler.select()`. |
| `step` | int | Step selected by `scheduler.select()` (possibly replaced during retry). |
| `bucket` | int | Step bucket: `arm_universe.bucket_for_step(step)`. Used for retry logic. |
| `bucket_steps` | List[int] | All valid steps in the selected arm's bucket. Used for retry. |
| `outcome` | str | Outcome string for reward: "REJECTED", "CRASH", "ACCEPTED", "NO_EFFECT". |
| `reward` | float | Reward from `compute_reward`. Passed to `scheduler.update`. |
| `diag` | dict | Reward diagnostic dict. Stored in `result.reward_diag`. |
| `exec_result` | MutationExecutionResult | Raw execution result from `run_a4_mutation`. Contains `.touch_bitmap`, `.failures`, `.exit_code`, `.combined_output`. |

### 8.5 Campaign Flow Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `main_budget` | int | Number of bandit-driven mutations: `num_mutations - _pilot_count`. For N=200, pilot=30: 170. |
| `start_idx` | int | Mutation number offset for bandit runs (= `_pilot_count`). Ensures continuous numbering: pilot 1-30, bandit 31-200. |
| `mutation_num` | int | Current mutation number (1-indexed, continuous across pilot + bandit). |

### 8.6 Calibrated Parameters (from pilot, frozen for campaign)

| Parameter | Value (N=200 campaign) | Meaning |
|-----------|----------------------|---------|
| τ_T | 42.0 | Touch novelty scaling. T_new = 1 - exp(-Δ_T / τ_T). |
| τ_d | 2.8 | Distinct-failure penalty. Q_dist = exp(-d_fail / τ_d). |
| K_T_rare | 31 | Touch rarity top-K. Average of 31 rarest touched buckets. |
| γ | 0.9862 | Bandit discount factor. Half-life ≈ 50 iterations. |
| τ_F_new | 2.0 (HARD) | Failure novelty scaling. |
| K_F_rare | 2 (HARD) | Failure rarity top-K. |
| r_0 | 10 (HARD) | Cascade threshold. |
| τ_r | 25.0 (HARD) | Cascade penalty slope. |
| c_explore | 0.25 (HARD) | UCB exploration coefficient. |
| a_Tn, a_Tr, a_Fn, a_Fr, a_Z | 1.0, 0.25, 1.0, 1.0, 1.0 (HARD) | Reward component weights. |

---

## 9. For Anyone New: What Phase II.4 Is and Why

### What

Phase II.4 is the **integration** phase. It connects all the standalone components built in Phases II.0–II.3 into the real fuzzer's campaign loop. Before II.4, the bandit, reward function, pilot calibration, arm universe, and baseline touch all existed as separate Python modules with unit tests but no connection to the actual fuzzer. Phase II.4 is where they come together.

### Why

Each previous phase built one piece in isolation:
- II.0: Baseline touch capture
- II.1: Arm universe (action space)  
- II.1.5: Pilot calibration
- II.2R: Reward function
- II.3: Bandit scheduler

None do anything useful alone. Phase II.4 wires them into a pipeline: the fuzzer captures a baseline, builds the arm universe, runs pilot mutations to calibrate parameters, constructs the bandit, then runs the main campaign with the bandit making selections and the reward guiding learning.

### How it differs

Phase II.4 is the only phase that modifies the main fuzzer. All previous phases avoided touching `fuzzer.py` to keep the system working during development. II.4 is where the investment pays off — the user can now run `python -m a4.standalone.cli fuzz --selector bandit` to execute a fully coverage-guided campaign.

---

*End of Phase II.4 Implementation Report.*

# Phase II.4 Detailed Implementation Plan: Campaign Loop Integration

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.4** (Campaign Loop Integration). It wires the `DiscountedUCBScheduler` (Phase II.3), `CoverageState` + `compute_reward` / `update_state` (Phase II.2R), baseline seeding (Phase II.0), and pilot calibration (Phase II.1.5) into the actual fuzzer campaign loop.

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites

### 1.1 What previous sub-phases delivered

| Sub-phase | Key deliverable | File |
|-----------|----------------|------|
| II.0 | `capture_baseline_touch(host, host_args) → BaselineTouch` | `baseline_touch.py` |
| II.1 | `ArmUniverse(data, budget, mutation_kinds)` | `arm_universe.py` |
| II.1.5 | `calibrate_from_pilot(pilot_stats, budget) → CalibratedParams`, `collect_pilot_stat(exec_result, global_bitmap) → PilotRunStats`, `compute_N_pilot(budget) → int` | `pilot_calibration.py` |
| II.2R | `CoverageState(params)`, `compute_reward(bitmap, failures, exit_code, outcome, proof_generated, state) → (reward, diag)`, `update_state(bitmap, failures, exit_code, state)`, `CoverageState.seed_from_baseline(bitmap)` | `coverage_state.py` |
| II.3 | `DiscountedUCBScheduler(universe, params, seed)` with `select() → (kind, step)` and `update(kind, step, reward)` | `bandit.py` |

### 1.2 What Phase II.4 implements

A new `selector_strategy="bandit"` mode for `A4Fuzzer` that replaces the random kind selection + `ZonedStepSelector` with a full coverage-guided campaign loop:

1. Inspection → baseline capture → arm universe → pilot calibration → bandit construction
2. Bandit-driven mutation selection (kind + step jointly)
3. Per-run reward computation → bandit update → coverage state update
4. Enhanced diagnostic logging

### 1.3 What Phase II.4 does NOT do

- Does NOT modify `bandit.py`, `coverage_state.py`, `pilot_calibration.py`, `arm_universe.py`, `baseline_touch.py`
- Does NOT implement A/B experiments or parameter tuning (Phase II.5)
- Does NOT implement persistence/resume (Phase II.6)
- Does NOT change the value generation strategy (p_local remains constant at 0.7 per Pro_Report_7 §4; the fuzzer already uses "mixed" strategy)

---

## 2. Current Campaign Loop Analysis

The current `run_campaign` method in `fuzzer.py` (lines 193-253) does:

```
for i in range(num_mutations):
    result = _run_single_mutation(i+1, total, stats)
    if result:
        _update_stats(stats, result)
        _print_mutation_result(i+1, result)
```

Inside `_run_single_mutation` (lines 255-392):

1. **Kind selection** (line 263-266): `rng.choice(MUTATION_KINDS)` — uniform random
2. **Step selection** (line 274): `selector.select_step(data, kind)` — `ZonedStepSelector` (5%/90%/5% zoned)
3. **Retry loop** (lines 271-302): Up to 10 retries if `_create_mutation` returns `None`
4. **Execution** (lines 304-317): `run_a4_mutation(host, args, config_path)`
5. **Outcome classification** (lines 325-343): crash, proof_generated, verifier_accepted
6. **Result construction** (lines 350-365): `MutationResult` dataclass
7. **DB recording** (lines 368-380): `db.record_mutation`, `db.record_failures`
8. **Touch tracking** (lines 382-386): `count_new_bits` + `merge_into_global`

The bandit campaign must replace steps 1-2 while preserving steps 3-8, and add the reward computation + bandit update after step 8.

---

## 3. Source Code Context

### 3.1 Components being wired together

| Component | What it provides to the campaign loop |
|-----------|--------------------------------------|
| `capture_baseline_touch` | `BaselineTouch` with `.bitmap: bytes` for seeding |
| `ArmUniverse` | Action space: `select()`-able arms with step lists |
| `compute_N_pilot` | Number of pilot runs: `max(30, min(100, budget//20))` |
| `collect_pilot_stat` | Extracts `PilotRunStats` from a pilot `MutationExecutionResult` |
| `calibrate_from_pilot` | Computes `CalibratedParams` from pilot stats + budget |
| `CoverageState` | Holds global coverage state; drives `compute_reward` / `update_state` |
| `DiscountedUCBScheduler` | Bandit that takes `CalibratedParams` + `ArmUniverse`, provides `select()` / `update()` |

### 3.2 Outcome classification

The current fuzzer classifies outcomes in `_print_mutation_result` (lines 965-972). For the reward function, `compute_reward` needs `outcome` (str) and `proof_generated` (bool). These are already computed in `_run_single_mutation` (lines 325-343) and stored in `MutationResult.crashed`, `.proof_generated`, `.failures`, `.proof_verify_failed`, `.verifier_accepted`. The outcome string must be derived from these fields — matching the logic in the diagnostic script's `classify_outcome`.

### 3.3 CLI argument for bandit mode

The CLI (`cli.py` lines 201-203) currently offers `--selector zoned` or `--selector guided`. Phase II.4 adds `--selector bandit` which triggers the full coverage-guided pipeline.

---

## 4. Step-by-Step Implementation Plan

### Step II.4.1: Add bandit infrastructure to `A4Fuzzer.__init__`

**Goal**: Add optional bandit-related attributes, initialized to `None`, that are populated when `selector_strategy="bandit"`.

**Changes to `fuzzer.py` `__init__`** (around line 159):

Add new instance attributes (all initially `None`):
- `self.scheduler: Optional[DiscountedUCBScheduler]`
- `self.coverage_state: Optional[CoverageState]`
- `self.calibrated_params: Optional[CalibratedParams]`
- `self.arm_universe: Optional[ArmUniverse]`

When `selector_strategy == "bandit"`, the fuzzer does NOT create a `ZonedStepSelector`. Instead, it sets `self.selector = None` and defers bandit construction to the start of `run_campaign` (because the bandit needs inspection data, baseline, and pilot, which require running the host).

**New imports** in `fuzzer.py`:
```python
from a4.standalone.bandit import DiscountedUCBScheduler
from a4.standalone.arm_universe import ArmUniverse
from a4.standalone.pilot_calibration import (
    CalibratedParams, calibrate_from_pilot, collect_pilot_stat, compute_N_pilot
)
from a4.standalone.coverage_state import CoverageState, compute_reward, update_state
from a4.standalone.baseline_touch import capture_baseline_touch
```

---

### Step II.4.2: Add `_setup_bandit` method

**Goal**: Encapsulate the full bandit initialization sequence (baseline → arm universe → pilot → calibration → bandit) into a single method called at the start of `run_campaign`.

**Method**: `_setup_bandit(self, num_mutations: int) -> None`

Algorithm:
1. **Baseline capture**: `baseline = capture_baseline_touch(self.host_binary, self.host_args)`
2. **Arm universe**: `self.arm_universe = ArmUniverse(self.data, num_mutations, self.MUTATION_KINDS)`
3. **Pilot calibration**:
   a. `N_pilot = compute_N_pilot(num_mutations)` — typically 30-100
   b. Seed coverage state from baseline: `temp_state = CoverageState(CalibratedParams(tau_new=64, tau_d=3, K_T_rare=32, gamma=0.995))` then `temp_state.seed_from_baseline(baseline.bitmap)`. Copy the seeded global bitmap for pilot stat collection.
   c. Run N_pilot mutations using UNIFORM random selection (not the bandit — the bandit doesn't exist yet):
      - `kind = rng.choice(MUTATION_KINDS)`
      - `step = ZonedStepSelector(seed).select_step(data, kind)` (use a temporary zoned selector)
      - Execute mutation via `_create_mutation` + `run_a4_mutation`
      - `stat = collect_pilot_stat(exec_result, pilot_global_bitmap)`
      - `merge_into_global(exec_result.touch_bitmap, pilot_global_bitmap)` if bitmap present
      - Append stat to `pilot_stats` list
   d. `self.calibrated_params = calibrate_from_pilot(pilot_stats, num_mutations)`
4. **CoverageState**: `self.coverage_state = CoverageState(self.calibrated_params)`, then `self.coverage_state.seed_from_baseline(baseline.bitmap)`
5. **Merge pilot touch into coverage state**: The pilot runs' touch data should also be merged into the coverage state, so the bandit starts with the correct baseline + pilot coverage. Iterate the pilot's global bitmap into `self.coverage_state.global_bitmap` and update `freq` accordingly.
6. **Bandit**: `self.scheduler = DiscountedUCBScheduler(self.arm_universe, self.calibrated_params, seed=self.seed)`
7. **Logging**: Print baseline stats, arm universe summary, pilot calibration results.

**Important**: The pilot mutations count toward the campaign budget. If `num_mutations=200` and `N_pilot=30`, then 30 pilot runs + 170 bandit runs = 200 total. The `run_campaign` main loop should iterate `num_mutations - N_pilot` times after pilot.

---

### Step II.4.3: Modify `run_campaign` for bandit mode

**Goal**: When `selector_strategy == "bandit"`, the campaign loop uses the bandit for selection and computes rewards.

**Changes to `run_campaign`** (lines 193-253):

After inspection (line 212) and before the main loop:

```python
if self.selector is None:  # bandit mode
    self._setup_bandit(num_mutations)
    main_budget = num_mutations - len(pilot_stats)
else:
    main_budget = num_mutations
```

The main loop becomes:

```python
for i in range(main_budget):
    if self.scheduler is not None:
        result = self._run_bandit_mutation(i + 1 + pilot_count, num_mutations, stats)
    else:
        result = self._run_single_mutation(i + 1, num_mutations, stats)
    ...
```

---

### Step II.4.4: Add `_run_bandit_mutation` method

**Goal**: A new method parallel to `_run_single_mutation` that uses the bandit for selection and computes rewards.

**Method**: `_run_bandit_mutation(self, mutation_num, total, stats) -> Optional[MutationResult]`

Algorithm:
1. **Selection**: `kind, step = self.scheduler.select()`
2. **Retry within arm**: If `_create_mutation(kind, step)` returns `None`, retry with a different step from the SAME arm's bucket (up to 10 tries). Use `self.arm_universe.steps_in_arm(kind, bucket)` and pick a random alternative step. If all retries fail, skip this iteration (no bandit update — the arm isn't penalized for target-availability issues).
3. **Execution**: Same as `_run_single_mutation` lines 304-365 — execute mutation, classify outcome.
4. **Outcome classification**: Derive `outcome` string from `MutationResult` fields:
   ```python
   if result.verifier_accepted:
       outcome = "ACCEPTED"
   elif result.crashed:
       outcome = "CRASH"
   elif result.failures or result.proof_verify_failed:
       outcome = "REJECTED"
   else:
       outcome = "NO_EFFECT"
   ```
5. **Reward computation**: `reward, diag = compute_reward(exec_result.touch_bitmap, exec_result.failures, exit_code, outcome, result.proof_generated, self.coverage_state)`
6. **Bandit update**: `self.scheduler.update(kind, step, reward)`
7. **Coverage state update**: `update_state(exec_result.touch_bitmap, exec_result.failures, exit_code, self.coverage_state)`
8. **DB recording + touch tracking**: Same as existing (lines 368-386).
9. **Store reward in MutationResult**: Add `reward` field to `MutationResult` for logging.

**Ordering contract** (from `coverage_state.py` docstring):
```
compute_reward  → reads state BEFORE this run
scheduler.update → uses the reward
update_state    → writes this run's data
```

This order is critical. `compute_reward` must be called BEFORE `update_state`, and `scheduler.update` uses the reward from `compute_reward`.

---

### Step II.4.5: Add `reward` field to `MutationResult`

**Goal**: Store the reward in the result for logging and diagnostics.

**Change to `MutationResult` dataclass** (line 66):
- Add `reward: float = 0.0`
- Add `reward_diag: Optional[dict] = None`

In the non-bandit path, these remain at defaults (0.0, None).

---

### Step II.4.6: Update diagnostic output for bandit mode

**Goal**: When running in bandit mode, per-run output includes reward and arm info.

**Changes to `_print_mutation_result`** (around line 982):

After the existing output, if `result.reward_diag` is not None, print:
```
  r={reward:.3f} T_new={diag.T_new:.2f} F_new={diag.F_new:.2f} Q={diag.Q:.2f}
```

**Changes to `_print_campaign_summary`** (around line 1097):

If `self.scheduler` is not None:
- Print `self.scheduler.summary()` (top/bottom arms)
- Print calibrated params summary (τ_T, τ_d, K_T_rare, γ)

---

### Step II.4.7: Update CLI to support `--selector bandit`

**Goal**: Add `bandit` as a valid selector strategy in the CLI.

**Changes to `cli.py`** (line 201):

Add `"bandit"` to the choices list:
```python
fuzz_parser.add_argument("--selector", default="zoned",
                        choices=["zoned", "guided", "bandit"],
                        help="Step selection strategy")
```

---

### Step II.4.8: Integration test (200-mutation bandit campaign)

**Goal**: Run a real 200-mutation campaign with `--selector bandit` and verify it completes without errors, produces nontrivial adaptation (arm probabilities shift), and generates expected output.

**Command**:
```bash
python -m a4.standalone.cli fuzz --host ./workspace/output/target/release/risc0-host \
    --num 200 --seed 42 --selector bandit --db bandit_test.db \
    -- --in1 5 --in4 10
```

**Verification criteria** (from Pro_Report_4 §12):
1. Campaign completes without errors
2. Pilot calibration runs and produces reasonable parameters
3. Per-run output shows reward values
4. Campaign summary shows bandit arm stats
5. At least some arm adaptation is visible (not all arms have equal mean reward)

---

## 5. Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `a4/standalone/fuzzer.py` | **MODIFY** | Add bandit infrastructure to `__init__`, `_setup_bandit`, `_run_bandit_mutation`, updated output, `reward` field in `MutationResult` |
| `a4/standalone/cli.py` | **MODIFY** | Add `"bandit"` to `--selector` choices |

No new files created.

---

## 6. Alignment with Master Plan

| Master plan reference | Phase II.4 coverage | Notes |
|----------------------|---------------------|-------|
| §5 II.4: "Baseline touch seeded into CoverageState before pilot" | Step II.4.2 (item 4) | `coverage_state.seed_from_baseline(baseline.bitmap)` |
| §5 II.4: "No saturation switch logic needed" | N/A | Saturation switch was removed in II.2R; no remnant to handle |
| Pro_Report_4 §12: "Replace selector with choose arm → choose step → execute → compute reward → update coverage → update bandit" | Step II.4.4 | Exact sequence implemented |
| Pro_Report_4 §12: "Log per-run diagnostics (selected arm, new_touch, rare_touch, Q, reward)" | Step II.4.6 | Reward diagnostics logged |
| Pro_Report_4 §12: "200-500 mutations showing nontrivial adaptation" | Step II.4.8 | 200-mutation integration test |
| Pro_Report_7 §J: "p_local = 0.7 constant for Phase II.3-II.4" | No change needed | Fuzzer already uses "mixed" value strategy; no p_local parameter exists in current code. Pro_Report_7's p_local guidance is for Phase II.5 when value generation modes are explicitly implemented. |
| Pro_Report_7 §crash: "Bandit gets reward=0; coverage state not updated for crash" | Via `compute_reward` (already returns 0 for crash) + `update_state` (already gates on crash) | No II.4 code needed — handled by existing II.2R code |

### Deviations from master plan

1. **Pilot mutations count toward campaign budget**: The master plan doesn't explicitly specify whether pilot runs consume campaign budget. This plan makes them consume budget because: (a) the user specified max campaign size, (b) pilot runs do produce useful mutations that should be recorded, (c) the calibrated parameters are derived from the pilot, so not counting them would inflate the effective campaign size. With N=200 and N_pilot=30, the main bandit loop runs 170 iterations.

2. **Pilot coverage merged into CoverageState**: After pilot calibration, the pilot's touch bitmaps are merged into the `CoverageState` so the bandit starts with pilot+baseline coverage, not just baseline. This is not explicitly mentioned in any Pro Report but is necessary for correctness — otherwise the first bandit runs would see the pilot's coverage as "new," distorting rewards.

3. **Retry logic in `_run_bandit_mutation`**: When `_create_mutation` fails, the plan retries with alternative steps from the same arm's bucket rather than re-calling `scheduler.select()`. This preserves the bandit's iteration counter and avoids the "silent failure" problem noted in Phase II.3 report §5.2. If all 10 retries within the bucket fail, the iteration is skipped without penalizing the arm.

---

## 7. Dependencies for Phase II.5 (reminders)

Phase II.5 (A/B Experiments + Larger Campaign) will:

1. Run 500-1000 mutation campaigns comparing uniform vs bandit scheduling
2. A/B test weight variants: default, a_Z=0.5, a_Tn=0.5
3. A/B test c values: 0.15, 0.25, 0.4
4. Log cumulative distinct failure context_ids vs run index, Z-event counts per kind/bucket
5. Measure total distinct touched, time-to-hit rare touch, wall-clock overhead

Phase II.4 must produce output that makes these comparisons straightforward. The per-run reward logging and campaign summary from Step II.4.6 provide the data needed.

---

## 8. Design Decisions and Rationale

### 8.1 Why `_run_bandit_mutation` is separate from `_run_single_mutation`

The existing `_run_single_mutation` selects kind and step independently (line 263: `rng.choice`, line 274: `selector.select_step`). The bandit selects them jointly via `scheduler.select() → (kind, step)`. The mutation execution, outcome classification, and DB recording are identical in both paths. Factoring the shared code into a helper would be possible but adds indirection for a 60-line method; keeping two parallel methods is clearer for the initial integration and can be refactored in II.5 if desired.

### 8.2 Why pilot runs use uniform random selection (not the bandit)

The bandit requires `CalibratedParams` (from pilot) to be constructed. The pilot runs are used to calibrate those parameters. This is a classic bootstrapping problem. The solution is to use a simple uniform random strategy for pilot runs, then construct the bandit with the calibrated parameters. This matches Pro_Report_5 §11.2 ("Run N_pilot random mutations with a simple scheduler: uniform over mutation kind, uniform over valid steps within kind").

### 8.3 Why pilot runs use `ZonedStepSelector` (not pure uniform)

Pro_Report_5 says "uniform over valid steps within kind" for pilot. The `ZonedStepSelector` (5%/90%/5%) is close to uniform for core steps but adds init/final coverage. Since the pilot needs to observe representative mutations, the mild zone bias is acceptable and consistent with how the fuzzer has always operated. Using pure `random.choice(valid_steps)` would be equally valid; using `ZonedStepSelector` is simply reusing existing code.

### 8.4 Why the `kind` parameter still exists in CLI

With `--selector bandit`, the `--kind` flag becomes irrelevant because the bandit selects kinds. The implementation will ignore `--kind` when `--selector bandit` is active (defaulting to "all"). A warning is printed if the user specifies both `--selector bandit` and `--kind` != "all".

---

## 9. Completion Checklist

- [ ] Step II.4.1: Bandit infrastructure in `A4Fuzzer.__init__`
- [ ] Step II.4.2: `_setup_bandit` method (baseline → arm universe → pilot → calibration → bandit)
- [ ] Step II.4.3: `run_campaign` modified for bandit mode
- [ ] Step II.4.4: `_run_bandit_mutation` method with full reward pipeline
- [ ] Step II.4.5: `reward` and `reward_diag` fields in `MutationResult`
- [ ] Step II.4.6: Enhanced diagnostic output for bandit mode
- [ ] Step II.4.7: CLI `--selector bandit` option
- [ ] Step II.4.8: 200-mutation integration test campaign

---

## 10. For Anyone New: What Phase II.4 Is and Why

### What

Phase II.4 is the **integration** phase — it connects all the components built in previous phases into the real fuzzer's campaign loop. Before Phase II.4, the bandit scheduler, reward function, pilot calibration, arm universe, and baseline touch all exist as standalone modules with unit tests. Phase II.4 wires them together so that running `python -m a4.standalone.cli fuzz --selector bandit` executes a full coverage-guided fuzzing campaign.

### Why

Each previous phase built one piece of the system in isolation:
- II.0: Baseline touch capture
- II.1: Arm universe (action space)
- II.1.5: Pilot calibration
- II.2R: Reward function
- II.3: Bandit scheduler

None of these pieces do anything useful alone. Phase II.4 is where they come together: the fuzzer runs a baseline, builds the arm universe, runs pilot mutations to calibrate parameters, constructs the bandit, then runs the main campaign with the bandit selecting mutations and the reward guiding its learning.

### How it differs from other phases

| Phase | Nature | Creates new module? |
|-------|--------|-------------------|
| II.0-II.3 | Build individual components (baseline, arms, calibration, reward, bandit) | Yes — each creates a new `.py` file |
| **II.4** (this) | **Wire all components into the existing fuzzer** | **No new files — modifies `fuzzer.py` and `cli.py`** |
| II.5 | A/B experiments using the integrated system | No new files — runs campaigns and analyzes |

Phase II.4 is uniquely different: it's the only phase that modifies the main fuzzer. All previous phases carefully avoided touching `fuzzer.py` to keep the system working during development. Phase II.4 is where the investment pays off.

---

## 11. New and Withheld Sections

**Sections retained**: All standard sections (Prerequisites, Implementation Steps, Files, Alignment, Dependencies, Completion Checklist, For Anyone New).

**Sections retained from II.3**: Design Decisions and Rationale (§8) — retained because II.4 has several non-obvious integration choices (pilot budget, retry logic, parallel methods).

**New sections**:
- **§2 Current Campaign Loop Analysis**: Added because II.4 modifies existing code rather than creating new files. Understanding the current loop in detail is essential for knowing what to change and what to preserve. Previous plans created new files from scratch and didn't need this analysis.

**Sections withheld**:
- **Source-of-Truth: Bandit Specification** (present in II.3): Not needed — the bandit specification was consolidated in II.3's plan and doesn't need repeating. II.4 uses the bandit via its public API, not its internals.

---

*End of Phase II.4 Implementation Plan.*

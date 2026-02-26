# Phase II.1.5 Detailed Implementation Plan: Pilot Calibration

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.1.5** (Pilot Calibration). It is consistent with [PHASE_II_MASTER_IMPLEMENTATION_PLAN.md](./PHASE_II_MASTER_IMPLEMENTATION_PLAN.md) section 5 (Phase II.1.5), section 2.2-2.3, and [Pro_Report_5.md](./Pro_Report_5.md) section 11.2.

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites from Phases II.0 and II.1

### 1.1 What exists

- `ArmUniverse` from Phase II.1: computes T, B_count, B, arms from inspection data + budget.
- `MutationExecutionResult.touch_bitmap` (Phase 3.2): 65536-byte bitmap per run.
- `MutationExecutionResult.failures` (Phase I): list of `ConstraintFailure` per run.
- `count_new_bits(run_bitmap, global_bitmap)` (Phase 3.2): computes new touch count.
- `distinct_touched(bitmap)` (Phase 3.2): counts non-zero bitmap entries.
- Existing `A4Fuzzer` with `run_campaign` loop, `_run_single_mutation`, `global_touch_bitmap`.
- Baseline snapshot: 1599 distinct buckets (Phase II.0).
- Host binary up to date.

### 1.2 What Phase II.1.5 does NOT do

- Does NOT implement the reward function (Phase II.2).
- Does NOT implement the bandit (Phase II.3).
- Does NOT modify the campaign loop's selection logic (Phase II.4).
- Only collects statistics from random mutations and computes calibrated parameters.

---

## 2. Source-of-Truth Facts

### 2.1 Parameters to calibrate (from master plan section 2.3)

| Parameter | Calibration method | Default if skipped |
|-----------|-------------------|-------------------|
| tau_new | 75th percentile of `{delta_new_t : delta_new_t > 0}`, clamped [16, 256] | 64 |
| tau_fail_count | 75th percentile of `{n_fail_t : not crash}`, clamped minimum 5 | 25 |
| K_rare | `clamp(floor(0.02 * median(abs_U_t)), 16, 64)` | 32 |

### 2.2 DERIVED parameters also computed here (from master plan section 2.2)

| Parameter | Formula |
|-----------|---------|
| W | `clamp(floor(0.05 * N), 30, 150)` |
| gamma | `2^(-1/H)` where `H = clamp(floor(0.2 * N), 50, 300)` |

These are deterministic from N (no pilot data needed), but are computed here so all parameters are frozen at the same time.

### 2.3 Pilot budget

From Pro_Report_5 section 11.2:
```
N_pilot = clamp(floor(0.05 * N), 30, 100)
```

For N=1000: N_pilot = 50. For N=500: N_pilot = 30. For N=5000: N_pilot = 100.

### 2.4 What to collect per pilot run

For each of the N_pilot runs, record:
- `delta_new_t`: number of new touch bits (from `count_new_bits`)
- `abs_U_t`: number of distinct touched buckets in this run (from `distinct_touched(run_bitmap)`)
- `n_fail_t`: total number of constraint failure instances (`len(failures)`)
- `is_crash`: whether the run crashed (exit code indicates segfault, etc.)
- `touch_bitmap_present`: whether `touch_bitmap is not None`

### 2.5 How pilot runs work

Pilot runs use the **existing** fuzzer infrastructure: `_run_single_mutation` with uniform random kind selection and `ZonedStepSelector`. The pilot is NOT a separate campaign — it is the first N_pilot runs of the real campaign. The master plan (section 5, Phase II.1.5) states: "Pilot runs are NOT thrown away. They are the first N_pilot runs of the campaign. After calibration, the bandit takes over for the remaining N - N_pilot runs."

However, Phase II.1.5 only implements the **calibration function** — a standalone function that takes pilot statistics and returns calibrated parameters. The actual integration into the campaign loop (running pilot then switching to bandit) is Phase II.4's job.

### 2.6 Existing data from the fuzzer

From `fuzzer.py`:
- `exec_result.touch_bitmap` (Optional[bytes]): from `run_a4_mutation`.
- `exec_result.failures` (List[ConstraintFailure]): parsed constraint failures.
- `result.exit_code` (int): process exit code.
- `result.crashed` (bool): True if segfault/abort (checked in `_run_single_mutation` lines 317-319).

---

## 3. Step-by-Step Implementation Plan

### Step II.1.5.1: Create `pilot_calibration.py` module

**Goal**: A module that takes pilot run statistics and produces calibrated parameters.

**Actions**:

1. Create `a4/standalone/pilot_calibration.py` with:

   - `PilotRunStats` dataclass:
     ```
     delta_new: int          # new touch bits this run
     abs_U: int              # distinct touched buckets this run
     n_fail: int             # total failure instances this run
     is_crash: bool          # True if process crashed
     has_bitmap: bool        # True if touch_bitmap was not None
     ```

   - `CalibratedParams` dataclass:
     ```
     tau_new: float          # novelty scaling (for S_new score)
     tau_fail_count: float   # cascade penalty strength (for Q_t)
     K_rare: int             # number of rare bits to average (for S_rare score)
     W: int                  # rolling window size (for saturation detection)
     gamma: float            # discount factor (for bandit arm decay)
     lambda_fail: float      # failure novelty weight (default 0.2, tuned in II.5)
     c_explore: float        # UCB exploration coefficient (default 0.25, tuned in II.5)
     tau_fail_new: float     # failure novelty scaling (HARD = 2.0)
     ```

   - `calibrate_from_pilot(pilot_stats: List[PilotRunStats], budget: int) -> CalibratedParams`:
     - Computes tau_new, tau_fail_count, K_rare from pilot_stats.
     - Computes W, gamma from budget N.
     - Sets defaults for lambda_fail (0.2), c_explore (0.25), tau_fail_new (2.0).
     - Returns frozen CalibratedParams.

   - `compute_N_pilot(budget: int) -> int`:
     - Returns `max(30, min(100, budget // 20))` (i.e., `clamp(floor(0.05*N), 30, 100)`).

**Key implementation details**:

- For `tau_new`: Filter pilot_stats to those with `delta_new > 0`. If empty, use default 64. Otherwise, compute 75th percentile of the delta_new values, clamp to [16, 256].
- For `tau_fail_count`: Filter to non-crash runs with `has_bitmap == True`. Compute 75th percentile of their `n_fail` values. Clamp minimum 5.
- For `K_rare`: Compute median of `abs_U` across all runs with `has_bitmap == True`. Then `clamp(floor(0.02 * median_abs_U), 16, 64)`.
- For `W`: `max(30, min(150, budget // 20))`.
- For `gamma`: `H = max(50, min(300, budget // 5))`, then `gamma = 2 ** (-1.0 / H)`.

**Why a separate module**: Pilot calibration is a one-time computation that converts statistics into parameters. It does not depend on the bandit, reward function, or campaign loop. Keeping it in its own module makes it unit-testable with synthetic data.

**Deliverable**: `pilot_calibration.py` with `PilotRunStats`, `CalibratedParams`, `calibrate_from_pilot`, `compute_N_pilot`.

---

### Step II.1.5.2: Create `collect_pilot_stats` helper

**Goal**: A function that extracts `PilotRunStats` from a single mutation run's results.

**Actions**:

1. In `pilot_calibration.py`, add:

   - `collect_pilot_stat(exec_result: MutationExecutionResult, global_bitmap: bytearray) -> PilotRunStats`:
     - `delta_new = count_new_bits(exec_result.touch_bitmap, global_bitmap)` if bitmap present, else 0.
     - `abs_U = distinct_touched(exec_result.touch_bitmap)` if bitmap present, else 0.
     - `n_fail = len(exec_result.failures)`.
     - `is_crash`: determined by exit code check (same logic as fuzzer.py lines 317-319).
     - `has_bitmap = exec_result.touch_bitmap is not None`.

**Note**: This function does NOT merge into the global bitmap. The caller (Phase II.4) is responsible for merging after collecting the stat. This preserves the update order from master plan section 3.4 (compute reward/stats before updating global state).

**Deliverable**: `collect_pilot_stat` function.

---

### Step II.1.5.3: Unit tests

**Goal**: Verify calibration logic with synthetic pilot data.

**Actions**:

1. Create `a4/standalone/tests/test_pilot_calibration.py` with:

   - `test_compute_N_pilot`: N=1000 -> 50, N=500 -> 30 (clamped), N=5000 -> 100 (clamped).
   - `test_calibrate_typical`: Create 50 fake PilotRunStats with realistic values (delta_new mostly 0 after first few, abs_U ~1599, n_fail ~2-10), verify tau_new, tau_fail_count, K_rare are in plausible ranges.
   - `test_calibrate_no_novelty`: All delta_new=0 -> tau_new defaults to 64.
   - `test_calibrate_all_crashes`: All is_crash=True -> tau_fail_count defaults to 25.
   - `test_W_and_gamma_from_budget`: Verify W and gamma formulas for N=500, 1000, 5000.
   - `test_defaults_preserved`: lambda_fail=0.2, c_explore=0.25, tau_fail_new=2.0.

**Deliverable**: Unit tests for calibration logic.

---

### Step II.1.5.4: Integration test (optional, with host)

**Goal**: Run a short actual pilot (e.g., 5 mutations) and verify that `collect_pilot_stat` produces valid stats and `calibrate_from_pilot` produces valid parameters.

**Actions**:

1. In `test_pilot_calibration.py`, add host-dependent test:
   - `test_pilot_real_runs` (skipped unless A4_TEST_HOST set).
   - Run 5 mutations via the existing CLI or fuzzer.
   - Collect PilotRunStats for each.
   - Call calibrate_from_pilot.
   - Assert all parameters are in valid ranges.

**Note**: This test actually runs 5 host mutations (~30-60s each = 2.5-5 minutes total). It should use no more than 5 mutations per the user's campaign size constraints.

**Deliverable**: Integration test with real mutations.

---

## 4. Files to Touch (Phase II.1.5 only)

| File | Change |
|------|--------|
| a4/standalone/pilot_calibration.py | **New**: PilotRunStats, CalibratedParams, calibrate_from_pilot, compute_N_pilot, collect_pilot_stat. |
| a4/standalone/tests/test_pilot_calibration.py | **New**: Unit tests + optional integration test. |

No changes to: arm_universe.py, executor.py, fuzzer.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs, coverage_db.py, step_selector.py.

---

## 5. Alignment with Master Plan

| Master plan reference | Phase II.1.5 coverage | Notes |
|----------------------|----------------------|-------|
| Section 5, Phase II.1.5: "Run N_pilot random mutations; calibrate tau_new, tau_fail_count, K_rare" | calibrate_from_pilot function | As specified. |
| Section 5, Phase II.1.5: "Also compute DERIVED parameters: W, gamma" | Included in CalibratedParams | As specified. |
| Section 5, Phase II.1.5: "Pilot runs contribute to campaign" | collect_pilot_stat does not merge bitmap; caller manages this | Phase II.4 handles the campaign loop integration. |
| Section 2.3: Calibration methods and defaults | Exact formulas implemented | As specified. |

### Deviations from master plan

1. **No campaign loop changes**: The master plan's Phase II.1.5 description says "Run N_pilot mutations." Phase II.1.5's implementation only provides the calibration FUNCTIONS and stat collection. The actual running of pilot mutations and integration into the campaign loop is deferred to Phase II.4, which will call these functions during the first N_pilot iterations. **Reason**: Phase II.1.5 creates tested, modular components. Phase II.4 wires them together. This maintains the incremental approach where each sub-phase is independently testable.

2. **CalibratedParams includes ALL parameters (not just calibrated ones)**: The dataclass bundles DERIVED (W, gamma), CALIBRATE ONCE (tau_new, tau_fail_count, K_rare), and default A/B parameters (lambda_fail, c_explore, tau_fail_new) into one frozen object. **Reason**: Phase II.2 (CoverageState + Reward) and Phase II.3 (Bandit) both need these parameters. Having one object they can pass around avoids scattering parameter references.

3. **`collect_pilot_stat` does not merge into global bitmap**: The function computes delta_new from the current global bitmap but does not update it. **Reason**: Master plan section 3.4 specifies update order: compute reward/stats FIRST, then update global state. If collect_pilot_stat merged automatically, the second pilot run would see the first run's merged bitmap and report fewer new bits. The caller must merge explicitly after collecting the stat.

No other deviations.

---

## 6. Key Variables and Functions

### 6.1 PilotRunStats (dataclass)

- **delta_new**: Number of new touch bitmap buckets this run discovered (buckets not in global bitmap before this run). This is the same quantity as `Δ_new_t` in Pro_Report_4 section 6.1.
- **abs_U**: Number of distinct touched buckets in this run's bitmap (`|U_t|`). For our guest, typically ~1599.
- **n_fail**: Total number of constraint failure instances (raw count, not distinct contexts). This is `n^fail_t` in Pro_Report_4 section 6.5.
- **is_crash**: True if the host process crashed (SIGSEGV, SIGABRT, etc.).
- **has_bitmap**: True if the touch bitmap was successfully parsed from the run's output.

### 6.2 CalibratedParams (dataclass)

- **tau_new** (float): Novelty scaling for `S_new = 1 - exp(-delta_new / tau_new)`. Larger tau_new means more new bits needed to reach a high novelty score. Calibrated from 75th percentile of nonzero delta_new values.
- **tau_fail_count** (float): Cascade penalty for `Q_t = exp(-n_fail / tau_fail_count)`. Larger tau_fail_count means more failures before strong penalty. Calibrated from 75th percentile of failure counts.
- **K_rare** (int): How many rare bits to average for the rarity score. Derived from 2% of median touched-set size. For our guest (~1599 distinct), K_rare = 32.
- **W** (int): Rolling window size for saturation detection. Derived from budget: `clamp(0.05*N, 30, 150)`.
- **gamma** (float): Discount factor for bandit arm statistics. Recent history counts more. Derived from budget via half-life: `gamma = 2^(-1/H)`, `H = clamp(0.2*N, 50, 300)`.
- **lambda_fail** (float): Weight for failure novelty in combined reward. Default 0.2.
- **c_explore** (float): UCB exploration coefficient. Default 0.25.
- **tau_fail_new** (float): Failure novelty scaling (HARD constant). Default 2.0.

### 6.3 calibrate_from_pilot(pilot_stats, budget) -> CalibratedParams

Takes a list of PilotRunStats and the campaign budget N. Computes all parameters. Returns a frozen CalibratedParams.

### 6.4 collect_pilot_stat(exec_result, global_bitmap) -> PilotRunStats

Extracts a PilotRunStats from one mutation run's results. Does NOT modify global_bitmap.

### 6.5 compute_N_pilot(budget) -> int

Returns the number of pilot runs: `clamp(0.05*N, 30, 100)`.

---

## 7. Completion Checklist

- [ ] Step II.1.5.1: pilot_calibration.py with PilotRunStats, CalibratedParams, calibrate_from_pilot, compute_N_pilot.
- [ ] Step II.1.5.2: collect_pilot_stat helper.
- [ ] Step II.1.5.3: Unit tests for calibration logic.
- [ ] Step II.1.5.4 (optional): Integration test with real mutations.
- [ ] No changes to existing fuzzer, executor, bandit, or C++/Rust.

---

## 8. Dependencies for Phase II.2 (reminders)

Phase II.2 (CoverageState + Reward) needs:
- CalibratedParams (from Phase II.1.5) to parameterize the reward function.
- The reward function will use tau_new, tau_fail_count, K_rare, W, lambda_fail, tau_fail_new.
- The bandit (Phase II.3) will use gamma, c_explore, n_min (from ArmUniverse).

---

## 9. For Anyone New: What Phase II.1.5 Is and Why

### What

Phase II.1.5 is the **parameter calibration** step. The coverage-guided bandit scheduler (built in later sub-phases) has several numerical parameters that control how it evaluates runs and selects mutations. Some of these parameters depend on the specific guest program's behavior — how many constraint contexts it touches, how many failures a typical mutation produces, how quickly new coverage is discovered.

Rather than hardcoding these numbers (which would only work for one guest program), we run a small "pilot" of random mutations at the start of each campaign and compute the parameters from the observed statistics.

### Why

- **tau_new** controls what counts as "a lot" of new coverage. If the guest program typically discovers 100 new touch buckets on the first few mutations, tau_new should be ~75-100 so the novelty score doesn't saturate at 1.0 too easily. If it only discovers 10, tau_new should be smaller.
- **tau_fail_count** controls how strongly we penalize "garbage cascade" runs (mutations that produce dozens of failures). This depends on what a "typical" failure count looks like for this guest.
- **K_rare** controls how many "rare" touch buckets we average to compute rarity. This depends on how many distinct buckets the guest typically touches.

All three depend on the guest program and mutation mix, so they are calibrated from pilot data rather than hardcoded.

### How it differs from other phases

| Phase | What it does | Nature |
|-------|-------------|--------|
| **II.0** | Baseline touch snapshot | Measurement (one unmutated run) |
| **II.1** | Arm universe construction | Data structure (from inspection) |
| **II.1.5** (this) | Pilot calibration | **Parameter estimation** (from pilot mutations) |
| **II.2** | CoverageState + reward function | Algorithm (uses calibrated params) |
| **II.3** | Bandit scheduler | Algorithm (uses calibrated params) |
| **II.4** | Campaign loop integration | Wiring (runs pilot, then bandit) |

Phase II.1.5 is the bridge between "we know the action space" (II.1) and "we can compute rewards" (II.2). It provides the numerical parameters that II.2 and II.3 need.

---

## 10. New and Withheld Sections

**Sections retained**: All from previous plans.

**Sections withheld**: None.

**New sections**: None beyond the standard set.

---

*End of Phase II.1.5 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*

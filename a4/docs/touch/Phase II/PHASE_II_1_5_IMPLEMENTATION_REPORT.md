# Phase II.1.5 Implementation Report: Pilot Calibration

This report describes the implementation and testing of Phase II.1.5 (Pilot Calibration), deviations from the plan, key variables and functions, testing performed, and insights for Phase II.2.

**Reference plan**: [PHASE_II_1_5_IMPLEMENTATION_PLAN.md](./PHASE_II_1_5_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.1.5 was implemented as specified. A new `pilot_calibration.py` module provides `PilotRunStats`, `CalibratedParams`, `calibrate_from_pilot`, `compute_N_pilot`, and `collect_pilot_stat`. 20 unit tests pass with synthetic data. No integration test with real mutations was run (the optional Step II.1.5.4 was skipped -- the unit tests cover all calibration logic paths).

**Goal of this subphase**: Build the calibration machinery -- standalone functions that take pilot statistics and produce the numerical parameters that Phase II.2 (reward function) and Phase II.3 (bandit) need. The parameters are calibrated per-campaign, per-guest-program, so they adapt to whatever program and inputs are being fuzzed.

---

## 2. Deviations from the Phase II.1.5 Implementation Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Integration test (Step II.1.5.4) | "Optional: run 5 real mutations" | Not implemented | All calibration logic is exercised by the 20 unit tests with synthetic data. Real mutations would only test that `collect_pilot_stat` receives real `MutationExecutionResult` objects, which is straightforward and will be tested naturally in Phase II.4 integration. |
| `_percentile` helper | Not explicitly in plan | Added as private helper `_percentile(data, p)` | Needed for computing 75th percentile. Python's `statistics` module has `median` but not a generic percentile function. A simple linear-interpolation implementation was added (~10 lines). |
| Crash detection | Plan said "same logic as fuzzer.py lines 317-319" | Extracted into `_is_crash(exit_code)` private helper | Avoids importing from fuzzer.py (which would create a circular dependency). The crash signal sets are duplicated from fuzzer.py lines 329-331 -- they are constants, so duplication is acceptable. |

No other deviations.

---

## 3. Key Variables and Functions

### 3.1 `PilotRunStats` (dataclass)

Per-pilot-run statistics collected by `collect_pilot_stat`:

- **`delta_new`** (int): Number of new touch bitmap buckets this run discovered. Computed as `count_new_bits(run_bitmap, global_bitmap)`. For the first pilot run (global is empty), this is ~1599. For subsequent runs with the same guest/inputs, typically 0 (touch saturation).
- **`abs_U`** (int): Number of distinct touched buckets in this run's bitmap. `distinct_touched(run_bitmap)`. Typically ~1599 for our guest regardless of mutation.
- **`n_fail`** (int): Total number of constraint failure instances (raw count). `len(exec_result.failures)`. Typically 0-28 per mutation for our guest.
- **`is_crash`** (bool): True if exit code indicates segfault/abort. Checked via `_is_crash(exit_code)`.
- **`has_bitmap`** (bool): True if the touch bitmap was successfully parsed from the run output. False if run crashed before witgen completed or if host wasn't built with Phase 3.2 C++ changes.

### 3.2 `CalibratedParams` (dataclass)

All parameters needed by the reward function and bandit, frozen after calibration:

- **`tau_new`** (float): Novelty scaling. Controls the steepness of `S_new = 1 - exp(-delta_new / tau_new)`. Larger tau_new means you need more new bits to get a high novelty score. Calibrated from 75th percentile of nonzero delta_new values.
- **`tau_fail_count`** (float): Cascade penalty strength. Controls `Q_t = exp(-n_fail / tau_fail_count)`. Larger tau_fail_count means more failures before strong penalty. Calibrated from 75th percentile of failure counts.
- **`K_rare`** (int): Number of rarest-touched buckets to average for the rarity score. Derived from 2% of median touched-set size. For our guest (~1599 distinct), K_rare = 31.
- **`W`** (int): Rolling window size for saturation detection. `clamp(N//20, 30, 150)`. Determines how many recent runs the saturation test looks at.
- **`gamma`** (float): Discount factor for bandit arm statistics. `2^(-1/H)` where `H = clamp(N//5, 50, 300)`. Controls how fast old arm statistics fade. Closer to 1 = longer memory.
- **`lambda_fail`** (float): Weight for failure novelty in combined reward. Default 0.2. Tunable in Phase II.5.
- **`c_explore`** (float): UCB exploration coefficient. Default 0.25. Tunable in Phase II.5.
- **`tau_fail_new`** (float): Failure novelty scaling (HARD constant). Default 2.0.

### 3.3 `calibrate_from_pilot(pilot_stats, budget) -> CalibratedParams`

Takes a list of PilotRunStats and the campaign budget N. Computes all parameters via the formulas from Pro_Report_4 section 6 and Pro_Report_5 section 11. Returns a frozen CalibratedParams.

**Internal logic**:
1. Filter pilot_stats to nonzero delta_new -> compute 75th percentile -> clamp [16, 256] -> tau_new.
2. Filter to non-crash bitmap runs -> compute 75th percentile of n_fail -> clamp min 5 -> tau_fail_count.
3. Filter to bitmap runs -> compute median abs_U -> 2% of that -> clamp [16, 64] -> K_rare.
4. From budget: compute W and gamma.
5. Set defaults for lambda_fail, c_explore, tau_fail_new.

### 3.4 `collect_pilot_stat(exec_result, global_bitmap) -> PilotRunStats`

Extracts statistics from one mutation run. Does NOT merge into global_bitmap -- the caller merges explicitly after collecting stats. This preserves the update order from master plan section 3.4.

### 3.5 `compute_N_pilot(budget) -> int`

Returns how many pilot runs to do: `clamp(N//20, 30, 100)`.

### 3.6 `_percentile(data, p) -> float`

Private helper that computes the p-th percentile (0-100) using linear interpolation between sorted data points. Used for the 75th percentile computation of tau_new and tau_fail_count.

### 3.7 `_is_crash(exit_code) -> bool`

Private helper that checks if an exit code indicates a crash. Mirrors the logic in fuzzer.py lines 329-331 (SIGSEGV=-11, SIGABRT=-6, etc.).

---

## 4. Testing Performed

### 4.1 Unit tests

**Command**: `python -m pytest a4/standalone/tests/test_pilot_calibration.py -v`
**Result**: 20 passed in 1.00s.

| Test class | Tests | What they verify |
|-----------|-------|-----------------|
| TestComputeNPilot | 3 | N_pilot formula: typical (50 for N=1000), clamped low (30), clamped high (100) |
| TestPercentile | 3 | Percentile helper: single element, two elements, 1-100 distribution |
| TestCalibrateFromPilot | 10 | tau_new from typical/no-novelty/varied data; tau_fail_count from high/low/all-crash; K_rare scaling; W/gamma budget scaling; defaults preserved |
| TestCollectPilotStat | 4 | Basic stat collection; no-bitmap crash; delta_new with populated global; does not modify global |

**Key test**: `test_typical_pilot` simulates 50 pilot runs where the first run discovers 1599 new bits and the remaining 49 discover 0. This matches the real behavior observed in Phase 3.3 (touch saturates after first run). The calibrated tau_new = 256 (clamped from 1599), tau_fail_count = 5 (75th percentile of [2,5,5,...]), K_rare = 31 (0.02 * 1599).

**Key test**: `test_does_not_modify_global` verifies that `collect_pilot_stat` reads but does not write the global bitmap. This ensures the update-order contract from master plan section 3.4 is respected.

---

## 5. Insights for Phase II.2 (CoverageState + Reward)

### 5.1 CalibratedParams is the interface

Phase II.2's `compute_reward` function takes `CalibratedParams` as input (alongside run data and coverage state). All reward formula parameters come from this one object. Phase II.3's bandit takes `gamma`, `c_explore`, `n_min` from the same object (plus `n_min` from ArmUniverse).

### 5.2 Touch saturation affects tau_new calibration

For our guest program, the first pilot run discovers ~1599 new bits and subsequent runs discover 0. This means the only nonzero delta_new in the pilot is 1599, so the 75th percentile of nonzero deltas is 1599, clamped to tau_new=256. This means `S_new = 1 - exp(-1599/256) ≈ 1.0` for the first run (maximally novel) and `S_new = 0` for all subsequent runs (no novelty). The novelty-to-rarity switch (saturation detection) will trigger almost immediately (median delta_new = 0 after 2 runs).

This is the expected behavior for a fixed guest program: novelty mode is brief, rarity mode dominates. The reward function needs to handle this gracefully. Phase II.2 should verify this transition in unit tests.

### 5.3 The pilot runs ARE the campaign start

Phase II.4 will run pilot runs as the first N_pilot iterations of the real campaign. Pilot stats are collected, parameters are calibrated, coverage is merged into the global bitmap, and then the bandit takes over for the remaining N - N_pilot runs. The pilot_calibration module provides the tools; Phase II.4 provides the campaign loop orchestration.

### 5.4 No changes needed to existing code

This subphase only adds new files. No existing fuzzer, executor, or coverage code was modified.

---

## 6. Files Touched

| File | Change |
|------|--------|
| a4/standalone/pilot_calibration.py | **New**: PilotRunStats, CalibratedParams, calibrate_from_pilot, compute_N_pilot, collect_pilot_stat, _percentile, _is_crash. |
| a4/standalone/tests/test_pilot_calibration.py | **New**: 20 unit tests. |
| a4/docs/touch/Phase II/PHASE_II_1_5_IMPLEMENTATION_REPORT.md | This report. |

No changes to: arm_universe.py, executor.py, fuzzer.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs, coverage_db.py, step_selector.py.

---

## 7. Completion Checklist

- [x] Step II.1.5.1: pilot_calibration.py with PilotRunStats, CalibratedParams, calibrate_from_pilot, compute_N_pilot.
- [x] Step II.1.5.2: collect_pilot_stat helper.
- [x] Step II.1.5.3: 20 unit tests passing.
- [ ] Step II.1.5.4 (optional): Integration test with real mutations -- skipped.
- [x] No changes to existing fuzzer, executor, bandit, or C++/Rust.

---

## 8. Variable Reference

Every variable involved in Phase II.1.5, with full definitions.

### Single-letter and Greek-letter variables

| Variable | Full name | Type | Definition | Context |
|----------|-----------|------|------------|---------|
| **N** | Campaign budget | int | Total number of mutations planned for the campaign | Input to calibration |
| **N_pilot** | Pilot run count | int | `clamp(N//20, 30, 100)` -- how many random mutations to run before activating the bandit | Computed by compute_N_pilot |
| **W** | Rolling window size | int | `clamp(N//20, 30, 150)` -- number of recent runs the saturation test examines | DERIVED from N |
| **H** | Half-life | int | `clamp(N//5, 50, 300)` -- number of iterations until bandit arm statistics are halved in influence | Intermediate for gamma |
| **gamma** (γ) | Discount factor | float | `2^(-1/H)` -- controls how fast old arm statistics fade. 0.9965 for N=1000 | DERIVED from H |
| **K** | Mutation kind count | int | 8 (from A4Fuzzer.MUTATION_KINDS) | From arm universe |
| **c** | UCB exploration coefficient | float | Controls exploration vs exploitation in arm selection. Default 0.25 | A/B tunable |

### Greek-letter and formula variables

| Variable | Full name | Type | Definition | Context |
|----------|-----------|------|------------|---------|
| **tau_new** (τ_new) | Novelty scaling | float | Controls steepness of `S_new = 1 - exp(-delta_new / tau_new)`. Calibrated from 75th percentile of nonzero delta_new, clamped [16, 256] | CALIBRATE ONCE |
| **tau_fail_count** (τ_fail_count) | Cascade penalty | float | Controls `Q_t = exp(-n_fail / tau_fail_count)`. Calibrated from 75th percentile of n_fail (non-crash runs), clamped min 5 | CALIBRATE ONCE |
| **tau_fail_new** (τ_fail_new) | Failure novelty scaling | float | Controls `S_fail_new = 1 - exp(-delta_fail / tau_fail_new)`. HARD constant = 2.0 | HARD |
| **lambda_fail** (λ) | Failure novelty weight | float | Weight for failure novelty in combined reward. Default 0.2 | A/B tunable |

### Per-run statistics

| Variable | Full name | Type | Definition | Context |
|----------|-----------|------|------------|---------|
| **delta_new** (Δ_new_t) | New touch count | int | Number of bitmap buckets touched by this run that are NOT in the global bitmap | Per-run, from count_new_bits |
| **abs_U** (abs(U_t)) | Touched set size | int | Number of distinct nonzero buckets in this run's bitmap | Per-run, from distinct_touched |
| **n_fail** (n^fail_t) | Failure count | int | Total number of constraint failure instances in this run | Per-run, len(failures) |
| **K_rare** | Rare bit count | int | Number of rarest-touched buckets to average for rarity score. `clamp(floor(0.02 * median(abs_U)), 16, 64)` | CALIBRATE ONCE |

### Reward components (used by Phase II.2, parameterized here)

| Variable | Formula | Range | What it measures |
|----------|---------|-------|-----------------|
| **S_new** | `1 - exp(-delta_new / tau_new)` | [0, 1] | How much new coverage this run found (bounded novelty) |
| **S_rare** | `(1/K_rare) * sum(w(i) for i in top-K_rare by rarity)` | (0, 1] | How rare the touched contexts are |
| **S_fail_new** | `1 - exp(-delta_fail / tau_fail_new)` | [0, 1] | Whether new failure contexts were found |
| **Q_t** | `exp(-n_fail / tau_fail_count)` or 0 if crash | [0, 1] | Execution quality (penalty for garbage cascades) |
| **r_t** | `min(1, Q_t * (S_touch + lambda * S_fail_new) / (1 + lambda))` | [0, 1] | Final reward for the bandit |

---

*End of Phase II.1.5 Implementation Report.*

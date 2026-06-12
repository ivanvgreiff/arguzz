# Phase II.2 Implementation Report: CoverageState + Reward

This report describes the implementation and testing of Phase II.2 (CoverageState + Reward Function), deviations from the plan, key variables and functions, testing performed, and insights for Phase II.3.

**Reference plan**: [PHASE_II_2_IMPLEMENTATION_PLAN.md](./PHASE_II_2_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.2 was implemented as specified. A new `coverage_state.py` module provides `CoverageState`, `compute_reward`, and `update_state`. 21 unit tests pass covering all reward components, state update mechanics, edge cases, and the update-order contract. No deviations from the plan.

**Goal of this subphase**: Build the reward function -- the mathematical formula that evaluates how "good" each mutation run was, and the coverage state that tracks campaign-level information needed for that evaluation.

---

## 2. Deviations from the Phase II.2 Implementation Plan

None. All steps were implemented exactly as specified:
- CoverageState class with all fields (global_bitmap, freq, fail_freq, rolling_window, diagnostics).
- compute_reward as a pure function (does not modify state).
- update_state as a separate mutation function.
- 21 unit tests covering all paths.

---

## 3. Key Variables and Functions

### 3.1 CoverageState class

Holds all mutable campaign-level state. Created once after pilot calibration.

**Fields**:
- **global_bitmap** (bytearray, 65536 entries): The max-merged touch bitmap. `global_bitmap[i] > 0` means bucket i has been touched by at least one run. Used by `count_new_bits` to detect new buckets.
- **freq** (list of 65536 ints): Run-frequency per bitmap bucket. `freq[i]` = number of runs that touched bucket i. Used by the rarity score: `w(i) = 1/sqrt(1+freq[i])`. A bucket with freq=1 (touched by only one run) is rarer than one with freq=50 (touched by many runs).
- **fail_freq** (dict, FailKey -> int): Run-frequency per failure context. `fail_freq[(loc, major, minor)]` = number of runs that produced this failure. Used for failure novelty: a failure context not in fail_freq is "new."
- **rolling_window** (deque, maxlen=W): Last W values of delta_new. Used for saturation detection: `median(window) < 1` triggers switch from novelty mode to rarity mode.
- **total_runs** (int): Campaign run counter.
- **maj_seen** (dict, major -> int): Diagnostic counter -- how many failure instances per major category. Not fed into reward.
- **maj_min_seen** (dict, (major,minor) -> int): Diagnostic counter -- how many failure instances per (major,minor) pair. Not fed into reward.
- **params** (CalibratedParams): Reference to the frozen parameters from pilot calibration.

### 3.2 compute_reward(touch_bitmap, failures, exit_code, state) -> (float, dict)

Pure function. Reads CoverageState, returns (reward, diagnostics). Does NOT modify state.

**Flow**:
1. If crash or no bitmap: return reward=0, mode="crash".
2. Compute delta_new = count_new_bits(run_bitmap, state.global_bitmap).
3. Compute S_new = 1 - exp(-delta_new / tau_new). Range [0,1]. Measures "how much new coverage."
4. Check saturation: if rolling window is full AND median < 1, switch to rarity mode.
5. Compute S_rare: for each touched bucket i, compute rarity weight w(i) = 1/sqrt(1+freq[i]). Take the K_rare buckets with highest w (rarest). Average their weights. Range (0,1].
6. S_touch = S_new if novelty mode, S_rare if rarity mode.
7. Compute delta_fail = number of failure contexts not in fail_freq (new failures).
8. Compute S_fail_new = 1 - exp(-delta_fail / tau_fail_new). Range [0,1].
9. Compute Q = exp(-n_fail / tau_fail_count). Range [0,1]. Penalizes garbage cascades.
10. Final: r = min(1, Q * (S_touch + lambda * S_fail_new) / (1 + lambda)).

**Diagnostics dict**: Contains all intermediate values (delta_new, S_new, sat, S_rare, S_touch, delta_fail, S_fail_new, n_fail, Q, r, mode). This enables logging and debugging without re-computation.

### 3.3 update_state(touch_bitmap, failures, delta_new, state) -> None

Mutates CoverageState. Called AFTER compute_reward.

**Steps** (in order per master plan section 3.4):
1. Merge touch_bitmap into global_bitmap (element-wise max).
2. Increment freq[i] for each touched bucket.
3. Increment fail_freq[(loc,major,minor)] for each distinct failure context in this run (deduplicated: same context appearing multiple times in one run increments by 1, not by count).
4. Append delta_new to rolling window.
5. Increment total_runs.
6. Update diagnostic counters (maj_seen, maj_min_seen).

### 3.4 Why compute_reward is a standalone function (not a CoverageState method)

Keeping it as a standalone function that takes state as a parameter (rather than `state.compute_reward(...)`) makes the purity contract explicit: the function signature shows it does not own or modify the state. It also makes unit testing simpler -- you construct a CoverageState, call the function, and check the output without worrying about side effects.

---

## 4. Testing Performed

### 4.1 Unit tests

**Command**: `python -m pytest a4/standalone/tests/test_coverage_state.py -v`
**Result**: 21 passed in 2.12s.

| Test class | Count | What they verify |
|-----------|-------|-----------------|
| TestCoverageState | 1 | Initialization: all fields correct size, zeros, empty dicts |
| TestComputeReward | 11 | All reward components and edge cases |
| TestUpdateState | 9 | All state update mechanics |

**Detailed test coverage**:

| Test | Reward component tested |
|------|------------------------|
| test_crash_returns_zero | Q=0, r=0 when exit code is SIGSEGV |
| test_no_bitmap_returns_zero | Q=0, r=0 when touch_bitmap is None |
| test_first_run_high_novelty | S_new high, Q=1 (no failures), r > 0.5 |
| test_no_novelty_zero_S_new | delta_new=0 when global already saturated |
| test_rarity_mode_when_saturated | sat=True when window full of zeros; S_rare used |
| test_rarity_prefers_rare_buckets | Buckets with low freq get higher weight |
| test_failure_novelty | New failure contexts increase S_fail_new |
| test_failure_novelty_no_new | Already-seen failures produce S_fail_new=0 |
| test_cascade_penalty | Q approaches 0 with many failures |
| test_reward_bounded_0_1 | r always in [0, 1] |
| test_novelty_mode_before_window_full | Stay in novelty mode if window not yet full |
| test_merges_bitmap | global_bitmap updated after merge |
| test_increments_freq | freq[i] incremented per run |
| test_increments_fail_freq | fail_freq updated per failure context |
| test_fail_freq_deduplicates_per_run | Same context in one run increments by 1 only |
| test_appends_to_rolling_window | delta_new appended to deque |
| test_increments_total_runs | Counter goes up |
| test_none_bitmap_still_updates | Crash run still updates fail_freq and window |
| test_diagnostic_counters | maj_seen and maj_min_seen track failures |
| test_update_order_matters | Run 1 gets high reward; run 2 (same bitmap) gets lower |

---

## 5. Insights for Phase II.3 (Bandit)

### 5.1 The reward function is fully self-contained

Phase II.3 (bandit) only needs the `float` reward value from `compute_reward`. It does not need to understand the reward internals. The bandit's `update(arm, step, reward, t)` method takes the float and updates its arm statistics. This clean separation means the bandit can be developed and tested independently.

### 5.2 The diagnostics dict enables rich logging

Phase II.4 (campaign loop) can log the full diagnostics dict per run. This includes the mode (novelty vs rarity), all sub-scores, and the saturation flag. This will be critical for understanding bandit behavior and for Phase II.5 (A/B experiments).

### 5.3 Saturation will trigger quickly for our guest

From Phase 3.3's observation: touch coverage saturates after the first run (~1599 new bits, then 0). The rolling window will fill with zeros quickly, triggering rarity mode. This means the rarity score will dominate the campaign. The rarity score rewards runs that touch buckets with LOW freq -- i.e., buckets that few previous runs touched. Since all value mutations touch the same ~1599 buckets, freq will be roughly uniform and S_rare will be approximately constant across runs. Only INSTR_TYPE_MOD mutations (which change which constraints are evaluated) can create freq asymmetry. This means the bandit should learn to prefer INSTR_TYPE_MOD arms -- which is the desired behavior.

### 5.4 The ACCEPTED override

The plan defers the ACCEPTED (bug) override to Phase II.4. When the campaign loop detects `verifier_accepted == True`, it should set `r = 1.0` regardless of what compute_reward returned. This is a one-line override in the campaign loop, not in compute_reward.

### 5.5 Performance

compute_reward iterates over 65536 entries to find touched indices and compute rarity weights. On synthetic data this takes ~2ms. This is negligible compared to the ~30-90s host execution per run.

---

## 6. Files Touched

| File | Change |
|------|--------|
| a4/standalone/coverage_state.py | **New**: CoverageState, compute_reward, update_state. |
| a4/standalone/tests/test_coverage_state.py | **New**: 21 unit tests. |
| a4/docs/touch/Phase II/PHASE_II_2_IMPLEMENTATION_REPORT.md | This report. |

No changes to: pilot_calibration.py, arm_universe.py, fuzzer.py, executor.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs.

---

## 7. Completion Checklist

- [x] Step II.2.1: CoverageState class.
- [x] Step II.2.2: compute_reward function.
- [x] Step II.2.3: update_state function.
- [x] Step II.2.4: 21 unit tests passing.
- [x] No changes to existing modules.

---

## 8. Variable Reference

### Reward component variables (per run)

| Variable | Symbol | Type | Range | Definition |
|----------|--------|------|-------|------------|
| delta_new | Δ_new_t | int | >= 0 | Number of bitmap buckets newly touched by this run (not in global bitmap before) |
| S_new | S^new_t | float | [0, 1] | Novelty score: `1 - exp(-delta_new / tau_new)`. How much new coverage this run found. |
| sat | sat_t | bool | {0, 1} | Saturation flag: True if median of rolling window < 1 (most recent runs found no new bits) |
| S_rare | S^rare_t | float | (0, 1] | Rarity score: average of `1/sqrt(1+freq[i])` over K_rare rarest touched buckets |
| S_touch | S^touch_t | float | [0, 1] | Touch score: S_new if novelty mode, S_rare if rarity mode |
| delta_fail | Δ^fail_t | int | >= 0 | Number of failure contexts not previously seen in the campaign |
| S_fail_new | S^fail-new_t | float | [0, 1] | Failure novelty: `1 - exp(-delta_fail / tau_fail_new)` |
| n_fail | n^fail_t | int | >= 0 | Total constraint failure instances in this run |
| Q | Q_t | float | [0, 1] | Execution quality: `exp(-n_fail / tau_fail_count)`, or 0 if crash |
| r | r_t | float | [0, 1] | Final reward: `min(1, Q * (S_touch + lambda * S_fail_new) / (1 + lambda))` |

### Global state variables (campaign-level)

| Variable | Symbol | Type | Definition |
|----------|--------|------|------------|
| global_bitmap | G[i] | bytearray(65536) | Max-merged bitmap: G[i]>0 means bucket i was touched by some run |
| freq | freq[i] | list of 65536 ints | Run-frequency: how many runs touched bucket i |
| fail_freq | ffreq[c] | dict | Run-frequency per FailKey (constraint_loc, major, minor) |
| rolling_window | - | deque(maxlen=W) | Last W values of delta_new for saturation detection |
| total_runs | - | int | Total mutation runs completed |

### Parameter variables (from CalibratedParams)

| Variable | Symbol | Type | Definition |
|----------|--------|------|------------|
| tau_new | τ_new | float | Novelty scaling: larger = more new bits needed for high S_new |
| tau_fail_count | τ_fail_count | float | Cascade penalty: larger = more failures tolerated before Q drops |
| tau_fail_new | τ_fail_new | float | Failure novelty scaling: HARD constant = 2.0 |
| K_rare | K_rare | int | Number of rarest buckets to average for S_rare |
| W | W | int | Rolling window size for saturation detection |
| lambda_fail | λ | float | Failure novelty weight in combined reward. Default 0.2 |

### Rarity weight

| Variable | Symbol | Definition |
|----------|--------|------------|
| w(i) | w(i) | `1 / sqrt(1 + freq[i])` -- rarity weight for bitmap bucket i. High when freq is low (rare). |

---

*End of Phase II.2 Implementation Report.*

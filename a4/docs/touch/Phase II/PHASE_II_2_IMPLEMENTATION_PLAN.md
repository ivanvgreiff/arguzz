## Q4: How was K_rare = 31 calculated?

From the `test_typical_pilot` test in `test_pilot_calibration.py`:

1. The test creates 50 PilotRunStats. All have `abs_U=1599` (every run touches 1599 bitmap buckets — this matches our real guest measurement from Phase 3.2).

2. `calibrate_from_pilot` filters to runs with `has_bitmap=True` (all 50). It takes `abs_U` from each: `[1599, 1599, 1599, ..., 1599]` (50 values).

3. It computes `median_abs_U = statistics.median([1599]*50) = 1599.0`.

4. It computes `K_rare = int(math.floor(0.02 * 1599.0)) = int(math.floor(31.98)) = 31`.

5. Clamp to [16, 64]: 31 is already in range, so K_rare = 31.

The source code for this computation is in `pilot_calibration.py` lines 173-177:
```python
median_abs_U = statistics.median(abs_U_values)
K_rare = int(math.floor(0.02 * median_abs_U))
K_rare = max(16, min(64, K_rare))
```

The 0.02 factor comes from Pro_Report_5 section 11 item (15): "K_rare := clamp(floor(0.02U), 16, 64)".

# Phase II.2 Detailed Implementation Plan: CoverageState + Reward

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.2** (CoverageState + Reward Function). It is consistent with [PHASE_II_MASTER_IMPLEMENTATION_PLAN.md](./PHASE_II_MASTER_IMPLEMENTATION_PLAN.md) section 3 (Reward Function) and section 5 (Phase II.2).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites from Previous Sub-Phases

### 1.1 What exists

- **Phase I**: `touch_coverage.py` with `count_new_bits`, `merge_into_global`, `make_global_bitmap`, `distinct_touched`, `A4_TOUCH_MAP_SIZE=65536`.
- **Phase II.0**: `baseline_touch.py` with `BaselineTouch` snapshot (1599 distinct, 192676 total).
- **Phase II.1**: `arm_universe.py` with `ArmUniverse` (T, B_count, B, arms).
- **Phase II.1.5**: `pilot_calibration.py` with `CalibratedParams` (tau_new, tau_fail_count, K_rare, W, gamma, lambda_fail, c_explore, tau_fail_new).
- **Fuzzer**: `global_touch_bitmap: bytearray(65536)` in `fuzzer.py` (Phase 3.3). `MutationExecutionResult.touch_bitmap: Optional[bytes]`, `.failures: List[ConstraintFailure]`, `.exit_code: int`.
- **ConstraintFailure**: has `.constraint_loc()`, `.major`, `.minor` (Phase 0.1).

### 1.2 What Phase II.2 does NOT do

- Does NOT implement the bandit (Phase II.3).
- Does NOT modify the campaign loop (Phase II.4).
- Does NOT modify fuzzer.py.
- Only creates the `CoverageState` class and `compute_reward` / `update_state` functions as a standalone module.

---

## 2. Source-of-Truth Facts

### 2.1 Reward function specification (from master plan section 3)

The reward function has five components, combined into a final bounded [0,1] reward:

1. **Novelty score** S_new: `1 - exp(-delta_new / tau_new)` where delta_new = count of new bitmap buckets.
2. **Saturation indicator** sat: `1 if median(rolling_window) < 1 else 0`.
3. **Rarity score** S_rare: average of `1/sqrt(1+freq[i])` over the K_rare rarest-touched buckets.
4. **Failure novelty** S_fail_new: `1 - exp(-delta_fail / tau_fail_new)` where delta_fail = new failure contexts.
5. **Execution quality** Q: `0` if crash/no bitmap, else `exp(-n_fail / tau_fail_count)`.
6. **Touch score** S_touch: S_new if not saturated, S_rare if saturated.
7. **Final reward** r: `min(1, Q * (S_touch + lambda * S_fail_new) / (1 + lambda))`. Override r=1 if ACCEPTED.

### 2.2 Update order (from master plan section 3.4)

After computing reward for run t:
1. Update seen bitmap (G[i]) for all touched indices.
2. Update freq[i] += 1 for all touched indices.
3. Update ffreq[c] += 1 for all failure contexts.
4. Append delta_new to rolling window.

### 2.3 Global state needed (from master plan section 5, Phase II.2)

- `global_bitmap: bytearray(MAP_SIZE)` -- seen/max bitmap (already exists in fuzzer.py as `global_touch_bitmap`).
- `freq: array of uint32[MAP_SIZE]` -- per-bucket run-frequency (NEW: how many runs touched bucket i).
- `fail_freq: dict[(constraint_loc, major, minor) -> int]` -- per-FailKey run-frequency (NEW).
- `rolling_window: deque(maxlen=W)` -- last W values of delta_new (NEW).
- `maj_seen: dict[int -> int]` -- diagnostic: per-major touch count (NEW, per Pro_Report_5 section 10).
- `maj_min_seen: dict[(int,int) -> int]` -- diagnostic: per-(major,minor) touch count (NEW).

### 2.4 Existing code that CoverageState wraps

- `count_new_bits(run_bitmap, global_bitmap)` from `touch_coverage.py` line 58: counts bitmap buckets where `run[i]>0 and global[i]==0`.
- `merge_into_global(run_bitmap, global_bitmap)` from `touch_coverage.py` line 72: element-wise max merge.
- `make_global_bitmap()` from `touch_coverage.py` line 53: zeroed bytearray(65536).

### 2.5 Crash detection

Same signals as `fuzzer.py` lines 329-331 and `pilot_calibration.py`'s `_is_crash`: exit codes in `{-11,-6,-8,-9,-10}` or `{139,134,136,137,138}`.

---

## 3. Step-by-Step Implementation Plan

### Step II.2.1: Create `coverage_state.py` module with CoverageState class

**Goal**: A class that holds all global coverage state for a campaign and provides methods for querying and updating.

**Actions**:

1. Create `a4/standalone/coverage_state.py` with:

   - `CoverageState` class:
     - `__init__(self, params: CalibratedParams)`:
       - `self.global_bitmap: bytearray = make_global_bitmap()`
       - `self.freq: list = [0] * A4_TOUCH_MAP_SIZE` (run-frequency per bucket; plain list of ints -- no need for array module overhead at 65536 entries)
       - `self.fail_freq: Dict[Tuple[str,int,int], int] = {}` (FailKey -> run count)
       - `self.rolling_window: deque = deque(maxlen=params.W)`
       - `self.total_runs: int = 0`
       - `self.maj_seen: Dict[int, int] = {}` (diagnostic)
       - `self.maj_min_seen: Dict[Tuple[int,int], int] = {}` (diagnostic)
       - `self.params: CalibratedParams = params` (reference to parameters)

**Why a class**: CoverageState holds mutable campaign-level state that is read by compute_reward and written by update_state. A class bundles the state and makes the interface clear.

**Deliverable**: CoverageState class with all global state fields initialized.

---

### Step II.2.2: Implement `compute_reward`

**Goal**: Given a run's results and the current CoverageState, compute the reward and diagnostic dict WITHOUT modifying state.

**Actions**:

1. In `coverage_state.py`, add function:

   `compute_reward(touch_bitmap: Optional[bytes], failures: List[ConstraintFailure], exit_code: int, state: CoverageState) -> Tuple[float, dict]`

   Logic (following master plan section 3.3 exactly):

   a. **Check for crash/no bitmap**: If `_is_crash(exit_code)` or `touch_bitmap is None`, set `Q = 0`, skip touch/fail scores, return `r = 0` with diagnostics.

   b. **Compute delta_new**: `count_new_bits(touch_bitmap, state.global_bitmap)`.

   c. **Compute S_new**: `1 - math.exp(-delta_new / state.params.tau_new)`.

   d. **Compute sat**: Check if `len(state.rolling_window) >= state.params.W` and `statistics.median(state.rolling_window) < 1`. If window is not full yet, sat=0 (novelty mode).

   e. **Compute S_rare**: Get touched indices `U = [i for i in range(MAP_SIZE) if touch_bitmap[i]>0]`. For each i in U, compute `w(i) = 1/sqrt(1+state.freq[i])`. Sort by w descending, take top K_rare. Average the w values. If `|U| < K_rare`, average over `|U|` instead.

   f. **Compute S_touch**: `S_new if sat==0 else S_rare`.

   g. **Compute delta_fail**: Count failure contexts `(f.constraint_loc(), f.major, f.minor)` not in `state.fail_freq`.

   h. **Compute S_fail_new**: `1 - math.exp(-delta_fail / state.params.tau_fail_new)`.

   i. **Compute n_fail**: `len(failures)`.

   j. **Compute Q**: `math.exp(-n_fail / state.params.tau_fail_count)`.

   k. **Compute r**: `min(1.0, Q * (S_touch + state.params.lambda_fail * S_fail_new) / (1 + state.params.lambda_fail))`.

   l. **ACCEPTED override**: Not checked here (compute_reward doesn't know the outcome classification; the caller handles this in Phase II.4 by checking verifier_accepted).

   m. **Return** `(r, diagnostics)` where diagnostics is a dict with keys: `delta_new`, `S_new`, `sat`, `S_rare`, `S_touch`, `delta_fail`, `S_fail_new`, `n_fail`, `Q`, `r`, `mode` ("novelty" or "rarity").

**Why a standalone function (not a method)**: Keeps compute_reward pure -- it reads state but does not write it. This makes it unit-testable: construct a fake CoverageState, call compute_reward, check the output.

**Deliverable**: `compute_reward` function.

---

### Step II.2.3: Implement `update_state`

**Goal**: After reward is computed, update CoverageState with this run's data.

**Actions**:

1. In `coverage_state.py`, add function:

   `update_state(touch_bitmap: Optional[bytes], failures: List[ConstraintFailure], delta_new: int, state: CoverageState) -> None`

   Logic (following master plan section 3.4):

   a. If `touch_bitmap is not None`:
      - `merge_into_global(touch_bitmap, state.global_bitmap)` -- updates G[i].
      - For each i where `touch_bitmap[i] > 0`: `state.freq[i] += 1`.

   b. For each failure in failures:
      - key = `(f.constraint_loc(), f.major, f.minor)`
      - `state.fail_freq[key] = state.fail_freq.get(key, 0) + 1`

   c. `state.rolling_window.append(delta_new)`

   d. `state.total_runs += 1`

   e. Diagnostic counters: for each failure, update `state.maj_seen[f.major]` and `state.maj_min_seen[(f.major, f.minor)]`.

**Why delta_new is a parameter**: It was already computed by compute_reward. Passing it in avoids recomputing.

**Deliverable**: `update_state` function.

---

### Step II.2.4: Unit tests

**Goal**: Verify reward computation and state update with synthetic data.

**Actions**:

1. Create `a4/standalone/tests/test_coverage_state.py` with:

   - **test_reward_first_run_novelty**: Empty state, run with 1599 new bits -> high S_new, Q based on failure count, r > 0.
   - **test_reward_no_novelty**: State where global already has all buckets -> delta_new=0, S_new=0.
   - **test_reward_crash_is_zero**: Crash exit code -> r=0 regardless of bitmap.
   - **test_reward_no_bitmap_is_zero**: touch_bitmap=None -> r=0.
   - **test_reward_rarity_mode**: Fill rolling window with zeros to trigger sat=1, verify S_rare is used.
   - **test_reward_failure_novelty**: New failure context -> S_fail_new > 0.
   - **test_reward_cascade_penalty**: Many failures -> Q close to 0 -> low reward.
   - **test_update_state_merges_bitmap**: After update, global bitmap has the run's entries.
   - **test_update_state_increments_freq**: freq[i] increases by 1 for touched buckets.
   - **test_update_state_increments_fail_freq**: fail_freq increases for seen failure contexts.
   - **test_update_state_appends_to_window**: rolling_window grows.
   - **test_update_order_matters**: compute_reward THEN update_state; second run sees updated state.

**Deliverable**: Comprehensive unit tests.

---

## 4. Files to Touch (Phase II.2 only)

| File | Change |
|------|--------|
| a4/standalone/coverage_state.py | **New**: CoverageState, compute_reward, update_state. |
| a4/standalone/tests/test_coverage_state.py | **New**: Unit tests for reward and state update. |

No changes to: pilot_calibration.py, arm_universe.py, fuzzer.py, executor.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs.

---

## 5. Alignment with Master Plan

| Master plan reference | Phase II.2 coverage | Notes |
|----------------------|---------------------|-------|
| Section 3.3: All five reward components | compute_reward implements all five | As specified. |
| Section 3.4: Update order | update_state follows exact order | As specified. |
| Section 5 Phase II.2: CoverageState with seen, freq, fail_freq, rolling window | CoverageState class | As specified. |
| Section 5 Phase II.2: Major/minor diagnostic counters | maj_seen, maj_min_seen in CoverageState | As specified (Pro_Report_5 section 10). |
| Section 5 Phase II.2: compute_reward deterministic and unit-testable | Standalone function, does not modify state | As specified. |

### Deviations from master plan

1. **`freq` as plain list instead of `array.array('I')`**: The master plan suggests `array('I')`. Phase II.2 uses a plain Python `list` of ints. **Reason**: At 65536 entries, a list of ints is ~0.5MB and operations take ~5ms -- negligible. `array.array` would save memory but add import complexity. If profiling shows a bottleneck, we can switch later.

2. **ACCEPTED override not in compute_reward**: The master plan says "if ACCEPTED, override r=1." Phase II.2's compute_reward does not check for ACCEPTED because `MutationExecutionResult` doesn't have a `verifier_accepted` field at the `compute_reward` level -- that classification happens in the fuzzer's `_run_single_mutation`. The override will be applied by the caller in Phase II.4. **Reason**: compute_reward takes bitmap + failures + exit_code, not the full fuzzer result. Keeping it focused on these inputs makes it testable without depending on fuzzer internals.

3. **S_rare when |U| < K_rare**: The master plan says "taking top K_rare (or fewer if |U_t|<K)." Phase II.2 averages over `min(K_rare, |U|)` entries. If `|U|=0` (no touched buckets), S_rare=0. This handles the edge case.

No other deviations.

---

## 6. Key Variables and Functions

### 6.1 CoverageState

Holds all mutable campaign-level state:
- **global_bitmap**: bytearray(65536). G[i]>0 means bucket i has been touched by some run.
- **freq**: list of 65536 ints. freq[i] = number of runs that touched bucket i.
- **fail_freq**: dict mapping FailKey (constraint_loc, major, minor) -> number of runs that produced this failure.
- **rolling_window**: deque(maxlen=W) of recent delta_new values. Used for saturation detection.
- **total_runs**: int, campaign-level run counter.
- **maj_seen, maj_min_seen**: diagnostic counters for major/minor coverage.

### 6.2 compute_reward(touch_bitmap, failures, exit_code, state) -> (float, dict)

Pure function. Reads state, returns (reward, diagnostics). Does not modify state.

### 6.3 update_state(touch_bitmap, failures, delta_new, state) -> None

Mutates state: merges bitmap, increments freq, increments fail_freq, appends to rolling window.

---

## 7. Completion Checklist

- [ ] Step II.2.1: CoverageState class in coverage_state.py.
- [ ] Step II.2.2: compute_reward function.
- [ ] Step II.2.3: update_state function.
- [ ] Step II.2.4: Unit tests.
- [ ] No changes to existing modules.

---

## 8. Dependencies for Phase II.3 (reminders)

Phase II.3 (Bandit) needs:
- CalibratedParams (from II.1.5): gamma, c_explore.
- ArmUniverse (from II.1): available_arms, steps_in_arm, n_min.
- compute_reward and update_state (from II.2): used in campaign loop.

Phase II.3 does NOT depend on CoverageState directly -- it only receives the reward value (float) from compute_reward. The bandit updates its own arm statistics with that reward.

---

## 9. For Anyone New: What Phase II.2 Is and Why

### What

Phase II.2 builds the **reward function** -- the mathematical formula that evaluates how "good" each mutation run was. After every mutation, the reward function looks at:

- Did this run touch constraint contexts we've never seen before? (novelty)
- Did this run touch constraint contexts that are rarely seen? (rarity)
- Did this run discover new constraint failures? (failure novelty)
- Did this run produce a garbage cascade of failures? (quality penalty)

It combines these signals into a single number between 0 and 1. This number is what the bandit scheduler (Phase II.3) uses to learn which mutation kinds and program regions are worth exploring more.

### Why

Without a reward function, the bandit has no signal to learn from. Phase II.1 built the action space (what the bandit can choose). Phase II.1.5 calibrated the parameters (how to scale the scores). Phase II.2 builds the function that turns run outcomes into learning signal.

### How it differs

| Phase | What | Nature |
|-------|------|--------|
| II.0 | Baseline snapshot | Measurement |
| II.1 | Arm universe | Action space |
| II.1.5 | Parameter calibration | Configuration |
| **II.2** (this) | **Reward function + coverage state** | **Core algorithm** |
| II.3 | Bandit scheduler | Selection algorithm |
| II.4 | Campaign loop integration | Wiring |

Phase II.2 is the first sub-phase that implements actual algorithmic logic (not just data structures or configuration). It is the bridge between "what happened in this run" and "how should the bandit update its beliefs."

---

## 10. New and Withheld Sections

**Sections retained**: All from previous plans.
**Sections withheld**: Variable reference (deferred -- the Phase II.1.5 report already has a comprehensive variable reference that covers the reward components. Phase II.2's report will update it if needed).
**New sections**: None.

---

*End of Phase II.2 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*

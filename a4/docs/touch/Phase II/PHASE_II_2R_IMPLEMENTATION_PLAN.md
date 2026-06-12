# Phase II.2R Detailed Implementation Plan: Reward Rework

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.2R** (Reward Rework). It revises the reward function and calibration based on Pro_Report_6.md and Pro_Report_7.md before implementing the Discounted-UCB bandit (Phase II.3).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites

### 1.1 What exists and needs reworking

| File | Current state | What changes |
|------|--------------|-------------|
| `coverage_state.py` | CoverageState with rolling_window; compute_reward with saturation switch + old Q; update_state always updates | Remove rolling_window; rewrite compute_reward (5 components + revised Q + weighted average); update_state only for valid runs |
| `pilot_calibration.py` | CalibratedParams with tau_fail_count, K_rare, W, lambda_fail; calibrate_from_pilot calibrates these | Replace tau_fail_count with tau_d; remove W (no rolling window); add weights + cascade params; tighten tau_T clamp; add d_fail to PilotRunStats |
| `test_coverage_state.py` | 21 tests for old reward | Rewrite for new reward components |
| `test_pilot_calibration.py` | 20 tests for old calibration | Update for new params |

### 1.2 Key decisions from Pro_Report_6 and Pro_Report_7

All decisions are final (no open questions):
- **K_F_rare = 2** (HARD, not calibrated)
- **Z gating**: outcome==REJECTED AND proof_generated==True AND d_fail==0
- **Baseline seeding**: freq_touch[i]=1 for baseline-touched buckets
- **Crash handling**: bandit gets r=0; coverage state NOT updated
- **n_min = 1** (both arm and step level)
- **Weights**: a_Tn=1.0, a_Tr=0.25, a_Fn=1.0, a_Fr=1.0, a_Z=1.0
- **Cascade**: r_0=10, tau_r=25
- **No rolling window / saturation switch**

### 1.3 What Phase II.2R does NOT do

- Does NOT implement the bandit (II.3)
- Does NOT modify the campaign loop (II.4)
- Does NOT modify fuzzer.py
- Does NOT modify C++ code
- Only rewrites coverage_state.py, pilot_calibration.py, and their tests

---

## 2. Source-of-Truth: Current Code vs Required Changes

### 2.1 CoverageState (`coverage_state.py` line 44-61)

**Current fields**:
- `global_bitmap: bytearray(65536)` — KEEP
- `freq: List[int]` (65536 entries) — KEEP (renamed conceptually to f_T)
- `fail_freq: Dict[Tuple, int]` — KEEP (renamed conceptually to f_F)
- `rolling_window: deque(maxlen=W)` — **REMOVE**
- `total_runs: int` — KEEP
- `maj_seen, maj_min_seen: Dict` — KEEP (diagnostics)

**New fields needed**: None structurally. But need a `seed_from_baseline(baseline_bitmap)` method.

### 2.2 CalibratedParams (`pilot_calibration.py` line 62-82)

**Current fields**: tau_new, tau_fail_count, K_rare, W, gamma, lambda_fail, c_explore, tau_fail_new

**New fields needed**: tau_d (replaces tau_fail_count), r_0, tau_r, K_T_rare (renamed from K_rare), a_Tn, a_Tr, a_Fn, a_Fr, a_Z. Remove W and lambda_fail.

### 2.3 PilotRunStats (`pilot_calibration.py` line 51-58)

**Current fields**: delta_new, abs_U, n_fail, is_crash, has_bitmap

**New field needed**: `d_fail: int` (distinct failure contexts). Required for calibrating tau_d.

### 2.4 compute_reward (`coverage_state.py` line 64-130)

**Complete rewrite** — new 5-component formula with revised Q.

### 2.5 update_state (`coverage_state.py` line 133-174)

**Modify** — only update for valid runs (not crash/missing bitmap). Currently always updates.

---

## 3. Step-by-Step Implementation Plan

### Step II.2R.1: Update CalibratedParams

**Goal**: Replace old params with new params matching Pro_Report_6/7 spec.

**Actions**:

1. In `pilot_calibration.py`, replace `CalibratedParams` dataclass:

   Remove: `tau_fail_count`, `W`, `lambda_fail`
   
   Keep: `tau_new`, `gamma`, `c_explore`, `tau_fail_new`
   
   Add:
   - `tau_d: float` — distinct-failure penalty scale (calibrated, replaces tau_fail_count)
   - `K_T_rare: int` — touch rarity K (renamed from K_rare for clarity)
   - `r_0: int = 10` — cascade threshold (HARD)
   - `tau_r: float = 25.0` — cascade penalty slope (HARD)
   - `K_F_rare: int = 2` — failure rarity K (HARD)
   - `a_Tn: float = 1.0` — touch novelty weight
   - `a_Tr: float = 0.25` — touch rarity weight
   - `a_Fn: float = 1.0` — failure novelty weight
   - `a_Fr: float = 1.0` — failure rarity weight
   - `a_Z: float = 1.0` — zero-fail indicator weight

**Deliverable**: Updated CalibratedParams with all new parameters.

---

### Step II.2R.2: Update PilotRunStats and collect_pilot_stat

**Goal**: Add d_fail to pilot stats so tau_d can be calibrated.

**Actions**:

1. Add `d_fail: int` to `PilotRunStats` dataclass.

2. In `collect_pilot_stat`, compute d_fail:
   ```python
   fail_contexts = set()
   for f in exec_result.failures:
       fail_contexts.add((f.constraint_loc(), f.major, f.minor))
   d_fail = len(fail_contexts)
   ```

**Deliverable**: PilotRunStats includes d_fail.

---

### Step II.2R.3: Update calibrate_from_pilot

**Goal**: Calibrate tau_d instead of tau_fail_count; tighten tau_T clamp; remove W.

**Actions**:

1. **tau_T**: Change clamp from [16, 256] to [8, 128].

2. **tau_d** (NEW, replaces tau_fail_count): 
   ```python
   d_fail_values = [s.d_fail for s in pilot_stats if not s.is_crash and s.has_bitmap]
   tau_d = max(1.0, _percentile(d_fail_values, 75)) if d_fail_values else 3.0
   ```

3. **K_T_rare**: Same formula as old K_rare (renamed). `clamp(0.02 * median(abs_U), 16, 64)`.

4. **Remove W computation** (no rolling window needed).

5. **Keep gamma computation** (unchanged).

6. Return new CalibratedParams with all new fields.

**Deliverable**: calibrate_from_pilot produces the new parameter set.

---

### Step II.2R.4: Add baseline seeding to CoverageState

**Goal**: CoverageState can be initialized from a baseline touch bitmap so pilot calibration sees incremental novelty.

**Actions**:

1. Add method to CoverageState:
   ```python
   def seed_from_baseline(self, baseline_bitmap: bytes) -> None:
       for i in range(A4_TOUCH_MAP_SIZE):
           if baseline_bitmap[i] > 0:
               self.global_bitmap[i] = max(self.global_bitmap[i], baseline_bitmap[i])
               self.freq[i] = 1  # one "run" (the baseline) touched this
   ```

2. Remove `rolling_window` from `__init__`.

**Source code fact**: `baseline_touch.py` `BaselineTouch.bitmap` is `bytes` of length 65536 — directly usable.

**Deliverable**: CoverageState.seed_from_baseline method; no rolling_window.

---

### Step II.2R.5: Rewrite compute_reward

**Goal**: Implement the complete revised reward function from the master plan §2.

**Actions**:

1. New signature (adds `outcome` and `proof_generated` for Z gating):
   ```python
   def compute_reward(
       touch_bitmap: Optional[bytes],
       failures: List[ConstraintFailure],
       exit_code: int,
       outcome: str,           # "REJECTED", "CRASH", "ACCEPTED", etc.
       proof_generated: bool,
       state: CoverageState,
   ) -> Tuple[float, dict]:
   ```

2. Implementation follows master plan §2.4-2.6 exactly:
   - Crash/missing bitmap → r=0, mode="crash"
   - Compute F_t (distinct failure contexts), d_fail, r_rep
   - Compute Δ_T (count_new_bits), Δ_F (new failure contexts)
   - T_new = 1 - exp(-Δ_T / tau_T)
   - T_rare from top-K_T_rare rarest touched buckets
   - F_new = 1 - exp(-Δ_F / tau_F_new)
   - F_rare from top-K_F_rare (=2) rarest failure contexts
   - Z = 1 if (outcome=="REJECTED" and proof_generated and d_fail==0) else 0
   - Q_dist = exp(-d_fail / tau_d)
   - Q_rep = 1 if r_rep <= r_0 else exp(-(r_rep - r_0) / tau_r)
   - Q = Q_dist * Q_rep
   - S = weighted average of (T_new, T_rare, F_new, F_rare, Z) with weights (a_Tn, a_Tr, a_Fn, a_Fr, a_Z)
   - r = min(1, Q * S)
   - ACCEPTED override: r = 1

3. Diagnostics dict includes all intermediate values.

**Deliverable**: Complete rewritten compute_reward.

---

### Step II.2R.6: Update update_state

**Goal**: Only update coverage state for valid runs (not crash/missing bitmap).

**Actions**:

1. Add a `valid_run` check at the top:
   ```python
   if touch_bitmap is None or _is_crash(exit_code):
       state.total_runs += 1  # count the run but don't update coverage
       return
   ```

2. Rest of update logic stays the same (merge bitmap, increment freq, increment fail_freq per-run-per-context).

3. Remove rolling_window append (no longer exists).

**Deliverable**: update_state only updates f_T, f_F, seen for valid runs.

---

### Step II.2R.7: Update unit tests

**Goal**: All tests pass with the new reward formula.

**Actions**:

1. Rewrite `test_coverage_state.py` tests:
   - test_reward_crash_zero: crash → r=0, state not updated
   - test_reward_no_bitmap_zero: no bitmap → r=0
   - test_reward_touch_novelty: high Δ_T → high T_new component
   - test_reward_touch_rarity: runs with different freq → different T_rare
   - test_reward_failure_novelty: new failure contexts → F_new > 0
   - test_reward_failure_rarity: rare failure contexts → high F_rare
   - test_reward_zero_fail_indicator: Z fires when REJECTED + proof_generated + d_fail==0
   - test_reward_Z_not_on_crash: Z does not fire for crash
   - test_reward_Z_not_without_proof: Z does not fire if proof_generated==False
   - test_reward_cascade_penalty: r_rep > r_0 → Q_rep < 1
   - test_reward_no_cascade_penalty: r_rep <= r_0 → Q_rep = 1
   - test_reward_distinct_fail_penalty: more d_fail → lower Q_dist
   - test_reward_weighted_average: verify S is correct weighted average
   - test_reward_accepted_override: ACCEPTED → r=1
   - test_update_valid_run: bitmap + freq + fail_freq updated
   - test_update_crash_no_coverage_change: crash run doesn't update freq/fail_freq
   - test_update_order: compute before update gives correct deltas
   - test_baseline_seeding: after seed, freq[i]=1 for baseline buckets

2. Update `test_pilot_calibration.py` tests:
   - test_calibrate_tau_d: verify tau_d from p75(d_fail)
   - test_calibrate_no_rolling_window: W no longer in params
   - test_d_fail_in_pilot_stats: verify d_fail computed correctly
   - test_tau_T_tighter_clamp: verify [8, 128] range

**Deliverable**: All tests pass.

---

## 4. Files to Touch (Phase II.2R only)

| File | Change |
|------|--------|
| `a4/standalone/coverage_state.py` | Remove rolling_window; add seed_from_baseline; rewrite compute_reward (5 components + Q + weighted avg); update update_state (valid-run gating) |
| `a4/standalone/pilot_calibration.py` | Rewrite CalibratedParams (new fields); add d_fail to PilotRunStats; rewrite calibrate_from_pilot (tau_d, tighter clamps, no W) |
| `a4/standalone/tests/test_coverage_state.py` | Rewrite all tests for new reward |
| `a4/standalone/tests/test_pilot_calibration.py` | Update tests for new params |

No changes to: fuzzer.py, executor.py, arm_universe.py, baseline_touch.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs.

---

## 5. Alignment with Master Plan

| Master plan reference | Phase II.2R coverage | Notes |
|----------------------|---------------------|-------|
| §2.4: 5 component scores | Step II.2R.5 | All 5 implemented |
| §2.5: Revised Q (Q_dist * Q_rep) | Step II.2R.5 | r_0=10 threshold, tau_r=25 |
| §2.6: Weighted average S | Step II.2R.5 | With default weights |
| §2.7: Remove saturation switch | Step II.2R.4 (remove rolling_window), Step II.2R.5 (no sat logic) | Confirmed |
| §3.1 HARD: K_F_rare=2, r_0=10, tau_r=25 | Step II.2R.1 (CalibratedParams) | As specified |
| §3.3 CALIBRATE: tau_d, tau_T clamp [8,128] | Step II.2R.3 | As specified |
| §9 resolved: Z gating, baseline seeding, crash handling | Steps II.2R.4, II.2R.5, II.2R.6 | All per Pro_Report_7 |

### Deviations from master plan

1. **compute_reward signature change**: Added `outcome: str` and `proof_generated: bool` parameters. **Reason**: Z gating requires knowing the run outcome and whether proof was generated. The old signature only had `exit_code`. The caller (Phase II.4) has access to both through `MutationResult.verifier_accepted`, `MutationResult.proof_verify_failed`, and `MutationResult.proof_generated` in fuzzer.py.

2. **PilotRunStats.d_fail added**: **Reason**: Required for calibrating tau_d. The old PilotRunStats only had n_fail (raw instance count). d_fail is the number of distinct (constraint_loc, major, minor) contexts.

No other deviations.

---

## 6. Key Variables and Functions

### 6.1 New CalibratedParams fields

| Field | Type | Source | Purpose |
|-------|------|--------|---------|
| tau_d | float | Calibrated: max(1, p75(d_fail)) | Distinct-failure penalty: Q_dist = exp(-d_fail / tau_d) |
| K_T_rare | int | Calibrated: clamp(0.02 * median(abs_U), 16, 64) | Touch rarity: top-K_T for T_rare |
| K_F_rare | int | HARD: 2 | Failure rarity: top-K_F for F_rare |
| r_0 | int | HARD: 10 | Cascade threshold: Q_rep=1 if r_rep <= r_0 |
| tau_r | float | HARD: 25.0 | Cascade slope: Q_rep = exp(-(r_rep - r_0) / tau_r) |
| a_Tn..a_Z | float | HARD defaults | Weights for 5-component weighted average |

### 6.2 New reward components

| Component | Formula | Range | What it measures |
|-----------|---------|-------|-----------------|
| T_new | 1 - exp(-Δ_T / tau_T) | [0,1] | How many new touch bitmap buckets this run found |
| T_rare | avg of top-K_T rarest w_T(i) | (0,1] | How rare the touched buckets are across the campaign |
| F_new | 1 - exp(-Δ_F / tau_F_new) | [0,1] | How many new failure context_ids this run found |
| F_rare | avg of top-K_F rarest w_F(c) | [0,1] | How rare the failure contexts are across the campaign |
| Z | 0 or 1 | {0,1} | 1 if REJECTED + proof_generated + no local failures |

### 6.3 Revised Q

| Component | Formula | When |
|-----------|---------|------|
| Q_dist | exp(-d_fail / tau_d) | Always (penalizes more distinct failures) |
| Q_rep | 1 | r_rep <= 10 (no cascade penalty) |
| Q_rep | exp(-(r_rep - 10) / 25) | r_rep > 10 (cascade penalty) |
| Q | Q_dist * Q_rep | Combined; 0 if crash |

---

## 7. Completion Checklist

- [ ] Step II.2R.1: CalibratedParams updated with new fields
- [ ] Step II.2R.2: PilotRunStats.d_fail + collect_pilot_stat updated
- [ ] Step II.2R.3: calibrate_from_pilot updated (tau_d, tighter clamp, no W)
- [ ] Step II.2R.4: CoverageState.seed_from_baseline + remove rolling_window
- [ ] Step II.2R.5: compute_reward rewritten (5 components + Q + weighted avg + Z gating)
- [ ] Step II.2R.6: update_state with valid-run gating
- [ ] Step II.2R.7: All tests pass
- [ ] No changes to fuzzer, executor, C++, or Rust

---

## 8. Dependencies for Phase II.2V (reminders)

Phase II.2V (Reward Verification) will:
1. Run a 200-mutation diagnostic with the revised reward
2. Verify reward variance across non-INSTR_TYPE_MOD arms
3. Verify Z-events get high reward
4. Verify cascades are suppressed without erasing information
5. Compare reward distributions between mutation kinds

---

## 9. For Anyone New: What Phase II.2R Is and Why

### What

Phase II.2R is a **rework** of the reward function that evaluates each mutation run. The original reward (Phase II.2) was designed around the assumption that touch coverage (which constraint contexts were evaluated) would be the main differentiating signal between mutation runs. A 200-mutation diagnostic campaign revealed that this assumption was wrong: touch coverage saturates after a single run for 7 of 8 mutation kinds, providing zero signal for the bandit to learn from.

The rework makes the reward **co-primary** between touch signals and failure-context signals. Failure contexts (which constraints actually FAILED, at which major/minor dispatch values) provide a much richer signal: 31% of runs discover new failure contexts throughout the campaign, compared to only 8% for new touch contexts.

### Why now (before the bandit)

The bandit (Phase II.3) learns from reward signals. If the reward is near-constant across most arms (as the original reward would be after touch saturation), the bandit can't learn useful preferences and degenerates to random selection. Fixing the reward before implementing the bandit ensures the bandit has meaningful signal to learn from on day one.

### How Phase II.2R differs from other phases

| Phase | What | Nature |
|-------|------|--------|
| II.0-II.2 | Original infrastructure | Building blocks |
| **II.2R** (this) | **Reward rework based on empirical data** | **Course correction** |
| II.2V | Verify the rework works | Validation |
| II.3+ | Bandit + integration | Core scheduling |

Phase II.2R is the only phase that goes back and rewrites existing code. All other phases add new functionality. This makes it a "course correction" phase — it exists because we tested our assumptions with real data and found they needed adjustment.

---

## 10. New and Withheld Sections

**Sections retained**: All from previous plans (prerequisites, source-of-truth, steps, files, alignment, key variables, checklist, dependencies, for-anyone-new).

**Sections withheld**: None.

**New sections**: None.

---

*End of Phase II.2R Implementation Plan. All assertions are tied to the cited files and code facts.*

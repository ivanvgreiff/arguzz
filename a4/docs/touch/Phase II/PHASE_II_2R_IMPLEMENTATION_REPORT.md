# Phase II.2R Implementation Report: Reward Rework

This report describes the implementation and testing of Phase II.2R (Reward Rework), deviations from the plan, key variables and functions, and insights for Phase II.2V.

**Reference plan**: [PHASE_II_2R_IMPLEMENTATION_PLAN.md](./PHASE_II_2R_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.2R was implemented as specified. Both `coverage_state.py` and `pilot_calibration.py` were rewritten. 46 unit tests pass (26 for coverage_state, 20 for pilot_calibration). All 85 non-host-dependent tests in the project pass.

**Goal**: Revise the reward function so the bandit has meaningful signal to differentiate arms across all 8 mutation kinds, not just INSTR_TYPE_MOD. The original reward (touch-primary with failure-secondary at lambda=0.2) provided near-constant reward for 7/8 kinds after touch saturation. The revised reward uses 5 co-primary components with failure-context rarity as the key new bandwidth signal.

---

## 2. Deviations from Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| seed_from_baseline | `max(global_bitmap[i], baseline_bitmap[i])` | `self.global_bitmap[i] = baseline_bitmap[i]` | Direct assignment is simpler and equivalent when called on a fresh (zeroed) state |
| No other deviations | - | - | All steps implemented as specified |

---

## 3. Key Variables and Functions

### 3.1 CalibratedParams (pilot_calibration.py)

Completely rewritten dataclass. New fields:

| Field | Type | Source | Purpose |
|-------|------|--------|---------|
| tau_new | float | Calibrated: p75 of nonzero delta_T, clamp [8, 128] | Touch novelty scaling: T_new = 1 - exp(-delta_T / tau_new) |
| tau_d | float | Calibrated: max(1, p75(d_fail)) | Distinct-failure penalty: Q_dist = exp(-d_fail / tau_d) |
| K_T_rare | int | Calibrated: clamp(0.02 * median(abs_U), 16, 64) | Touch rarity: average of top-K_T rarest touched buckets |
| gamma | float | Derived: 2^(-1/H), H = clamp(N//5, 50, 300) | Bandit discount factor |
| tau_F_new | float | HARD: 2.0 | Failure novelty scaling: F_new = 1 - exp(-delta_F / tau_F_new) |
| K_F_rare | int | HARD: 2 | Failure rarity: average of top-2 rarest failure contexts |
| r_0 | int | HARD: 10 | Cascade threshold: Q_rep = 1 when r_rep <= 10 |
| tau_r | float | HARD: 25.0 | Cascade slope: Q_rep = exp(-(r_rep - 10) / 25) when r_rep > 10 |
| c_explore | float | HARD: 0.25 | UCB exploration coefficient |
| a_Tn | float | HARD: 1.0 | Weight for touch novelty |
| a_Tr | float | HARD: 0.25 | Weight for touch rarity |
| a_Fn | float | HARD: 1.0 | Weight for failure novelty |
| a_Fr | float | HARD: 1.0 | Weight for failure rarity |
| a_Z | float | HARD: 1.0 | Weight for zero-fail indicator |

Removed fields: tau_fail_count, W, lambda_fail, K_rare.

### 3.2 PilotRunStats (pilot_calibration.py)

Added `d_fail: int` — number of distinct failure context_ids `(constraint_loc, major, minor)` in this run. Required for calibrating tau_d.

### 3.3 CoverageState (coverage_state.py)

Removed: `rolling_window` (no saturation switch).

Added: `seed_from_baseline(baseline_bitmap: bytes)` — sets global_bitmap[i] = baseline_bitmap[i] and freq[i] = 1 for all baseline-touched buckets.

### 3.4 compute_reward (coverage_state.py)

Complete rewrite. New signature adds `outcome: str` and `proof_generated: bool` for Z gating.

**5 component scores**:
- **T_new**: Touch novelty. `1 - exp(-delta_T / tau_new)`. High when many new bitmap buckets found.
- **T_rare**: Touch rarity. Average of `1/sqrt(1+freq[i])` for the K_T_rare rarest touched buckets. Differentiates INSTR_TYPE_MOD runs that touch rare buckets.
- **F_new**: Failure novelty. `1 - exp(-delta_F / tau_F_new)`. High when new failure context_ids found.
- **F_rare**: Failure rarity. Average of `1/sqrt(1+fail_freq[c])` for the 2 rarest failure contexts. This is the KEY NEW SIGNAL — provides bandwidth across all mutation kinds after novelty decays.
- **Z**: Zero-local-fail indicator. 1 if outcome==REJECTED AND proof_generated AND d_fail==0. Rewards runs that "got deep enough" to pass all local constraints.

**Revised Q (execution quality)**:
- `Q_dist = exp(-d_fail / tau_d)` — penalizes more distinct failures
- `Q_rep = 1 if r_rep <= 10, else exp(-(r_rep-10)/25)` — penalizes cascades only when repeats exceed threshold
- `Q = Q_dist * Q_rep` (0 if crash/missing bitmap)

**Final reward**:
- `S = weighted_average(T_new, T_rare, F_new, F_rare, Z)` with weights (1.0, 0.25, 1.0, 1.0, 1.0)
- `r = min(1, Q * S)`
- Override: r = 1 if ACCEPTED

### 3.5 update_state (coverage_state.py)

Key change: **valid-run gating**. If crash or missing bitmap, only increment total_runs — do NOT update freq, fail_freq, or global_bitmap. This prevents crashes from corrupting rarity statistics (Pro_Report_7).

---

## 4. Testing

### 4.1 Coverage state tests (26 tests)

| Category | Tests | What they verify |
|----------|-------|-----------------|
| Init | 2 | CoverageState creation; seed_from_baseline sets freq=1 |
| T_new | 1 | Touch novelty: delta_T → T_new formula |
| T_rare | 1 | Touch rarity: different freq → different T_rare |
| F_new | 2 | Failure novelty: new contexts → F_new > 0; already-seen → 0 |
| F_rare | 2 | Failure rarity: rare contexts ranked correctly; no failures → 0 |
| Z | 4 | Z fires on REJECTED+proof+d_fail==0; not on crash; not without proof; not with failures |
| Q_dist | 1 | More distinct failures → lower Q_dist |
| Q_rep | 2 | Below r_0 → Q_rep=1; above r_0 → Q_rep < 1 (cascade penalty) |
| Weighted avg | 1 | Zero-weight components excluded from average |
| ACCEPTED | 1 | Override r=1 |
| Bounded | 1 | 0 <= r <= 1 |
| Crash zero | 2 | Crash and no-bitmap both return r=0 |
| Update valid | 1 | Valid run updates bitmap, freq, fail_freq |
| Update crash | 2 | Crash and no-bitmap DON'T update coverage (only total_runs) |
| Dedup | 1 | fail_freq increments once per context per run (not per instance) |
| Freq incr | 1 | freq[i] increments per run |
| Order | 1 | compute_reward before update_state gives correct deltas |

### 4.2 Pilot calibration tests (20 tests)

| Category | Tests | What they verify |
|----------|-------|-----------------|
| N_pilot | 3 | Budget → pilot count formula |
| Percentile | 2 | Helper function edge cases |
| Calibrate | 10 | tau_new clamps [8,128], tau_d from d_fail, K_T_rare scaling, no W, hard defaults, gamma scaling |
| Collect stat | 4 | d_fail counted, no bitmap handling, does not modify global |

### 4.3 Full test suite

85 non-host-dependent tests pass (0.88s). No regressions.

---

## 5. Insights for Phase II.2V

### 5.1 What II.2V needs to verify

The revised reward should produce **meaningful variance** across non-INSTR_TYPE_MOD arms. Specifically:
- After touch saturation (run 1), T_new ≈ 0 and T_rare ≈ constant for value mutations. The reward's ability to differentiate arms depends on F_new, F_rare, and Z.
- Different mutation kinds at different steps should produce different failure context compositions, giving different F_rare scores.
- Z events (REJECTED + proof_generated + no local failures) should get higher reward than similar runs with failures.

### 5.2 Baseline seeding is critical for pilot

The pilot's tau_T calibration depends on whether the global state is seeded from baseline. Without seeding, run 1 produces delta_T ≈ 1614, which clamps tau_T to 128 (the max). With seeding, run 1 produces delta_T ≈ 0 (baseline already in global), and only INSTR_TYPE_MOD runs produce nonzero delta_T ≈ 30-50, giving a more useful tau_T ≈ 30-50.

### 5.3 The diagnostic script needs updating for II.2V

The current diagnostic script (`run_diagnostic_campaign.py`) computes the OLD reward formula. For II.2V, it needs to compute the NEW reward per-run and report reward distributions by kind.

---

## 6. Files Touched

| File | Change |
|------|--------|
| a4/standalone/pilot_calibration.py | Complete rewrite: CalibratedParams (new fields), PilotRunStats (+d_fail), calibrate_from_pilot (tau_d, tighter clamp, no W) |
| a4/standalone/coverage_state.py | Complete rewrite: CoverageState (no rolling_window, +seed_from_baseline), compute_reward (5 components + Q + weighted avg), update_state (valid-run gating) |
| a4/standalone/tests/test_coverage_state.py | Complete rewrite: 26 tests for new reward |
| a4/standalone/tests/test_pilot_calibration.py | Rewritten: 20 tests for new params |
| a4/docs/touch/Phase II/PHASE_II_2R_IMPLEMENTATION_REPORT.md | This report |

No changes to: fuzzer.py, executor.py, arm_universe.py, baseline_touch.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs.

---

## 7. Completion Checklist

- [x] Step II.2R.1: CalibratedParams updated
- [x] Step II.2R.2: PilotRunStats.d_fail + collect_pilot_stat updated
- [x] Step II.2R.3: calibrate_from_pilot updated (tau_d, clamp [8,128], no W)
- [x] Step II.2R.4: CoverageState.seed_from_baseline + rolling_window removed
- [x] Step II.2R.5: compute_reward rewritten (5 components + Q + weighted avg + Z gating)
- [x] Step II.2R.6: update_state with valid-run gating
- [x] Step II.2R.7: 46 tests pass; 85 total project tests pass
- [x] No changes to fuzzer, executor, C++, or Rust

---

## 8. Variable Reference

### Per-run observations

| Variable | Symbol | Type | Definition |
|----------|--------|------|------------|
| touch bitmap | X_t | bytes(65536) | Raw bitmap from C++ witgen |
| touched set | U_t | set of int | {i : X_t[i] > 0} (bitmap bucket indices) |
| failure list | L_t | List[ConstraintFailure] | All failure instances from this run |
| failure context set | F_t | set of (str,int,int) | {(constraint_loc, major, minor)} distinct contexts |
| raw failure count | n_fail | int | len(L_t) — total instances |
| distinct failure count | d_fail | int | len(F_t) — distinct contexts |
| cascade repeat mass | r_rep | int | max(0, n_fail - d_fail) — excess instances beyond distinct |
| touch novelty | Δ_T (delta_T) | int | Number of bitmap buckets newly touched |
| failure novelty | Δ_F (delta_F) | int | Number of failure contexts never seen before |

### Global state

| Variable | Symbol | Type | Definition |
|----------|--------|------|------------|
| touch seen | G[i] | bytearray(65536) | global_bitmap[i] > 0 means bucket i was touched |
| touch frequency | f_T[i] (freq[i]) | list of 65536 int | Number of valid runs that touched bucket i |
| failure frequency | f_F[c] (fail_freq[c]) | dict | Number of valid runs whose F_t contained context c |
| total runs | total_runs | int | All runs including crashes |

### Reward components

| Variable | Symbol | Range | Formula |
|----------|--------|-------|---------|
| Touch novelty score | T_new | [0, 1] | 1 - exp(-Δ_T / τ_T) |
| Touch rarity score | T_rare | (0, 1] | avg of 1/sqrt(1+f_T[i]) for top-K_T_rare rarest i in U_t |
| Failure novelty score | F_new | [0, 1] | 1 - exp(-Δ_F / τ_F_new) |
| Failure rarity score | F_rare | [0, 1] | avg of 1/sqrt(1+f_F[c]) for top-2 rarest c in F_t |
| Zero-fail indicator | Z | {0, 1} | 1 if REJECTED AND proof_generated AND d_fail==0 |

### Quality multiplier

| Variable | Symbol | Range | Formula |
|----------|--------|-------|---------|
| Distinct-fail penalty | Q_dist | [0, 1] | exp(-d_fail / τ_d) |
| Cascade penalty | Q_rep | [0, 1] | 1 if r_rep <= r_0, else exp(-(r_rep - r_0) / τ_r) |
| Combined quality | Q | [0, 1] | Q_dist * Q_rep (0 if crash) |

### Final reward

| Variable | Symbol | Range | Formula |
|----------|--------|-------|---------|
| Weighted score | S | [0, 1] | (a_Tn*T_new + a_Tr*T_rare + a_Fn*F_new + a_Fr*F_rare + a_Z*Z) / (a_Tn + a_Tr + a_Fn + a_Fr + a_Z) |
| Reward | r_t | [0, 1] | min(1, Q * S). Override: r=1 if ACCEPTED. |

### Parameters

| Parameter | Symbol | Value | How determined |
|-----------|--------|-------|---------------|
| τ_T (tau_new) | τ_T | ~30-50 typical | Calibrated: p75 of nonzero Δ_T, clamp [8, 128] |
| τ_d (tau_d) | τ_d | ~2-3 typical | Calibrated: max(1, p75(d_fail)) |
| K_T_rare | K_T | ~31 typical | Calibrated: 0.02 * median(abs(U_t)), clamp [16, 64] |
| γ (gamma) | γ | ~0.9965 | Derived: 2^(-1/H), H from budget |
| τ_F_new (tau_F_new) | τ_{F,new} | 2.0 | HARD |
| K_F_rare | K_F | 2 | HARD |
| r_0 | r_0 | 10 | HARD |
| τ_r (tau_r) | τ_r | 25.0 | HARD |
| c (c_explore) | c | 0.25 | HARD |
| a_Tn | a_{Tn} | 1.0 | HARD |
| a_Tr | a_{Tr} | 0.25 | HARD |
| a_Fn | a_{Fn} | 1.0 | HARD |
| a_Fr | a_{Fr} | 1.0 | HARD |
| a_Z | a_Z | 1.0 | HARD |

---

*End of Phase II.2R Implementation Report.*

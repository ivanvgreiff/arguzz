# Phase II Master Implementation Plan: Coverage-Guided Scheduling

This document is the **master implementation plan** for Phase II. It was originally derived from Pro_Report_4.md and Pro_Report_5.md, then **revised based on empirical data** from a 200-mutation diagnostic campaign (Concerns.md) and expert review (Pro_Report_6.md).

**Rule**: No guesses. All statements are tied to file paths and code facts.

**Foundational documents**: Pro_Report_4.md (original architecture), Pro_Report_5.md (parameter calibration), Pro_Report_6.md (reward rework based on empirical data). Pro_Report_6 supersedes Pro_Report_4's reward function (§6) and parts of Pro_Report_5's parameter inventory (§11).

---

## 0. Current Status (What Has Been Implemented)

### 0.0 Completed sub-phases

| Sub-Phase | Status | Key deliverables |
|-----------|--------|-----------------|
| Phase I (all) | COMPLETE | Touch instrumentation pipeline (C++ bitmap + base64 emission + Python parser + fuzzer integration) |
| II.0 | COMPLETE | Baseline touch snapshot (1614 exact triples / 1599 bitmap buckets). Rust mod.rs fix for SeqForward. |
| II.1 | COMPLETE | Arm universe (T=3930, B_count=32 for N=1000, 254 arms). `arm_universe.py` with `ArmUniverse` class. |
| II.1.5 | COMPLETE | Pilot calibration functions. `pilot_calibration.py` with `PilotRunStats`, `CalibratedParams`, `calibrate_from_pilot`. |
| II.2 | COMPLETE (superseded) | CoverageState + compute_reward + update_state. `coverage_state.py`. Superseded by II.2R. |
| II.2R | COMPLETE | Revised reward: 5 co-primary components + revised Q + weighted average. 46 unit tests passing. |
| II.2V | COMPLETE | 200-mut verification: reward variance across all 8 kinds (stdev 0.042–0.090), Z-events 2.7× higher, cascades suppressed. All 4 criteria PASS. |

### 0.1 What exists in source code

| Component | File | Status |
|-----------|------|--------|
| Touch bitmap per run | `executor.py` `MutationExecutionResult.touch_bitmap` | Working |
| Touch verbose mode | `ffi.cpp` `A4_COVERAGE_TOUCH_VERBOSE` env var | Working (diagnostic only) |
| Global bitmap + merge | `fuzzer.py` `global_touch_bitmap` + `touch_coverage.py` | Working |
| Failure parsing | `constraint_parser.py` `parse_all_constraint_failures` | Working |
| Failure coverage DB | `coverage_db.py` `record_failures` | Fixed (INSERT OR IGNORE) |
| Arm universe | `arm_universe.py` `ArmUniverse` | Working |
| Pilot calibration | `pilot_calibration.py` | Working (needs parameter updates) |
| CoverageState + reward | `coverage_state.py` | **Needs rework** |
| Baseline touch | `baseline_touch.py` `capture_baseline_touch` | Working |

### 0.2 Key empirical findings (from 200-mutation diagnostic campaign)

- **1614 exact touch triples** at baseline; **2076** after 200 runs (+462, 98% from INSTR_TYPE_MOD)
- **Touch saturates after run 1** for 7 of 8 mutation kinds (only INSTR_TYPE_MOD discovers new touch)
- **163 distinct failure context_ids** `(constraint_loc, major, minor)` from 28 constraint_loc families
- **31% of runs discover new failure context_ids** vs only 8% for touch novelty
- **35 hash collisions** in bitmap (1.7%, acceptable)
- Cascade runs: max 159 failure instances from a single mutation (back-reference propagation)

---

## 1. Sub-Phase Structure (Revised)

Phase II now includes an intermediate rework phase (II.2R) inserted before the bandit implementation, based on Pro_Report_6's recommendation to "fix the reward first, then implement the bandit."

| Sub-Phase | Name | Scope | Status |
|-----------|------|-------|--------|
| **II.0** | Baseline Touch Snapshot | Baseline capture | COMPLETE |
| **II.1** | Arm Universe Construction | Bucketed action space | COMPLETE |
| **II.1.5** | Pilot Calibration | Calibration functions | COMPLETE (params need update) |
| **II.2** | CoverageState + Reward (v1) | Original reward function | COMPLETE (superseded) |
| **II.2R** | **Reward Rework** | Revise reward per Pro_Report_6; update CoverageState, pilot calibration, baseline seeding | COMPLETE |
| **II.2V** | **Reward Verification** | Run 200-mut diagnostic with revised reward; verify variance across arms | COMPLETE |
| **II.3** | **Discounted-UCB Bandit** | Bandit scheduler | **NEXT** |
| **II.4** | Campaign Loop Integration | Wire bandit into fuzzer | After II.3 |
| **II.5** | A/B Experiments + Larger Campaign | Compare uniform vs bandit; tune weights; run 500-1000 campaign | After II.4 |
| **II.6** | Persistence + Resume | Save/load state | After II.4 |

**Phase II.7 (Bug Mode)** remains deferred until ACCEPTED is observed.

---

## 2. Revised Reward Function (Pro_Report_6 §2)

The original reward (Pro_Report_4 §6) used touch novelty/rarity as primary with failure as secondary (λ=0.2). Pro_Report_6 replaces this with a **co-primary** architecture where failure-context signals have equal weight to touch signals.

### 2.1 Per-run observations

- `U_t = {i : bitmap[i] > 0}` — touched bitmap indices
- `F_t = {(constraint_loc, major, minor)}` — distinct failure context_ids in this run
- `n_fail = len(failures)` — raw failure instance count
- `d_fail = |F_t|` — distinct failure contexts in this run
- `r_rep = max(0, n_fail - d_fail)` — cascade repeat mass

### 2.2 Global state

- `G[i]` — touch seen indicator (global_bitmap[i] > 0)
- `f_T[i]` — touch run-frequency (how many runs touched bucket i)
- `f_F[c]` — failure context run-frequency (how many runs produced failure context c). **Per-run-per-context, NOT per-instance.**

### 2.3 Novelty counts

- `Δ_T = |{i ∈ U_t : G[i] == 0}|` — touch novelty (count_new_bits)
- `Δ_F = |{c ∈ F_t : f_F[c] == 0}|` — failure context novelty

### 2.4 Component scores

**Touch novelty**: `T_new = 1 - exp(-Δ_T / τ_T)`

**Touch rarity** (useful for INSTR_TYPE_MOD differentiation):
```
w_T(i) = 1 / sqrt(1 + f_T[i])
T_rare = (1/K_T) * Σ over top-K_T rarest touched buckets of w_T(i)
```
where K_T = min(K_T_rare, |U_t|)

**Failure novelty**: `F_new = 1 - exp(-Δ_F / τ_F_new)`

**Failure rarity** (the key new signal — provides bandwidth after novelty decays):
```
w_F(c) = 1 / sqrt(1 + f_F[c])
F_rare = (1/K_F) * Σ over top-K_F rarest failure contexts of w_F(c)
```
where K_F = min(K_F_rare, |F_t|). If |F_t| = 0, F_rare = 0.

**Zero-local-fail indicator** (rewards runs where no local constraints failed but proof was still rejected — a proxy for "got deep enough that local constraints aren't trivially catching you"):
```
Z = 1 if (outcome == REJECTED AND proof_generated == True AND d_fail == 0) else 0
```
The gating on `proof_generated == True` ensures Z only fires for runs that produced a proof that failed verification, not for shallow aborts (Pro_Report_7 §1).

### 2.5 Execution quality (Q) — revised

**Distinct-failure penalty**: `Q_dist = exp(-d_fail / τ_d)`

**Cascade-repeat penalty** (only activates for true cascades):
```
Q_rep = 1                                  if r_rep <= r_0
Q_rep = exp(-(r_rep - r_0) / τ_r)         if r_rep > r_0
```

**Combined**: `Q = 0` if crash or missing bitmap; else `Q = Q_dist * Q_rep`

### 2.6 Final reward

**Weighted average of components, multiplied by Q**:
```
S = (a_Tn * T_new + a_Tr * T_rare + a_Fn * F_new + a_Fr * F_rare + a_Z * Z) / (a_Tn + a_Tr + a_Fn + a_Fr + a_Z)

r_t = min(1, Q * S)
```

**Override**: if verifier ACCEPTED, r_t = 1.

### 2.7 Key changes from original reward

| Aspect | Original (Pro_Report_4) | Revised (Pro_Report_6) |
|--------|------------------------|----------------------|
| Primary signal | Touch novelty/rarity | Touch + failure signals co-primary |
| Failure signal | Secondary (λ=0.2 weight) | Co-primary (a_Fn=1.0, a_Fr=1.0) |
| Failure rarity | Not present | New: F_rare based on f_F[c] |
| Zero-fail indicator | Not present | New: Z rewards no-local-fail runs |
| Saturation switch | Rolling-window median | **Removed** — both T_new and T_rare are always computed; weighted average handles the transition naturally |
| Q (quality) | exp(-n_fail / τ_fail_count) | Split: Q_dist * Q_rep (distinct vs cascade) |
| Rolling window | Required for saturation switch | **No longer needed** |

---

## 3. Revised Parameter Inventory

### 3.1 HARD parameters

| # | Parameter | Value | Source |
|---|-----------|-------|--------|
| 1 | MAP_SIZE | 65536 | Unchanged (1.7% collision rate acceptable) |
| 2 | TouchKey | (constraint_loc, major, minor) | Unchanged |
| 3 | FailKey | (constraint_loc, major, minor) | Unchanged |
| 4 | τ_F_new | 2.0 | Unchanged (Pro_Report_6 §3.2) |
| 5 | r_0 (cascade threshold) | 10 | **New** (Pro_Report_6 §3.2): don't penalize small repeats |
| 6 | τ_r (cascade penalty slope) | 25 | **New** (Pro_Report_6 §3.2): penalize true cascades |
| 7 | K_F_rare (failure rarity K) | 2 | **New, HARD** (Pro_Report_7): hardcoded, not calibrated. Stable when d_fail is small. |
| 8 | ε (numeric stability) | 1e-6 | Unchanged |
| 9 | n_min (forced exploration) | 1 | Pro_Report_7: for both arm-level and step-level. Higher values cause too much resampling under discounting. |

### 3.2 DERIVED parameters (from budget)

Unchanged from original: T, B_count, B, n_min, γ (Pro_Report_6 §3.1 item 4 confirms these are fine).

### 3.3 CALIBRATE ONCE parameters (from pilot)

| # | Parameter | Calibration | Default | Change from original |
|---|-----------|-------------|---------|---------------------|
| 8 | τ_T (touch novelty) | p75 of {Δ_T > 0} from pilot | 64 | Clamp tightened to [8, 128] (was [16, 256]) |
| 9 | τ_d (distinct-fail penalty) | max(1, p75(d_fail)) from pilot | 3 | **New**: replaces τ_fail_count |
| 10 | K_T_rare (touch rarity K) | clamp(0.02 * median(abs(U)), 16, 64) | 32 | Unchanged |

### 3.4 Weights (co-primary, not A/B initially)

| # | Weight | Value | Rationale (Pro_Report_6 §3.3) |
|---|--------|-------|-------------------------------|
| 12 | a_Tn (touch novelty) | 1.0 | Still matters when it happens (INSTR_TYPE_MOD) |
| 13 | a_Tr (touch rarity) | 0.25 | Keeps INSTR_TYPE_MOD differentiated; low because uniform for value mutations |
| 14 | a_Fn (failure novelty) | 1.0 | Co-primary |
| 15 | a_Fr (failure rarity) | 1.0 | Co-primary: the key new bandwidth signal |
| 16 | a_Z (zero-fail indicator) | 1.0 | Explicitly reward no-local-fail |

### 3.5 TUNE VIA A/B (Phase II.5)

| # | Parameter | Default | A/B range |
|---|-----------|---------|-----------|
| 17 | c (UCB exploration) | 0.25 | {0.15, 0.25, 0.4} |
| 18 | Weights (a_*) | As above | Variations |
| 19 | p_local schedule | 0.7→0.4 | Various schedules |

---

## 4. Bandit Model

Unchanged from original. Discounted-UCB with lazy decay, forced exploration, nested step-level selection. See Pro_Report_4 §7 (confirmed as fine by Pro_Report_6 §6).

---

## 5. Sub-Phase Details

### Phase II.0-II.2: COMPLETE (see individual reports)

---

### Phase II.2R — Reward Rework (NEW)

**Goal**: Revise CoverageState and compute_reward per Pro_Report_6 before implementing the bandit.

**Actions**:
1. Update `CoverageState` in `coverage_state.py`:
   - Remove rolling_window (no longer needed — saturation switch removed)
   - Ensure `fail_freq` increments per-run-per-context (not per-instance) — verify existing code
   - Add baseline seeding method: initialize seen_touch[i]=1 and freq_touch[i]=1 for all baseline-touched buckets (Pro_Report_7 Q3)

2. Update `CalibratedParams` in `pilot_calibration.py`:
   - Replace τ_fail_count with τ_d (distinct-failure penalty scale)
   - Remove K_F_rare from calibration (hardcoded to 2 per Pro_Report_7 Q1)
   - Add weight parameters (a_Tn, a_Tr, a_Fn, a_Fr, a_Z) with defaults
   - Add cascade parameters (r_0=10, τ_r=25) as HARD
   - Tighten τ_T clamp to [8, 128]

3. Update `calibrate_from_pilot` in `pilot_calibration.py`:
   - Calibrate τ_d from max(1, p75(d_fail)) instead of τ_fail_count from p75(n_fail)
   - **Baseline seeding**: Initialize global state from baseline touch snapshot before pilot, so τ_T calibration reflects incremental novelty, not the empty→baseline jump (Pro_Report_6 §4, confirmed Pro_Report_7 Q3)

4. Rewrite `compute_reward` in `coverage_state.py`:
   - Implement all 5 component scores (T_new, T_rare, F_new, F_rare, Z)
   - Z must be gated: `outcome==REJECTED AND proof_generated==True AND d_fail==0` (Pro_Report_7 §1)
   - Implement revised Q (Q_dist * Q_rep with r_0=10 threshold)
   - Implement weighted average S with default weights
   - Remove saturation switch logic
   - **Crash/missing-bitmap handling**: If crash or no bitmap, set r=0 and do NOT update coverage state (Pro_Report_7 §crash). Bandit still gets the 0 reward so it learns to avoid crash-prone arms.

5. Update `update_state` in `coverage_state.py`:
   - Only update coverage state (f_T, f_F, seen) for valid runs (not crash/missing bitmap)
   - Ensure fail_freq increments per-run-per-context (already verified correct)

6. Update unit tests for all changed functions.

**Deliverable**: Revised reward function that provides meaningful variance across all mutation kinds.

---

### Phase II.2V — Reward Verification (NEW)

**Goal**: Run a 200-mutation diagnostic campaign with the revised reward and verify that it actually differentiates arms.

**Actions**:
1. Update the diagnostic script to compute revised reward per-run
2. Run 200 mutations (same seed as original diagnostic for comparison)
3. Verify:
   - Reward variance exists across non-INSTR_TYPE_MOD arms
   - Z-events (no-local-fail) get high reward
   - Cascades are suppressed but not information-erased
   - Failure rarity provides differentiation after novelty decays
4. Document results

**Deliverable**: Verified that revised reward produces meaningful, differentiating signal.

---

### Phase II.3 — Discounted-UCB Bandit

Unchanged from original plan. Implement after II.2V confirms reward is working.

---

### Phase II.4 — Campaign Loop Integration

Unchanged from original plan, except:
- Baseline touch is seeded into CoverageState before pilot (per Pro_Report_6 §4)
- No saturation switch logic needed in campaign loop

---

### Phase II.5 — A/B Experiments + Larger Campaign

Extended from original plan per Pro_Report_6 §7:

**Additional actions**:
1. Run a **500-1000 mutation campaign** with the actual fuzzer value generator (not diagnostic script), logging:
   - Cumulative distinct failure context_ids vs run index
   - Cumulative distinct touch triples vs run index
   - Counts of Z-events (no-local-fail) per kind and per bucket
2. Confirm whether:
   - The 31% failure novelty rate is sustained or front-loaded
   - Which kinds/buckets produce Z-events
   - Failure rarity meaningfully differentiates arms after novelty decays

---

### Phase II.6 — Persistence + Resume

Unchanged from original plan.

---

## 6. Implementation Order (Revised)

```
II.0 (Baseline)        ✓ COMPLETE
    │
    ▼
II.1 (Arm Universe)    ✓ COMPLETE
    │
    ▼
II.1.5 (Pilot Calib)   ✓ COMPLETE (params need update in II.2R)
    │
    ▼
II.2 (Reward v1)       ✓ COMPLETE (superseded by II.2R)
    │
    ▼
II.2R (Reward Rework)  ✓ COMPLETE
    │
    ▼
II.2V (Reward Verify)  ✓ COMPLETE
    │
    ▼
II.3 (Bandit)          ◄── NEXT
    │
    ▼
II.4 (Integration)
    │
    ▼
II.5 (A/B + Large Campaign)
    │
    ▼
II.6 (Persistence)
```

---

## 7. Files Expected to Change

| File | Sub-Phase | Change |
|------|-----------|--------|
| `coverage_state.py` | **II.2R** | Rewrite compute_reward (5 components + revised Q + weighted average); remove rolling_window |
| `pilot_calibration.py` | **II.2R** | Update CalibratedParams (new params); update calibrate_from_pilot (τ_d, K_F_rare, baseline seeding) |
| `test_coverage_state.py` | **II.2R** | Rewrite tests for new reward formula |
| `test_pilot_calibration.py` | **II.2R** | Update tests for new calibration |
| `run_diagnostic_campaign.py` | **II.2V** | Add revised reward computation to diagnostic output |
| `bandit.py` | **II.3** | New: DiscountedUCBScheduler |
| `fuzzer.py` | **II.4** | Bandit-driven campaign loop with baseline seeding |

---

## 8. Consistency with Pro Reports

| Recommendation | Plan coverage | Source |
|---------------|---------------|--------|
| Failure-context signals co-primary | II.2R reward rework | Pro_Report_6 §1-2 |
| Failure rarity (F_rare) as new bandwidth signal | II.2R | Pro_Report_6 §2.2 |
| Zero-fail indicator (Z) | II.2R | Pro_Report_6 §2.2 |
| Refined Q (distinct + cascade split) | II.2R | Pro_Report_6 §2.3 |
| Remove rolling-window saturation switch | II.2R | Pro_Report_6 §6 item 4 |
| Baseline seeding before pilot | II.2R (calibration) | Pro_Report_6 §4 |
| Tighter τ_T clamp [8, 128] | II.2R (calibration) | Pro_Report_6 §3.1 |
| Arm universe unchanged | Confirmed | Pro_Report_6 §6 |
| Discounted-UCB unchanged | Confirmed | Pro_Report_6 §6 |
| MAP_SIZE=65536 unchanged | Confirmed | Pro_Report_6 Q4 |
| 500-1000 campaign for validation | II.5 | Pro_Report_6 §7 |
| Revise reward BEFORE bandit | II.2R before II.3 | Pro_Report_6 §1, §5 Q5 |

---

## 9. Resolved Questions (from Pro_Report_7)

All three open questions from the previous version have been resolved by Pro_Report_7 with explicit decisions:

1. **K_F_rare**: **Hardcoded to 2.** Not calibrated. Stable when d_fail is small, still meaningful when it grows. Eliminates a fragile calibration knob.

2. **Weight sensitivity**: **Keep defaults** (1.0, 0.25, 1.0, 1.0, 1.0) for II.2R+II.2V. Only 3 A/B variants in II.5: (a) default, (b) a_Z=0.5, (c) a_Tn=0.5.

3. **Baseline seeding**: **Yes, seed freq_touch[i]=1** for baseline-touched buckets. This makes rarity meaningful from the start. Do NOT seed fail_freq (baseline has no failures).

Additional explicit decisions from Pro_Report_7:
- **Z gating**: Must check `outcome==REJECTED AND proof_generated==True AND d_fail==0`
- **Crash handling**: Bandit gets reward=0, but coverage state (f_T, f_F) is NOT updated for crash/missing-bitmap runs
- **n_min = 1** for both arm-level and step-level forced exploration
- **p_local = 0.7 constant** for Phase II.3-II.4; schedule variations deferred to II.5
- **TouchKey naming**: Scheduler uses bitmap indices (hashed); exact triples are diagnostic only

---

*End of Phase II Master Implementation Plan (Revised). Based on Pro_Report_4.md, Pro_Report_5.md, Pro_Report_6.md, and empirical data from Concerns.md.*

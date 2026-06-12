# Phase II Master Implementation Plan: Coverage-Guided Scheduling

This document is the **master implementation plan** for Phase II. It was originally derived from Pro_Report_4.md and Pro_Report_5.md, then **revised based on empirical data** from diagnostic campaigns and expert review (Pro_Report_6.md, Pro_Report_7.md), and **updated with presentation strategy and future roadmap** from Pro_Report_8.md.

**Rule**: No guesses. All statements are tied to file paths and code facts.

**Foundational documents**: Pro_Report_4.md (original architecture), Pro_Report_5.md (parameter calibration), Pro_Report_6.md (reward rework), Pro_Report_7.md (parameter decisions), Pro_Report_8.md (A/B strategy, presentation notebook structure, Phase III/IV roadmap). Pro_Report_6 supersedes Pro_Report_4's reward function (§6). Pro_Report_8 supersedes the sub-phase structure for II.5+ and adds Phases III and IV.

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
| II.2V | COMPLETE | 200-mut verification: reward variance across all 8 kinds, Z-events 2.7× higher, cascades suppressed. All 4 criteria PASS. |
| II.3 | COMPLETE | `DiscountedUCBScheduler` in `bandit.py`. 14 unit tests passing. |
| II.4 | COMPLETE | Full bandit pipeline integrated into `fuzzer.py`. Pilot → calibration → bandit loop. 1000-mutation campaign completed successfully (996 executed, 50 pilot + 946 bandit). |

### 0.1 What exists in source code

| Component | File | Status |
|-----------|------|--------|
| Touch bitmap per run | `executor.py` `MutationExecutionResult.touch_bitmap` | Working |
| Touch verbose mode | `ffi.cpp` `A4_COVERAGE_TOUCH_VERBOSE` env var | Working (diagnostic only) |
| Global bitmap + merge | `fuzzer.py` `global_touch_bitmap` + `touch_coverage.py` | Working |
| Failure parsing | `constraint_parser.py` `parse_all_constraint_failures` | Working |
| Failure coverage DB | `coverage_db.py` `record_failures` | Fixed (INSERT OR IGNORE) |
| Arm universe | `arm_universe.py` `ArmUniverse` | Working |
| Pilot calibration | `pilot_calibration.py` | Working |
| CoverageState + reward | `coverage_state.py` | Working (revised 5-component reward) |
| Discounted-UCB bandit | `bandit.py` `DiscountedUCBScheduler` | Working |
| Bandit campaign loop | `fuzzer.py` `_run_bandit_mutation`, `_setup_bandit` | Working |
| Baseline touch capture | `baseline_touch.py` `capture_baseline_touch` | Working |
| Campaign analysis script | `tests/analyze_campaign.py` `parse_terminal`, `RunRecord` | Working (bandit output only) |
| Campaign notebook | `notebooks/campaign_analysis.ipynb` | Working (bandit-only) |

### 0.2 Key empirical findings (from 1000-mutation bandit campaign)

- **996 mutations executed**: 985 REJECTED (98.9%), 11 CRASH (1.1%), 0 ACCEPTED
- **Touch coverage**: baseline 1599 buckets → 2439 after pilot+bandit (+840 total, +729 from bandit)
- **99 Z events** (~10.5% of bandit runs), exclusively from INSTR_WORD_MOD_SUR (51) and INSTR_WORD_MOD_FULL (48)
- **Reward three-tier hierarchy**: IWORD_S (0.154) > IWORD_F (0.129) > ITYPE (0.088) > value mutations (0.029-0.055)
- **16x spread** between best and worst arm mean rewards
- **Arm-level exploitation NOT yet observable**: Pearson r = 0.060 between arm reward and selection count. 3.7 samples/arm is insufficient for exploitation.
- **All 11 crashes** from PRE_EXEC_REG_MOD at step 0 — crash-prone arm
- **Novelty saturation**: mean reward decays from 0.145 (early) to 0.055 (late), driven by F_new exhaustion. F_rare and Z maintain a stable reward floor.
- **Failure novelty rate**: decays from 39% to 6-7% but never reaches zero at 946 runs

---

## 1. Sub-Phase Structure (Revised per Pro_Report_8)

| Sub-Phase | Name | Scope | Status |
|-----------|------|-------|--------|
| **II.0** | Baseline Touch Snapshot | Baseline capture | COMPLETE |
| **II.1** | Arm Universe Construction | Bucketed action space | COMPLETE |
| **II.1.5** | Pilot Calibration | Calibration functions | COMPLETE |
| **II.2** | CoverageState + Reward (v1) | Original reward function | COMPLETE (superseded) |
| **II.2R** | Reward Rework | Revise reward per Pro_Report_6 | COMPLETE |
| **II.2V** | Reward Verification | 200-mut diagnostic | COMPLETE |
| **II.3** | Discounted-UCB Bandit | Bandit scheduler | COMPLETE |
| **II.4** | Campaign Loop Integration | Wire bandit into fuzzer | COMPLETE |
| **II.5a** | **A/B Comparison + Boss Notebook** | Uniform + reduced-arm bandit campaigns + presentation notebook | **NEXT** |
| **II.5a-fix** | Step 0 Crash Fix | Hard-exclude step 0 from PRE_EXEC_REG_MOD | After II.5a campaigns |
| **II.5b** | Weight Tuning A/B | Tune reward weights via A/B experiments | After II.5a |
| **II.6** | Persistence + Resume | Save/load bandit + coverage state | After II.5b |
| **III.0** | Z Signature Analysis | Cluster Z events by reject error | After II.5 |
| **III.1** | Global Constraint Hooks | Instrument permutation argument, etc. | After III.0 |
| **IV.0** | Multi-Program Scheduling | Per-program or contextual bandit | After III.1 |

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
| 5 | r_0 (cascade threshold) | 10 | Pro_Report_6 §3.2 |
| 6 | τ_r (cascade penalty slope) | 25 | Pro_Report_6 §3.2 |
| 7 | K_F_rare (failure rarity K) | 2 | HARD (Pro_Report_7) |
| 8 | ε (numeric stability) | 1e-6 | Unchanged |
| 9 | n_min (forced exploration) | 1 | Pro_Report_7 |

### 3.2 DERIVED parameters (from budget)

Unchanged from original: T, B_count, B, n_min, γ (Pro_Report_6 §3.1 item 4 confirms these are fine).

### 3.3 CALIBRATE ONCE parameters (from pilot)

| # | Parameter | Calibration | Default | Change from original |
|---|-----------|-------------|---------|---------------------|
| 8 | τ_T (touch novelty) | p75 of {Δ_T > 0} from pilot | 64 | Clamp tightened to [8, 128] (was [16, 256]) |
| 9 | τ_d (distinct-fail penalty) | max(1, p75(d_fail)) from pilot | 3 | Replaces τ_fail_count |
| 10 | K_T_rare (touch rarity K) | clamp(0.02 * median(abs(U)), 16, 64) | 32 | Unchanged |

### 3.4 Weights (co-primary, not A/B initially)

| # | Weight | Value | Rationale (Pro_Report_6 §3.3) |
|---|--------|-------|-------------------------------|
| 12 | a_Tn (touch novelty) | 1.0 | Still matters when it happens (INSTR_TYPE_MOD) |
| 13 | a_Tr (touch rarity) | 0.25 | Keeps INSTR_TYPE_MOD differentiated; low because uniform for value mutations |
| 14 | a_Fn (failure novelty) | 1.0 | Co-primary |
| 15 | a_Fr (failure rarity) | 1.0 | Co-primary: the key new bandwidth signal |
| 16 | a_Z (zero-fail indicator) | 1.0 | Explicitly reward no-local-fail |

### 3.5 TUNE VIA A/B (Phase II.5b+)

| # | Parameter | Default | A/B range |
|---|-----------|---------|-----------|
| 17 | c (UCB exploration) | 0.25 | {0.15, 0.25, 0.4} |
| 18 | Weights (a_*) | As above | Variations |
| 19 | p_local schedule | 0.7→0.4 | Various schedules |

---

## 4. Bandit Model

Discounted-UCB with lazy decay, forced exploration, nested step-level selection. Implemented in `bandit.py`. See Pro_Report_4 §7 (confirmed as fine by Pro_Report_6 §6).

---

## 5. Sub-Phase Details

### Phase II.0-II.4: COMPLETE (see individual reports)

---

### Phase II.5a — A/B Comparison + Boss-Facing Notebook (NEXT)

**Goal**: Quantify whether the bandit improves constraint-space exploration efficiency vs random, and produce a presentation-quality notebook.

**Pre-campaign code changes**:
1. Add reward/coverage tracking to non-bandit mode so both campaigns produce comparable per-run metrics
2. Add B_count CLI override for reduced-arm bandit campaign
3. Update analysis script for dual-campaign parsing

**Step 0 crash fix**: Intentionally NOT applied before the new campaigns. The existing bandit campaign ran without this fix, so for a fair A/B comparison, the new campaigns must run under identical conditions. Fix is deferred to Phase II.5a-fix after all campaigns complete.

**Campaigns to run**:
1. **Uniform baseline**: 1000 mutations, `--selector zoned`, same guest+inputs
2. **(Reuse existing)**: 1000-mutation bandit campaign data (from Phase II.4)
3. **Reduced-arm bandit**: 1000 mutations, `--selector bandit --b-count 16`, same guest+inputs

**Metrics to report (each as cumulative curves + final values)** (Pro_Report_8 §4):
- `C_fail(t)` = cumulative distinct failure context_ids
- `C_touch(t)` = cumulative distinct touch buckets
- `C_family(t)` = cumulative distinct constraint_loc families
- `C_Z(t)` = cumulative Z events
- `Crash(t)` = cumulative crashes

**Scalar summary numbers** (Pro_Report_8 §4):
- **AUC** (area under curve) normalized by final value
- **t_80** = iterations to reach 80% of that campaign's final value

**Notebook structure** (Pro_Report_8 §1):
- Section A: Executive summary (one-slide block: what changed, what we measure, headline results, limitations)
- Section B: "Did we explore more?" — cumulative overlay plots (bandit vs uniform)
- Section C: "What did the bandit learn?" — heatmaps + scatter + top arms table
- Section D: "Why Z events matter" — Z-by-kind, Z-by-bucket, Z step distribution
- Section E: Quality/cascades (tightened: one plot + one table)
- Section F: Appendix (algorithm spec)

**Deliverable**: Boss-facing notebook with three-way comparison (uniform, bandit-32, bandit-16) showing 4 overlay plots + summary table of (AUC, t_80) deltas.

---

### Phase II.5a-fix — Step 0 Crash Fix

**Goal**: Eliminate PRE_EXEC_REG_MOD crashes at step 0 for all future campaigns.

**Actions**: Hard-exclude step 0 from PRE_EXEC_REG_MOD valid steps in `inspection_data.py`. One-line change: add `and cycle.step != 0` to the PRE_EXEC_REG_MOD branch.

**Timing**: After all II.5a campaigns complete, so that experimental conditions are identical across the existing bandit campaign, new uniform campaign, and new reduced-arm campaign.

---

### Phase II.5b — Weight Tuning A/B

**Goal**: Test whether different reward weight configurations improve bandit performance.

---

### Phase II.6 — Persistence + Resume

Save/load:
- CoverageState (bitmaps, f_T, f_F)
- Bandit arm/step state (N, S, last_update)
- ArmUniverse parameters and hash of guest+input configuration

---

### Phase III.0 — Z Signature Analysis (Pro_Report_8 §4)

**Goal**: Add structure to Z events without instrumenting global constraints.

**Actions**:
1. Define `Z_signature` from structured verifier/prover error strings (normalize, sort, hash)
2. Track and report: count per Z_signature, novelty/rarity of Z signatures over time
3. Add to notebook: "Top Z reject signatures and counts" bar chart

If one dominant signature → bandit may be finding the same rejection mode repeatedly.
If many signatures → bandit is exploring diverse post-local checks.

---

### Phase III.1 — Global Constraint Hooks

Instrument global checks if feasible (permutation argument, lookup/permutation constraints). Replace Z with explicit global failure contexts where possible.

---

### Phase IV.0 — Multi-Program Scheduling

Either separate bandits per program, or contextual bandit where context = program_id and arms share priors. Do not start until II.5 A/B validates the bandit approach.

---

## 6. Implementation Order (Revised)

```
II.0 (Baseline)        ✓ COMPLETE
    │
    ▼
II.1 (Arm Universe)    ✓ COMPLETE
    │
    ▼
II.1.5 (Pilot Calib)   ✓ COMPLETE
    │
    ▼
II.2 (Reward v1)       ✓ COMPLETE (superseded)
    │
    ▼
II.2R (Reward Rework)  ✓ COMPLETE
    │
    ▼
II.2V (Reward Verify)  ✓ COMPLETE
    │
    ▼
II.3 (Bandit)          ✓ COMPLETE
    │
    ▼
II.4 (Integration)     ✓ COMPLETE
    │
    ▼
II.5a (A/B + Notebook) ◄── NEXT
    │   (includes uniform + reduced-arm campaigns)
    ▼
II.5a-fix (Step 0 Fix)
    │
    ▼
II.5b (Weight Tuning)
    │
    ▼
II.6 (Persistence)
    │
    ▼
III.0 (Z Signatures)
    │
    ▼
III.1 (Global Hooks)
    │
    ▼
IV.0 (Multi-Program)
```

---

## 7. Files Expected to Change (Phases II.5a+)

| File | Sub-Phase | Change |
|------|-----------|--------|
| `fuzzer.py` | **II.5a** | Add `_setup_coverage_tracking()`, reward computation in `_run_single_mutation`, `b_count_override` param, fix `new_coverage` capture in `_run_bandit_mutation` |
| `arm_universe.py` | **II.5a** | Accept optional `b_count_override` |
| `cli.py` | **II.5a** | Add `--b-count` CLI argument |
| `tests/analyze_campaign.py` | **II.5a** | Add `new_coverage` field + regex, cumulative metrics (terminal + DB), AUC/t_80 |
| `notebooks/boss_presentation.ipynb` | **II.5a** | New boss-facing notebook with three-way A/B comparison |
| `inspection_data.py` | **II.5a-fix** | Exclude step 0 from PRE_EXEC_REG_MOD valid steps |
| `fuzzer.py` | **II.6** | Save/load CoverageState + bandit state |

---

## 8. Consistency with Pro Reports

| Recommendation | Plan coverage | Source |
|---------------|---------------|--------|
| Failure-context signals co-primary | II.2R ✓ | Pro_Report_6 §1-2 |
| Failure rarity (F_rare) as new bandwidth signal | II.2R ✓ | Pro_Report_6 §2.2 |
| Zero-fail indicator (Z) | II.2R ✓ | Pro_Report_6 §2.2 |
| Refined Q (distinct + cascade split) | II.2R ✓ | Pro_Report_6 §2.3 |
| Remove rolling-window saturation switch | II.2R ✓ | Pro_Report_6 §6 |
| Baseline seeding before pilot | II.2R ✓ | Pro_Report_6 §4 |
| Tighter τ_T clamp [8, 128] | II.2R ✓ | Pro_Report_6 §3.1 |
| Arm universe unchanged | Confirmed ✓ | Pro_Report_6 §6 |
| Discounted-UCB unchanged | Confirmed ✓ | Pro_Report_6 §6 |
| MAP_SIZE=65536 unchanged | Confirmed ✓ | Pro_Report_6 Q4 |
| Hard-exclude step 0 from PRE_EXEC_REG_MOD | **II.5a-fix** (after campaigns) | Pro_Report_8 §3 |
| Uniform baseline A/B comparison | **II.5a** | Pro_Report_8 §3-4 |
| Reduced-arm bandit (B_count=16) | **II.5a** | Pro_Report_8 §3 |
| Boss-facing notebook structure | **II.5a** | Pro_Report_8 §1 |
| AUC + t_80 scalar metrics | **II.5a** | Pro_Report_8 §4 |
| Z signature analysis | **III.0** | Pro_Report_8 §2, §4 |
| Global constraint hooks | **III.1** | Pro_Report_8 §4 |
| Multi-program scheduling | **IV.0** | Pro_Report_8 §4 |

---

## 9. Resolved Questions (from Pro_Report_7 + Pro_Report_8)

All questions from previous versions have been resolved:

1. **K_F_rare**: Hardcoded to 2 (Pro_Report_7 Q1).
2. **Weight sensitivity**: Keep defaults for now; 3 A/B variants in II.5b (Pro_Report_7).
3. **Baseline seeding**: Yes, seed freq_touch[i]=1 for baseline-touched buckets (Pro_Report_7 Q3).
4. **Z gating**: Must check `outcome==REJECTED AND proof_generated==True AND d_fail==0` (Pro_Report_7 §1).
5. **Crash handling**: Bandit gets reward=0, coverage state NOT updated (Pro_Report_7 §crash).
6. **n_min = 1** for both arm-level and step-level forced exploration (Pro_Report_7).
7. **Step 0 crashes**: Hard-exclude step 0 from PRE_EXEC_REG_MOD (Pro_Report_8 §3). Deferred to II.5a-fix (after A/B campaigns) for experimental consistency.
8. **Z interpretation**: Present as "post-local rejection," NOT "global constraint failure" until instrumented (Pro_Report_8 §2).
9. **A/B is mandatory**: Cannot claim "better than random" without uniform control campaign (Pro_Report_8 §3).

---

*End of Phase II Master Implementation Plan (Revised). Based on Pro_Report_4.md, Pro_Report_5.md, Pro_Report_6.md, Pro_Report_7.md, Pro_Report_8.md, and empirical data from the 1000-mutation bandit campaign.*

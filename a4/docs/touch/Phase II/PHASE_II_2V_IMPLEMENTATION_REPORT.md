# Phase II.2V Implementation Report: Reward Verification

This report describes the implementation and testing of Phase II.2V (Reward Verification), deviations from the plan, key variables and functions, verification campaign results, and insights for Phase II.3.

**Reference plan**: [PHASE_II_2V_IMPLEMENTATION_PLAN.md](./PHASE_II_2V_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.2V was implemented as specified. The diagnostic script (`run_diagnostic_campaign.py`) was updated to compute the revised reward per run using `CoverageState` and `compute_reward`/`update_state`, classify run outcomes, and produce comprehensive analysis output. A 200-mutation campaign was executed successfully (exit_code=0, 4147s total). No production code was modified.

**Goal**: Verify that the revised reward function (Phase II.2R) produces meaningful, arm-differentiating signal before implementing the bandit (Phase II.3). The four verification criteria (§1.2 of the plan) were all evaluated; the results are documented in §4.

---

## 2. Deviations from Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| `proof_generated` detection | Plan §2.2 said "exit_code==0" | Used `_check_proof_generated` logic: "verify segment" OR Prover success OR Verifier output | exit_code==0 is imprecise. The fuzzer's actual `_check_proof_generated` (fuzzer.py:751-783) uses "verify segment" in output, Prover JSON success, or Verifier context output. Matching the real fuzzer logic ensures the diagnostic's outcome classification is identical to production. |
| `outcome` classification | Plan said "REJECTED if failures or proof_verify_failed" | Also gates on `proof_generated` for the Z computation; uses exact fuzzer regex for verifier acceptance | More precise. The `classify_outcome` function returns both `outcome` and `proof_generated` as separate signals, enabling accurate Z computation. |
| No other deviations | - | - | All steps implemented as specified |

---

## 3. What Was Implemented

### 3.1 Outcome Classification (`classify_outcome`)

A standalone function that replicates the fuzzer's multi-step outcome determination:

1. **CRASH**: `exit_code` matches any crash signal (`{-11, -6, -8, -9, -10, 139, 134, 136, 137, 138}`).
2. **proof_generated**: True if "verify segment" in output (proof created but self-verification failed), OR Prover JSON `{"context":"Prover","status":"success"}` present, OR Verifier context present.
3. **ACCEPTED**: Verifier success pattern matched via regex (both `context`-first and `status`-first orderings).
4. **REJECTED**: Has failures (`n_fail > 0`) or "verify segment" in output.
5. **NO_EFFECT**: None of the above.

This was factored into a reusable function `classify_outcome(output, exit_code, n_fail) → (outcome, proof_generated)` rather than inlining into the loop, for clarity.

### 3.2 CoverageState Integration

Before the mutation loop:
- Baseline touch captured via `capture_baseline_touch(host, host_args)`.
- `CalibratedParams` instantiated with hardcoded values: `tau_new=40`, `tau_d=3`, `K_T_rare=31`, `gamma=0.9965`. These match the calibrated values from Phase II.1.5's empirical analysis of the guest program.
- `CoverageState(params)` created, then `state.seed_from_baseline(baseline.bitmap)` called to initialize touch frequencies from the 1599 baseline buckets.

In the mutation loop, for each run:
1. `compute_reward(bitmap, failures, exit_code, outcome, proof_generated, state)` → `(reward, diag)` — reads state BEFORE this run's contribution.
2. `update_state(bitmap, failures, exit_code, state)` — writes this run's contribution into state for the next run.

This preserves the exact contract specified in `coverage_state.py`: compute-before-update.

### 3.3 Enhanced RunResult

The `RunResult` dataclass was expanded to include:
- `outcome` (str): "REJECTED", "CRASH", "ACCEPTED", "NO_EFFECT"
- `proof_generated` (bool): Whether the host generated a proof
- `d_fail` (int): Distinct failure context IDs
- `r_rep` (int): Cascade repeat count (`max(0, n_fail - d_fail)`)
- `reward` (float): Computed reward
- `diag` (dict): Full diagnostic breakdown (T_new, T_rare, F_new, F_rare, Z, Q_dist, Q_rep, Q, S, delta_T, delta_F, etc.)
- `execution_time_ms` (float): Wall-clock time per mutation

### 3.4 Report Sections

The script now produces these analysis sections:

1. **Campaign summary**: Total runs, outcome breakdown
2. **Touch coverage**: Final bitmap buckets, exact triples, hash collisions
3. **Failure coverage**: Distinct constraint_loc families, distinct (loc,major,minor) context_ids
4. **Reward by kind**: min/median/mean/max/stdev for each of the 8 mutation kinds
5. **Reward components by kind**: Mean T_new, T_rare, F_new, F_rare, Z, Q per kind
6. **Z-event analysis**: Count, reward range, which kinds produce Z events
7. **Cascade analysis**: Runs with r_rep > 10, their Q_rep and Q values
8. **Top 10 highest rewards**: Kind, step, reward, component breakdown
9. **Failure context_id novelty curve**: Running count of distinct context_ids at milestones

---

## 4. Verification Campaign Results (200 mutations, seed=123)

### 4.1 Campaign Overview

| Metric | Value |
|--------|-------|
| Total runs | 200 |
| Seed | 123 |
| Wall-clock time | 4147s (~69 min) |
| REJECTED | 197 |
| CRASH | 3 |
| NO_EFFECT | 0 |
| ACCEPTED | 0 |

### 4.2 Coverage Summary

| Metric | Value |
|--------|-------|
| Final bitmap buckets | 2041 |
| Final exact triples | 2076 |
| Hash collisions (exact − bitmap) | 35 (1.7%) |
| Distinct constraint_loc families | 28 |
| Distinct (loc,major,minor) context_ids | 163 |
| Runs with new context_ids | 62/200 (31%) |

The 442 new bitmap buckets (2041 − 1599) came primarily from INSTR_TYPE_MOD runs that change the major/minor dispatch path and reach different EQZ call sites.

### 4.3 Reward Distributions by Kind

| Kind | n | min | median | mean | max | stdev |
|------|---|-----|--------|------|-----|-------|
| COMP_OUT_MOD | 36 | 0.026 | 0.058 | 0.087 | 0.240 | 0.066 |
| LOAD_VAL_MOD | 21 | 0.026 | 0.043 | 0.062 | 0.212 | 0.052 |
| STORE_OUT_MOD | 17 | 0.031 | 0.050 | 0.062 | 0.207 | 0.042 |
| PRE_EXEC_REG_MOD | 18 | 0.000 | 0.062 | 0.070 | 0.157 | 0.051 |
| INSTR_TYPE_MOD | 19 | 0.043 | 0.125 | 0.137 | 0.294 | 0.070 |
| MEM_VAL_MOD | 33 | 0.009 | 0.073 | 0.105 | 0.251 | 0.079 |
| INSTR_WORD_MOD_FULL | 34 | 0.000 | 0.088 | 0.102 | 0.243 | 0.070 |
| INSTR_WORD_MOD_SUR | 22 | 0.000 | 0.169 | 0.155 | 0.245 | 0.090 |
| **ALL** | **200** | **0.000** | **0.073** | **0.098** | **0.294** | **0.073** |

### 4.4 Reward Component Breakdown (mean per kind)

| Kind | T_new | T_rare | F_new | F_rare | Z count | Q |
|------|-------|--------|-------|--------|---------|---|
| COMP_OUT_MOD | 0.000 | 0.153 | 0.116 | 0.521 | 0 | 0.547 |
| LOAD_VAL_MOD | 0.000 | 0.151 | 0.060 | 0.393 | 0 | 0.542 |
| STORE_OUT_MOD | 0.000 | 0.143 | 0.037 | 0.410 | 0 | 0.549 |
| PRE_EXEC_REG_MOD | 0.000 | 0.081 | 0.246 | 0.623 | 0 | 0.336 |
| INSTR_TYPE_MOD | 0.360 | 0.675 | 0.720 | 0.957 | 0 | 0.291 |
| MEM_VAL_MOD | 0.001 | 0.125 | 0.181 | 0.610 | 3 | 0.506 |
| INSTR_WORD_MOD_FULL | 0.003 | 0.128 | 0.239 | 0.684 | 2 | 0.460 |
| INSTR_WORD_MOD_SUR | 0.002 | 0.116 | 0.082 | 0.390 | 7 | 0.746 |

---

## 5. Verification of the Four Criteria

### 5.1 Criterion 1: Reward variance exists across non-INSTR_TYPE_MOD arms

**PASS.** The standard deviations range from 0.042 (STORE_OUT_MOD) to 0.090 (INSTR_WORD_MOD_SUR), all significantly above zero. More importantly, the **mean rewards differ meaningfully** across kinds:

- **High-reward kinds**: INSTR_WORD_MOD_SUR (mean 0.155), INSTR_TYPE_MOD (mean 0.137), MEM_VAL_MOD (mean 0.105), INSTR_WORD_MOD_FULL (mean 0.102)
- **Medium-reward kinds**: COMP_OUT_MOD (mean 0.087), PRE_EXEC_REG_MOD (mean 0.070)
- **Lower-reward kinds**: LOAD_VAL_MOD (mean 0.062), STORE_OUT_MOD (mean 0.062)

The 2.5× spread between the highest (0.155) and lowest (0.062) mean rewards gives the bandit meaningful differentiation. In the old reward, 7/8 kinds had near-identical reward after touch saturation; now all 8 kinds have distinct distributions.

**Why INSTR_WORD_MOD_SUR leads**: It produces the most Z-events (7 out of 12 total), which earn high reward (0.240–0.245). When it does cause failures, they tend to be few and distinct (1f, 1d pattern), giving high Q. Its mean Q (0.746) is the highest of any kind.

**Why INSTR_TYPE_MOD remains high**: It uniquely produces new touch coverage (mean T_new=0.360 vs ~0 for all others) AND has high F_rare (0.957) because it hits rare failure contexts. However, its Q (0.291) is the lowest because it triggers more distinct failures (4-6 per run), showing the Q_dist penalty working correctly.

### 5.2 Criterion 2: Z-events get high reward

**PASS.** 12 Z-events occurred across the 200 mutations:

| Metric | Value |
|--------|-------|
| Total Z events | 12 (6% of runs) |
| Z-event reward range | 0.240 – 0.245 |
| Z-event reward mean | 0.242 |
| Non-Z non-crash reward mean | 0.091 |
| **Z vs non-Z ratio** | **2.7×** |

Z-events get rewards 2.7× the average non-Z run. This is because Z-events have Q=1.0 (d_fail=0 means Q_dist=exp(0)=1, and r_rep=0 means Q_rep=1). The reward is then driven by the Z component in the weighted average: `S = (a_Tn * 0 + a_Tr * T_rare + a_Fn * 0 + a_Fr * 0 + a_Z * 1) / w_sum`. With a_Z=1.0 and w_sum=4.25, the Z term alone contributes `1.0/4.25 ≈ 0.235`, plus any T_rare contribution.

Z-event producers by kind:
- INSTR_WORD_MOD_SUR: 7 (32% of its 22 runs)
- MEM_VAL_MOD: 3 (9% of its 33 runs)
- INSTR_WORD_MOD_FULL: 2 (6% of its 34 runs)

This is expected: surgical mutations can produce "silent" execution changes (REJECTED with proof_generated=true but zero constraint failures locally), which are exactly the signal that could indicate a soundness bug bypass.

### 5.3 Criterion 3: Cascades are suppressed but not information-erased

**PASS.** Two cascade runs occurred:

| Run | Kind | n_fail | d_fail | r_rep | Q_rep | Q_dist | Q | reward |
|-----|------|--------|--------|-------|-------|--------|---|--------|
| 77 | INSTR_WORD_MOD_FULL | 159 | 7 | 152 | 0.003 | 0.098 | 0.000 | 0.000 |
| 145 | PRE_EXEC_REG_MOD | 23 | 11 | 12 | 0.923 | 0.024 | 0.024 | 0.011 |

**Run 77 analysis** (massive cascade):
- 159 total failures but only 7 distinct contexts → r_rep=152.
- Q_rep = exp(-(152-10)/25) = exp(-5.68) = 0.003. This is correctly near-zero.
- Q_dist = exp(-7/3) = 0.098. The 7 distinct failures are penalized, but not to zero.
- Final Q = 0.003 × 0.098 ≈ 0.000. The massive cascade correctly zeroes out the reward.
- However, the run's **information is NOT erased**: it contributed 7 distinct failure context IDs to `fail_freq`, and its touch bitmap was merged. Only its reward (the bandit signal) was suppressed.

**Run 145 analysis** (moderate cascade):
- 23 failures, 11 distinct → r_rep=12.
- Q_rep = exp(-(12-10)/25) = exp(-0.08) = 0.923. Only mild penalization for 2 repeats above threshold.
- Q_dist = exp(-11/3) = 0.024. The 11 distinct failures are heavily penalized (which is correct: more distinct failures means more cascade-like behavior).
- Final Q = 0.923 × 0.024 = 0.022. Low but not zero — the moderate cascade gets some small reward.

**Conclusion**: The cascade suppression is working as designed. Massive cascades (r_rep=152) get Q≈0. Moderate cascades (r_rep=12) get small but nonzero Q. In both cases, the run's coverage data is still recorded in state. The distinction between Q_dist (penalizing many distinct failures) and Q_rep (penalizing cascade repeats) is visible and functioning correctly.

### 5.4 Criterion 4: Failure rarity provides differentiation after novelty decays

**PASS.** The failure context_id novelty curve shows:

| After run | Distinct context_ids | Novel runs (cumulative) |
|-----------|---------------------|------------------------|
| 1 | 2 | 1 |
| 10 | 16 | 7 |
| 25 | 30 | 14 |
| 50 | 56 | 26 |
| 100 | 102 | 42 |
| 150 | 145 | 56 |
| 200 | 163 | 62 |

Key observation: Failure novelty (F_new) does NOT saturate as rapidly as touch novelty (T_new). New context_ids keep appearing at a roughly linear rate (~0.8 new context_ids per run). After 200 runs, 31% of runs still discovered at least one new context_id. This is because each mutation kind × step combination can hit a different combination of (constraint_loc, major, minor) triples.

**F_rare differentiation**: The component breakdown shows F_rare varies across kinds:

- INSTR_TYPE_MOD: F_rare = 0.957 (highest — it hits rare contexts)
- INSTR_WORD_MOD_FULL: F_rare = 0.684
- PRE_EXEC_REG_MOD: F_rare = 0.623
- MEM_VAL_MOD: F_rare = 0.610
- COMP_OUT_MOD: F_rare = 0.521
- STORE_OUT_MOD: F_rare = 0.410
- LOAD_VAL_MOD: F_rare = 0.393
- INSTR_WORD_MOD_SUR: F_rare = 0.390

This ~2.5× spread (0.957 vs 0.390) in F_rare confirms it provides meaningful differentiation. Even when F_new decays toward 0 (because a failure context has been seen before), F_rare continues to vary because different arms hit different failure contexts at different frequencies. Rarely-hit contexts get 1/sqrt(1+count) ≈ 1.0, while frequently-hit contexts get lower weights.

---

## 6. Cross-Campaign Comparison with Pre-Rework Data

The previous 200-mutation campaign (pre-rework, Phase II.2 report §5.3) showed that all value-mutation kinds produced near-identical reward after touch novelty saturated in the first run. The key differences now:

| Metric | Pre-rework | Post-rework (this campaign) |
|--------|-----------|---------------------------|
| Reward mean range across kinds | Near-constant for 7/8 kinds | 0.062 – 0.155 (2.5× spread) |
| Reward differentiation | Only INSTR_TYPE_MOD different | All 8 kinds have distinct distributions |
| Z-events | Not computed | 12 events, mean reward 2.7× higher than average |
| Cascade handling | Not computed | Massive cascade (159f) correctly suppressed to r=0.000 |
| Failure rarity signal | Not available | F_rare varies 0.390–0.957 across kinds |
| Touch novelty after 200 runs | Saturated at run 1 | Saturated at run 1 (unchanged, as expected) |

The revised reward addresses the original problem: the bandit now has meaningful signal to differentiate arms.

---

## 7. Observations and Insights for Phase II.3

### 7.1 Reward magnitude

All rewards fall in [0.000, 0.294]. The median is 0.073, the mean is 0.098. These are modest but non-degenerate values. The bandit's UCB exploration term (c_explore=0.25) will be large relative to mean reward, ensuring sufficient exploration in early rounds.

### 7.2 T_new is near-zero for all non-INSTR_TYPE_MOD

Touch novelty (T_new) saturates after the first few INSTR_TYPE_MOD runs. For all other kinds, T_new is effectively 0. This is expected and acceptable because the reward now has 4 other components. Touch rarity (T_rare) still contributes 0.081–0.675 of signal depending on the kind.

### 7.3 F_new decays slower than T_new

Failure novelty (F_new) provides meaningful signal throughout the campaign. At run 200, 31% of runs still discover new context_ids. The F_new tau (tau_F_new=2.0) is tuned low enough that even 1 new context ID gives F_new = 1 - exp(-1/2) = 0.393, which is significant.

### 7.4 Q acts as a soft gate, not a hard cutoff

For most runs (2f/2d or 1f/1d), Q_dist is moderate (0.51–0.72) and Q_rep is 1.0. Only pathological cascades (run 77: 159f) get Q≈0. This means Q acts as intended: it suppresses garbage without erasing information.

### 7.5 INSTR_WORD_MOD_SUR has highest mean reward

INSTR_WORD_MOD_SUR leads with mean 0.155, driven by its high Z-event rate (32% of runs produce Z) and highest Q (0.746). This makes sense: surgical field mutations are the most targeted and least likely to cause cascades, which aligns with the goal of finding underconstraints. The bandit should learn to favor this kind.

### 7.6 No ACCEPTED events

No mutations produced a verifier-accepted proof. This is expected for a 200-mutation random campaign — finding an actual soundness bug requires extensive coverage-guided search.

### 7.7 No production code changes

As specified in the plan, no changes were made to `coverage_state.py`, `pilot_calibration.py`, `fuzzer.py`, or any C++ code. Only the diagnostic script was updated.

---

## 8. Testing

### 8.1 Smoke test (3 mutations)

A 3-mutation quick test was run first to verify the diagnostic script works end-to-end before committing to the full 200-mutation campaign. Results:
- Run 1 (COMP_OUT_MOD): 2f, r=0.219
- Run 2 (INSTR_TYPE_MOD): 4f, r=0.125
- Run 3 (LOAD_VAL_MOD): 2f, r=0.212

All reward computations matched manual calculation from the component values, confirming the compute-before-update contract works correctly.

### 8.2 Full 200-mutation campaign

Completed without errors (exit_code=0). 200 runs executed in 4147 seconds. 3 crash runs correctly received r=0.000 (crash gating works). 12 Z-events correctly received high reward. 2 cascade runs correctly received suppressed reward.

---

## 9. Completion Checklist

- [x] Step II.2V.1: Diagnostic script updated with reward computation + outcome classification + reporting
- [x] Step II.2V.2: 200-mutation campaign executed
- [x] Step II.2V.3: Results analyzed; 4 verification criteria documented and all PASS
- [x] No changes to production code (coverage_state.py, pilot_calibration.py, fuzzer.py)

---

## 10. Variable Reference

This section defines every variable used in the diagnostic script and reward computation, including all single-letter and abbreviated names.

### 10.1 Reward Formula Variables

| Variable | Type | Definition | Where Set |
|----------|------|-----------|-----------|
| `T_new` | float [0,1] | Touch novelty signal: `1 - exp(-delta_T / tau_new)`. Measures how many new bitmap buckets this run discovered. | `coverage_state.py:116` |
| `T_rare` | float [0,1] | Touch rarity signal: average of top-K_T_rare rarest touched buckets, weighted by `1/sqrt(1 + freq[i])`. | `coverage_state.py:120-124` |
| `F_new` | float [0,1] | Failure novelty signal: `1 - exp(-delta_F / tau_F_new)`. Measures how many new failure context IDs this run discovered. | `coverage_state.py:130` |
| `F_rare` | float [0,1] | Failure rarity signal: average of top-K_F_rare rarest failure contexts, weighted by `1/sqrt(1 + fail_freq[c])`. | `coverage_state.py:133-137` |
| `Z` | int {0,1} | Zero-local-fail indicator: 1 when `outcome == "REJECTED" AND proof_generated AND d_fail == 0`. Flags potential underconstraint bypasses. | `coverage_state.py:142` |
| `Q` | float [0,1] | Execution quality multiplier: `Q_dist * Q_rep`. Suppresses garbage cascades. | `coverage_state.py:150` |
| `Q_dist` | float [0,1] | Distinct-failure penalty: `exp(-d_fail / tau_d)`. Penalizes runs with many distinct failures. | `coverage_state.py:145` |
| `Q_rep` | float [0,1] | Cascade-repeat penalty: 1.0 if `r_rep <= r_0`, else `exp(-(r_rep - r_0) / tau_r)`. | `coverage_state.py:146-149` |
| `S` | float [0,1] | Weighted average of 5 components: `(a_Tn*T_new + a_Tr*T_rare + a_Fn*F_new + a_Fr*F_rare + a_Z*Z) / w_sum`. | `coverage_state.py:155` |
| `r` | float [0,1] | Final reward: `min(1, Q * S)`. Overridden to 1.0 if `outcome == "ACCEPTED"`. | `coverage_state.py:160-164` |
| `w_sum` | float | Sum of all weights: `a_Tn + a_Tr + a_Fn + a_Fr + a_Z = 1.0 + 0.25 + 1.0 + 1.0 + 1.0 = 4.25`. | `coverage_state.py:153` |

### 10.2 Per-Run Measurement Variables

| Variable | Type | Definition |
|----------|------|-----------|
| `n_fail` | int | Total number of constraint failure instances from `parse_all_constraint_failures`. |
| `d_fail` | int | Number of distinct (constraint_loc, major, minor) triples among failures. |
| `r_rep` | int | Cascade repeat count: `max(0, n_fail - d_fail)`. How many failures are repeats of already-counted contexts. |
| `delta_T` | int | Number of new bitmap buckets: buckets nonzero in run bitmap but zero in global bitmap. |
| `delta_F` | int | Number of new failure context IDs: context IDs in this run not previously in `fail_freq`. |
| `outcome` | str | One of "REJECTED", "CRASH", "ACCEPTED", "NO_EFFECT". |
| `proof_generated` | bool | True if the host created a proof (even if self-verification failed). |
| `bitmap_delta_new` | int | Same as delta_T but tracked separately from CoverageState for comparison. |
| `exact_delta_new` | int | Number of new exact (loc, major, minor) triples from verbose touch mode. |
| `exact_touched_count` | int | Total exact triples in this run's verbose touch output. |
| `bitmap_touched_count` | int | Number of nonzero buckets in this run's bitmap. |

### 10.3 CalibratedParams (frozen at campaign start)

| Parameter | Value Used | Type | Meaning |
|-----------|-----------|------|---------|
| `tau_new` | 40.0 | CALIBRATE | Touch novelty scaling factor (higher = slower saturation). |
| `tau_d` | 3.0 | CALIBRATE | Distinct-failure penalty scaling (higher = less penalty per d_fail). |
| `K_T_rare` | 31 | CALIBRATE | Top-K for touch rarity averaging. |
| `gamma` | 0.9965 | DERIVED | Bandit discount factor (not used in reward, only in bandit). |
| `tau_F_new` | 2.0 | HARD | Failure novelty scaling (low → even 1 new context gives significant signal). |
| `K_F_rare` | 2 | HARD | Top-K for failure rarity averaging (average of 2 rarest contexts). |
| `r_0` | 10 | HARD | Cascade threshold (Q_rep=1 for r_rep ≤ 10). |
| `tau_r` | 25.0 | HARD | Cascade penalty slope. |
| `c_explore` | 0.25 | HARD | UCB exploration coefficient (not used in diagnostic). |
| `a_Tn` | 1.0 | HARD | Weight for T_new in S. |
| `a_Tr` | 0.25 | HARD | Weight for T_rare in S (lower because rarity is less important than novelty). |
| `a_Fn` | 1.0 | HARD | Weight for F_new in S. |
| `a_Fr` | 1.0 | HARD | Weight for F_rare in S. |
| `a_Z` | 1.0 | HARD | Weight for Z in S. |

### 10.4 CoverageState Fields

| Field | Type | Meaning |
|-------|------|---------|
| `global_bitmap` | bytearray[65536] | Cumulative max bitmap across all valid runs + baseline. |
| `freq` | List[int][65536] | Per-bucket touch frequency counter (incremented once per run that touches the bucket). Seeded from baseline (freq[i]=1 for baseline-touched buckets). |
| `fail_freq` | Dict[(str,int,int), int] | Per-failure-context frequency counter (incremented once per run that produces that context, NOT per instance). |
| `total_runs` | int | Total runs processed (including crashes). |
| `maj_seen` | Dict[int, int] | Diagnostic: failure count by major cycle category. |
| `maj_min_seen` | Dict[(int,int), int] | Diagnostic: failure count by (major, minor) pair. |

### 10.5 Diagnostic Script Variables

| Variable | Type | Meaning |
|----------|------|---------|
| `global_exact_set` | Set[str] | Cumulative set of exact (loc,major,minor) triples from verbose mode (parallel tracking for bitmap collision comparison). |
| `kind_counter` | Counter | Number of runs per mutation kind. |
| `results` | List[RunResult] | All collected results for analysis. |
| `rng` | random.Random | Deterministic RNG seeded with `--seed`. |
| `selector` | ZonedStepSelector | Step selector (same as fuzzer uses). |
| `value_gen` | ValueGenerator | Value generator (mixed strategy, same as fuzzer default). |

---

## 11. For Anyone New: What Phase II.2V Is and Why

### What

Phase II.2V is a **verification** phase. It runs a 200-mutation diagnostic campaign using the revised reward function from Phase II.2R and checks whether the reward actually produces meaningful signal that can differentiate between mutation kinds and step regions. It doesn't change any production code — it only updates the diagnostic script and analyzes results.

### Why

The entire point of revising the reward (Phase II.2R) was to fix the problem where the original reward was near-constant across 7 of 8 mutation kinds after touch saturation. Before building the multi-armed bandit scheduler (Phase II.3) on top of this reward, we need to verify the fix actually works. If we skip verification and implement the bandit on a still-degenerate reward, the bandit can't learn and we waste implementation effort.

### Result

All four verification criteria passed:
1. Reward variance exists across all kinds (stdev 0.042–0.090, mean spread 2.5×)
2. Z-events get 2.7× higher reward than average
3. Cascades are suppressed but not information-erased
4. Failure rarity differentiates across kinds (F_rare range 0.390–0.957)

**Verdict**: The revised reward is ready for bandit integration in Phase II.3.

---

*End of Phase II.2V Implementation Report.*

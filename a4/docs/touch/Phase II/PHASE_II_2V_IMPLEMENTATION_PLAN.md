# Phase II.2V Detailed Implementation Plan: Reward Verification

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.2V** (Reward Verification). It verifies that the revised reward function (Phase II.2R) produces meaningful, arm-differentiating signal before implementing the bandit (Phase II.3).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites

### 1.1 What Phase II.2R delivered

- Revised `compute_reward` with 5 co-primary components (T_new, T_rare, F_new, F_rare, Z) + revised Q (Q_dist * Q_rep) + weighted average
- Revised `CalibratedParams` with tau_d, K_T_rare, K_F_rare=2, weights, cascade params
- `CoverageState.seed_from_baseline()` for baseline seeding
- `update_state` with valid-run gating (crash/missing bitmap → no coverage update)
- 46 unit tests passing

### 1.2 What Phase II.2V needs to verify (from master plan §5, II.2V and Pro_Report_6 §8)

1. Reward variance exists across non-INSTR_TYPE_MOD arms
2. Z-events (REJECTED + proof_generated + d_fail==0) get high reward
3. Cascades are suppressed but not information-erased incorrectly
4. Failure rarity provides differentiation after novelty decays

### 1.3 What Phase II.2V does NOT do

- Does NOT implement the bandit (II.3)
- Does NOT modify the fuzzer campaign loop (II.4)
- Does NOT modify coverage_state.py or pilot_calibration.py
- Only updates the diagnostic script and runs a verification campaign

---

## 2. Source-of-Truth: What the Diagnostic Script Needs

### 2.1 Current diagnostic script state

The script (`run_diagnostic_campaign.py`) currently:
- Runs mutations with verbose touch + bitmap
- Tracks bitmap deltas and exact-set deltas per run
- Reports touch and failure statistics
- Does NOT compute the revised reward per run
- Does NOT classify outcome (REJECTED/CRASH/ACCEPTED) or proof_generated
- Does NOT use CoverageState or compute_reward

### 2.2 What needs to be added

1. **Outcome classification**: Determine if each run is REJECTED/CRASH/ACCEPTED and whether proof was generated. From fuzzer.py:
   - `proof_generated`: "verify segment" in output OR exit_code==0 (from `_check_proof_generated`)
   - `outcome`: CRASH if crash signals; ACCEPTED if verifier success pattern in output; REJECTED if failures or proof_verify_failed; else NO_EFFECT

2. **Reward computation**: For each run, call `compute_reward` and `update_state` from `coverage_state.py` using a `CoverageState` seeded from baseline.

3. **Report sections**: Per-kind reward distributions, Z-event analysis, cascade examples, reward variance statistics.

---

## 3. Step-by-Step Implementation Plan

### Step II.2V.1: Update diagnostic script with reward computation

**Goal**: The diagnostic script computes the revised reward for each run using CoverageState and reports reward distributions.

**Actions**:

1. Add imports for `CoverageState`, `compute_reward`, `update_state`, `CalibratedParams`.

2. Add outcome classification logic (replicated from fuzzer.py `_check_proof_generated`, `_check_verifier_acceptance`):
   - `proof_generated`: True if "verify segment" in output or exit_code==0
   - `verifier_accepted`: True if verifier success JSON pattern found
   - `outcome`: "CRASH" if crash, "ACCEPTED" if verifier_accepted, "REJECTED" if failures or "verify segment" in output, else "NO_EFFECT"

3. Before the mutation loop:
   - Run baseline and capture bitmap (using `capture_baseline_touch`)
   - Create `CalibratedParams` with default HARD values and reasonable calibrated values (tau_new=40, tau_d=3, K_T_rare=31, gamma=0.9965)
   - Create `CoverageState(params)` and call `seed_from_baseline(baseline.bitmap)`

4. In the mutation loop, after each run:
   - Call `compute_reward(bitmap, failures, exit_code, outcome, proof_generated, state)` → get (reward, diag)
   - Call `update_state(bitmap, failures, exit_code, state)` (only for valid runs per the gating)
   - Store reward and diagnostics in RunResult

5. In the report section, add:
   - **Reward by kind**: For each mutation kind, show min/median/mean/max reward
   - **Z-event analysis**: Count of Z=1 events, their reward values, which kinds produce them
   - **Cascade analysis**: Runs with r_rep > 10, their Q_rep values, final reward
   - **Reward variance**: Standard deviation of reward across all runs, and per-kind
   - **Top 10 highest-reward runs**: Show kind, step, reward, diagnostics
   - **Reward component breakdown**: Mean of each component (T_new, T_rare, F_new, F_rare, Z) per kind

**Deliverable**: Diagnostic script produces comprehensive reward analysis.

---

### Step II.2V.2: Run 200-mutation verification campaign

**Goal**: Execute the diagnostic campaign with revised reward computation and analyze results.

**Actions**:

1. Run: `python -m a4.standalone.tests.run_diagnostic_campaign --host ./workspace/output/target/release/risc0-host --num 200 --seed 123 -- --in1 5 --in4 10`

2. The output now includes per-run reward and diagnostics alongside the existing touch/failure data.

**Deliverable**: Full campaign output with reward distributions.

---

### Step II.2V.3: Analyze and document results

**Goal**: Verify the four criteria from §1.2 and document in a report.

**Verification criteria**:

1. **Reward variance across non-INSTR_TYPE_MOD arms**: Check that the standard deviation of reward for COMP_OUT_MOD, LOAD_VAL_MOD, etc. is meaningfully above zero. If all value-mutation rewards are near-identical, F_rare is not differentiating.

2. **Z-events get high reward**: Identify runs where Z=1. Verify their reward is higher than average. If Z-event rewards are low (because Q also penalizes them), the Z weight may need adjustment.

3. **Cascades suppressed**: Runs with r_rep > 10 should have lower Q_rep. Verify the cascade run (r_rep=148 from the 159-failure run) gets Q_rep near 0 but Q_dist is based on d_fail, not n_fail.

4. **Failure rarity differentiates**: After the first ~50 runs, F_new should be near 0 for most runs. F_rare should still vary because different arms hit different failure contexts with different frequencies.

**Deliverable**: Phase II.2V implementation report with analysis and conclusions.

---

## 4. Files to Touch (Phase II.2V only)

| File | Change |
|------|--------|
| `a4/standalone/tests/run_diagnostic_campaign.py` | Add CoverageState/reward computation; outcome classification; reward reporting |

No changes to: coverage_state.py, pilot_calibration.py, fuzzer.py, executor.py, C++.

---

## 5. Alignment with Master Plan

| Master plan reference | Phase II.2V coverage | Notes |
|----------------------|---------------------|-------|
| §5 II.2V: "Run 200-mutation diagnostic with revised reward" | Step II.2V.2 | Same seed (123) as original for comparison |
| §5 II.2V: "Verify reward variance across arms" | Step II.2V.3 criterion 1 | Per-kind reward distributions |
| §5 II.2V: "Verify Z-events get high reward" | Step II.2V.3 criterion 2 | Z analysis |
| §5 II.2V: "Verify cascades suppressed" | Step II.2V.3 criterion 3 | Q_rep analysis |
| Pro_Report_6 §8 item 4 | All 4 criteria | Matched |

### Deviations from master plan

1. **CalibratedParams hardcoded for diagnostic**: The verification campaign uses hardcoded calibrated params (tau_new=40, tau_d=3, K_T_rare=31) rather than running pilot calibration. **Reason**: The diagnostic script is standalone (not the fuzzer campaign loop). The purpose is to verify the reward FORMULA produces variance, not to test pilot calibration. Using reasonable default values is sufficient. Pilot calibration will be tested in the real campaign loop (Phase II.4).

No other deviations.

---

## 6. Completion Checklist

- [ ] Step II.2V.1: Diagnostic script updated with reward computation + outcome classification + reporting
- [ ] Step II.2V.2: 200-mutation campaign executed
- [ ] Step II.2V.3: Results analyzed; 4 verification criteria documented
- [ ] No changes to production code (coverage_state.py, pilot_calibration.py, fuzzer.py)

---

## 7. Dependencies for Phase II.3 (reminders)

Phase II.3 (Bandit) proceeds only if II.2V confirms:
- Reward variance is meaningful (standard deviation significantly above 0)
- Different kinds produce different reward distributions
- The reward signal is not degenerate (not near-constant across arms)

If II.2V reveals problems, we return to ChatGPT Pro for further adjustments before II.3.

---

## 8. For Anyone New: What Phase II.2V Is and Why

### What

Phase II.2V is a **verification** phase. It runs a 200-mutation diagnostic campaign using the revised reward function from Phase II.2R and checks whether the reward actually produces meaningful, arm-differentiating signal. It doesn't change any production code — it only updates the diagnostic script and analyzes the results.

### Why

The entire point of revising the reward (Phase II.2R) was to fix the problem where the original reward was near-constant across 7/8 mutation kinds after touch saturation. Before building the bandit (Phase II.3) on top of this reward, we need to verify the fix actually works. If we skip verification and implement the bandit on a still-degenerate reward, the bandit can't learn and we waste implementation effort.

### How it differs

| Phase | What | Nature |
|-------|------|--------|
| II.2R | Rewrote the reward function | Code change |
| **II.2V** (this) | **Verify the reward works** | **Diagnostic / analysis** |
| II.3 | Implement the bandit | Code change |

Phase II.2V is the "trust but verify" step between the reward rework and the bandit implementation.

---

## 9. New and Withheld Sections

**Sections retained**: All standard sections.

**Sections withheld**: Variable reference (not needed — no new variables introduced; see II.2R report for complete reference).

**New sections**: None.

---

*End of Phase II.2V Implementation Plan.*

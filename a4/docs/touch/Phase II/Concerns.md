# Phase II Concerns and 200-Mutation Diagnostic Campaign Analysis

**Purpose**: This document presents verified empirical data from a 200-mutation diagnostic campaign, comparing bitmap-based coverage against exact constraint context coverage. It identifies architectural concerns about the Phase II reward function and bandit scheduler that require expert review before implementing Subphase 3 (Discounted-UCB Bandit).

---

## Table of Contents: Phase II Markdowns

| File | What it contains |
|------|-----------------|
| **Pro_Report_4.md** | Original concrete architecture specification: coverage key, reward formulas, Discounted-UCB bandit model, arm universe, step bucketing, master plan (II.0-II.7). |
| **Pro_Report_5.md** | Parameter inventory (25 params: HARD/DERIVED/CALIBRATE/TUNE), pilot calibration methodology, budget-dependent derivation formulas. |
| **MUTATION_TAXONOMY.md** | All 8 mutation kinds, their targets, and constraint system interactions. |
| **PHASE_II_MASTER_IMPLEMENTATION_PLAN.md** | Master plan consolidating Pro_Report_4/5. All parameters, reward function spec, bandit model, sub-phases, dependencies. |
| **PHASE_II_0_IMPLEMENTATION_PLAN/REPORT.md** | Subphase 0: baseline touch snapshot (1599 bitmap buckets = 1614 exact triples). |
| **PHASE_II_1_IMPLEMENTATION_PLAN/REPORT.md** | Subphase 1: arm universe (T=3930, B_count=32 for N=1000, 254 arms). |
| **PHASE_II_1_5_IMPLEMENTATION_PLAN/REPORT.md** | Subphase 1.5: pilot calibration functions (tau_new, tau_fail_count, K_rare). |
| **PHASE_II_2_IMPLEMENTATION_PLAN/REPORT.md** | Subphase 2: CoverageState, compute_reward, update_state. |
| **Concerns.md** | THIS FILE. |

For Phase I context, see `a4/docs/touch/Phase I/INDEX.md`.

---

## 1. Diagnostic Campaign Summary

**Method**: Standalone diagnostic script replicating the fuzzer's mutation selection (random kind, zoned step, same seed) but capturing BOTH the AFL-style bitmap AND exact verbose (loc, major, minor) triples per run. This allows direct comparison between the lossy bitmap and the ground-truth constraint context list.

**Parameters**: host=risc0-host, guest args=`--in1 5 --in4 10`, N=200, seed=123, all 8 mutation kinds.

**Results**:
- 200 runs: 185 REJECTED, 2 CRASH, 13 NO_FAIL_BUT_REJECTED
- 656 total constraint failure instances
- 28 distinct constraint_loc families
- **163 distinct (constraint_loc, major, minor) failure context_ids**
- **2076 distinct exact touch triples** (up from 1614 baseline)
- **2041 bitmap buckets** (up from 1599 baseline)
- **35 hash collisions** (2076 exact - 2041 bitmap = 1.7% collision rate)

---

## 2. Bitmap vs Exact Touch Coverage

### 2.1 Baseline comparison

| Metric | Bitmap | Exact | Difference |
|--------|--------|-------|-----------|
| Baseline distinct | 1599 buckets | 1614 triples | 15 collisions (0.9%) |
| After 200 runs | 2041 buckets | 2076 triples | 35 collisions (1.7%) |

Hash collisions grow as more triples are discovered. At 2076 triples in a 65536 bitmap, the theoretical expected collisions are ~33 (from K^2 / (2*MAP_SIZE) = 2076^2 / 131072). The observed 35 is consistent.

### 2.2 Per-run bitmap vs exact deltas

16 of 200 runs discovered new touch triples. Of these, 12 showed bitmap/exact disagreement:

| Run | Kind | Bitmap delta | Exact delta | Lost to collision |
|-----|------|-------------|-------------|-------------------|
| 1 | COMP_OUT_MOD | 1599 | 1614 | 15 |
| 25 | INSTR_TYPE_MOD | 32 | 33 | 1 |
| 46 | INSTR_TYPE_MOD | 36 | 37 | 1 |
| 53 | INSTR_TYPE_MOD | 34 | 36 | 2 |
| 78 | INSTR_TYPE_MOD | 42 | 44 | 2 |
| 106 | INSTR_TYPE_MOD | 53 | 54 | 1 |
| 122 | INSTR_TYPE_MOD | 34 | 36 | 2 |
| 130 | INSTR_TYPE_MOD | 37 | 41 | 4 |
| 132 | INSTR_TYPE_MOD | 32 | 33 | 1 |
| 152 | INSTR_TYPE_MOD | 49 | 51 | 2 |
| 154 | INSTR_TYPE_MOD | 50 | 52 | 2 |
| 172 | INSTR_TYPE_MOD | 35 | 37 | 2 |

4 runs had matching deltas (bitmap == exact): runs 31, 82, 114, 165 (all small deltas of 2).

**Key finding**: The bitmap consistently undercounts by 1-4 triples per INSTR_TYPE_MOD discovery. Run 130 lost 4 triples to collisions. The bitmap is an approximation, not exact.

### 2.3 Touch discovery by mutation kind

| Kind | Runs | Runs with new touch | Total new triples |
|------|------|--------------------|--------------------|
| COMP_OUT_MOD | 36 | 1 (run 1 only = baseline init) | 1614 |
| LOAD_VAL_MOD | 21 | 0 | 0 |
| STORE_OUT_MOD | 17 | 0 | 0 |
| PRE_EXEC_REG_MOD | 18 | 0 | 0 |
| INSTR_TYPE_MOD | 19 | 11 (58%) | 454 |
| MEM_VAL_MOD | 33 | 1 | 2 |
| INSTR_WORD_MOD_FULL | 34 | 2 | 4 |
| INSTR_WORD_MOD_SUR | 22 | 1 | 2 |

**INSTR_TYPE_MOD is the dominant source** of new touch triples (454 of 462 non-baseline new = 98%). The 3 non-INSTR_TYPE_MOD discoveries (MEM_VAL_MOD +2, INSTR_WORD_MOD_FULL +4, INSTR_WORD_MOD_SUR +2) are small and may involve edge-case constraint paths or minor nondeterminism.

### 2.4 Touch growth curve

| After run | Exact triples | New since baseline |
|-----------|---------------|-------------------|
| 1 | 1614 | 0 (IS the baseline) |
| 10 | 1614 | 0 |
| 25 | 1647 | 33 |
| 50 | 1686 | 72 |
| 100 | 1768 | 154 |
| 150 | 1934 | 320 |
| 200 | 2076 | 462 |

Touch grows approximately linearly at ~2.3 new triples per run, driven entirely by INSTR_TYPE_MOD (19 runs / 200 total = 9.5% of runs are INSTR_TYPE_MOD, and 58% of those find new touch).

---

## 3. Failure Analysis

### 3.1 Failure count distribution

| n_fail | Count | % |
|--------|-------|---|
| 0 | 13 | 6.5% |
| 1 | 42 | 21.0% |
| 2 | 99 | 49.5% |
| 3 | 14 | 7.0% |
| 4 | 19 | 9.5% |
| 5-10 | 8 | 4.0% |
| 11-25 | 3 | 1.5% |
| 159 | 1 | 0.5% |

Median: 2. 75th percentile: 3. Max: 159 (cascade).

### 3.2 Failure granularity

| Metric | Count |
|--------|-------|
| Distinct constraint_loc families | 28 |
| Distinct (loc, major, minor) context_ids | 163 |
| Ratio: context_ids per constraint_loc | ~5.8x |

This is critical: the same constraint_loc (e.g., `MemoryWrite@mem.zir:99`) fails at many different (major, minor) pairs. Using context_ids as the failure coverage key gives ~6x more granularity than constraint_loc alone.

### 3.3 Failure context_id novelty

**62 of 200 runs (31%)** discovered at least one new failure context_id that had never been seen before in the campaign. This is much higher than touch novelty (16 of 200 = 8%) and provides a richer signal for the bandit.

Failure context_id novelty continues throughout the campaign because the same constraint_loc can fail at new (major, minor) combinations when mutated at different steps, unlike touch novelty which saturates after run 1 for non-INSTR_TYPE_MOD kinds.

Note: the per-run failure context_id growth curve was not captured in this diagnostic run. The 31% rate is an aggregate over 200 runs. A future diagnostic could track cumulative distinct failure context_ids at each run to show whether this rate is sustained or front-loaded.

### 3.4 Cascade behavior

Some runs produce very high failure instance counts (max: 159 from an INSTR_WORD_MOD_FULL at step 1411). The exact mechanism of how a single mutation in the preflight trace causes such large cascades has not been fully investigated at the transaction level. What we know: the RISC Zero witness generation has ~370 back-reference reads from previous cycles' DATA matrix rows, which can propagate corrupted values. The precise causal chain for the 159-failure run has not been traced.

---

## 4. Notes on Data Collection

**Diagnostic script vs real fuzzer**: The diagnostic script replicates the fuzzer's mutation KIND and STEP selection exactly (same seed, same ZonedStepSelector), but uses a generic value generator for INSTR_WORD_MOD_FULL instead of the fuzzer's validated RV32IM mutation strategy. This means INSTR_WORD_MOD_FULL mutation VALUES differ, which affects failure counts and failure context_ids for those runs. Touch data is unaffected (touch depends on which EQZ calls are reached, not on mutation values for non-INSTR_TYPE_MOD kinds). The failure distribution should be treated as approximately representative, not exact.

**Formula mapping**: The reward function from Pro_Report_4 section 6 uses: S_new (touch novelty), S_rare (touch rarity), S_fail_new (failure novelty keyed by constraint_loc), Q (cascade penalty on raw n_fail), combined as `r = Q * (S_touch + lambda * S_fail_new) / (1 + lambda)`. The concerns below identify specific issues with how these components behave given the empirical data. Specifically: S_new is zero after run 1 for most kinds; S_rare is approximately constant after saturation because all value mutations touch the same triples at the same frequency; and Q penalizes based on raw instance count rather than distinct context count.

---

## 5. Architectural Concerns

### Concern 1: Touch novelty cliff and rarity uniformity

Touch saturates after run 1 for all non-INSTR_TYPE_MOD kinds. After saturation, S_rare (touch rarity) is approximately constant across all value-mutation runs because they touch the same 1614 triples with the same frequency. The bandit gets the same reward from every non-INSTR_TYPE_MOD arm.

**Claude's Question**: Should the reward use failure-context novelty/rarity (31% of runs have it) instead of or in addition to touch novelty/rarity (8% of runs)? 

**My Question**: Is there something about this observation that indicates that our multi-armed bandit technique should work differently? Or is it already optimal including given this observation?

### Concern 2: Failure context_ids as coverage key

With 163 distinct failure context_ids (vs 28 constraint_locs and vs 2076 touch triples), failure context_ids offer a middle-granularity coverage signal. They are:
- More granular than constraint_loc alone (6x more entries)
- Less granular than touch triples (which are ~2076 and mostly non-differentiating)
- Actively growing throughout the campaign (31% novelty rate vs 8% for touch)

**Claude's Question**: Should the reward function incorporate failure-context coverage (novelty and/or rarity over the 163 failure context_ids) as a primary or co-primary signal alongside touch coverage?

**My Question**: Is there something about this observation that indicates that our multi-armed bandit technique should work differently? Or is it already optimal including given this observation?

### Concern 3: S_fail_new vs Q tension

The cascade penalty Q = exp(-n_fail / tau_fail_count) penalizes runs with many failure instances. But the value signal is in distinct new context_ids, not raw count. A run with 159 failure instances (mostly cascaded repeats) gets Q near 0, even if it discovered new context_ids.

**Question**: Should Q penalize only excess failures: Q = exp(-(n_fail - n_distinct_in_run) / tau)?

**My Question**: Is there something about this observation that indicates that our multi-armed bandit technique should work differently? Or is it already optimal including given this observation?

### Concern 4: Bitmap collision rate

35 collisions out of 2076 triples = 1.7%. Per INSTR_TYPE_MOD run, 1-4 triples are lost to collisions. This means the bitmap-based delta_new undercounts by ~5-10% for INSTR_TYPE_MOD runs.

**Question**: Is 1.7% collision rate acceptable, or should MAP_SIZE be increased? Or should we use the exact set (via verbose mode) for the reward function instead of the bitmap?

**My Question**: Is there something about this observation that indicates that our multi-armed bandit technique should work differently? Or is it already optimal including given this observation?

### Concern 5: What signal should the bandit optimize?

After touch saturation, the available signals are:
- Touch rarity (S_rare): uniform across value mutations, only varies for INSTR_TYPE_MOD
- Failure context_id novelty: nonzero for 31% of runs across all mutation kinds
- Failure context_id rarity: could differentiate arms by which failure contexts are rare
- Failure count penalty (Q): varies with n_fail

**Question**: What combination of signals gives the bandit the best ability to differentiate arms and learn useful preferences?

---

## 6. Questions for ChatGPT

1. Given the empirical data (touch saturates after 1 run for value mutations, 35 hash collisions, failure context_id novelty at 31%), should the reward function be restructured to use failure context_ids as a primary signal?

2. Should we maintain a "failure context bitmap" (hashed (loc, major, minor)) alongside the touch bitmap, and use it for failure-context novelty/rarity scoring?

3. How should the cascade penalty be refined given the n_fail vs n_distinct tension?

4. Is the current MAP_SIZE=65536 adequate given 1.7% collision rate, or should we increase it?

5. Given all of the above, should we revise the reward function BEFORE implementing the bandit, or proceed with the current design and iterate?

---

## 7. Summary Statistics

| Metric | Value |
|--------|-------|
| Campaign size | 200 mutations |
| Exact touch triples (baseline) | 1614 |
| Exact touch triples (final) | 2076 (+462) |
| Bitmap buckets (final) | 2041 |
| Hash collisions | 35 (1.7%) |
| Touch novelty runs | 16 of 200 (8%) |
| INSTR_TYPE_MOD touch discovery | 11 of 19 (58%) |
| Failure instances total | 656 |
| Distinct constraint_loc families | 28 |
| Distinct (loc,major,minor) context_ids | 163 |
| Failure context_id novelty runs | 62 of 200 (31%) |
| Median n_fail | 2 |
| Max n_fail | 159 (cascade) |
| Crashes | 2 (both PRE_EXEC_REG_MOD) |

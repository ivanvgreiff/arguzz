# MAB Architecture Report — IV.POS.7 (Pro Round 2)

**Author**: Ivan Greiff + Cursor (Composer + Claude Opus)  
**Date**: June 15, 2026  
**Purpose**: Pro Round 2 response to `ProG_Report_2.md` §10–§12. Five-variant ablation (V1–V5), 10 seeds × N=6000, answering whether constrained Thompson sampling with semantic zones (`cTS_semantic_v2`) clears the survival criteria Pro set after IV.POS.5.

> **TL;DR for Pro**: V5 discovered **4 novel kernel/ECALL constraint contexts** (`ControlLoadRootAndNonce@inst_control.zir:35/44/45`, `ControlMRET@inst_control.zir:93`) that no V1 seed reached across all 10 seeds, while passing **5/5 mechanical success criteria** with the **lowest variance** (σ ratio 0.58 vs V1) and a **4.3× speedup** to 43 contexts (mean time-to-43: 1017 vs 4366 mutations, paired t-test p<10⁻⁴ on AUC and final coverage).

**Companion artifacts**: `MAB_ARCHITECTURE_NOTEBOOK_R2.html` (D3), `metrics_table.csv`, `success_criteria.csv`, `discovery_rate_by_kind.csv`, `per_loc_v2_cells.csv`.

---

## Table of Contents

- [1. Context and goal](#1-context-and-goal)
- [2. The five variants (Pro §9)](#2-the-five-variants-pro-9)
- [3. Experimental setup](#3-experimental-setup)
- [4. Headline results](#4-headline-results)
- [5. Success criteria — mechanical evaluation (Pro §10)](#5-success-criteria--mechanical-evaluation-pro-10)
- [6. Diagnostic findings](#6-diagnostic-findings)
- [7. Conclusion](#7-conclusion)
- [Appendix A: per-variant aggregate metrics](#appendix-a-per-variant-aggregate-metrics)
- [Appendix B: paired tests vs V1](#appendix-b-paired-tests-vs-v1)
- [Appendix C: discovery rate per kind (V1 vs V5)](#appendix-c-discovery-rate-per-kind-v1-vs-v5)
- [Appendix D: V5 novel contexts](#appendix-d-v5-novel-contexts)

---

## 1. Context and goal

IV.POS.5 showed that a hand-crafted **zoned** baseline (`zoned_current`, V1) beat a naive UCB bandit because the reward signal was anti-correlated with discovery on high-yield kinds like `INSTR_TYPE_MOD`. Pro's Round 2 ask (`ProG_Report_2.md` §10) was a controlled ablation: isolate whether **step priors**, **reward variants**, **posterior sampling**, or **constrained TS + semantic zones** can beat V1 on:

1. Sample efficiency (AUC, time-to-threshold)
2. Final coverage and variance
3. Novel constraint discovery (kernel/ECALL region)
4. Compressed-global context lift

This report answers that ask with 50 production DBs (5 variants × 10 seeds). V0 (uniform) and V6 (arguzz) are deferred to `INTERNAL_V0_V6_ANALYSIS.md`.

---

## 2. The five variants (Pro §9)

| ID | DB selector | Pro name | Role |
|---|---|---|---|
| **V1** | `zoned` | `zoned_current` | Reference baseline |
| **V2** | `kindUCB_zoned_v1` | kind UCB + zoned step + current reward | Step prior alone |
| **V3** | `kindUCB_zoned_v2_noQ` | kind UCB + zoned step + no Q_loc reward | Q_loc removal |
| **V4** | `kindTS_zoned_v2` | kind TS + zoned step + discovery reward | Posterior sampling |
| **V5** | `cTS_semantic_v2` | constrained TS + semantic zones + discovery reward | **Main candidate** |

---

## 3. Experimental setup

| Parameter | Value |
|---|---|
| Guest | `risc0-host --in1 5 --in4 10` (same as IV.POS.5) |
| Budget | N = 6000 mutations per seed |
| Seeds | 1234–1243 (10 paired seeds) |
| Primary metric | `local_context_final` — distinct `constraint_loc` in legacy `coverage` table (IV.POS.5 parity, max empirical universe ≈46 for V1) |
| Secondary metric | `local_coverage_v2_final` — finer `(constraint_loc, major, minor)` granularity (Pro §8) |
| Validation | 50/50 DBs PASS (`COLLECTION_REPORT_FINAL.json`) |

All numbers regenerate from `analysis/build_artifacts.py`; notebook delegates to `analysis/` modules (no inline metric logic).

---

## 4. Headline results

### 4.1 Primary coverage (legacy table)

| Variant | mean final | σ | all-46 rate | mean AUC |
|---|---:|---:|---:|---:|
| V1 | 42.9 | 1.20 | 0/10 | 228,142 |
| V2 | 31.8 | 1.62 | 0/10 | 177,804 |
| V3 | 42.1 | 1.73 | 0/10 | 233,650 |
| V4 | 41.9 | 2.13 | 0/10 | 235,618 |
| **V5** | **46.4** | **0.70** | **10/10** | **264,555** |

V5 is the only variant that hits ≥46 on every seed (per-seed finals: 46,46,46,48,46,47,46,46,46,47). Paired vs V1 on final coverage: t=7.0, p=6.3×10⁻⁵; on AUC: t=10.6, p=2.2×10⁻⁶.

**V2 collapse (kind-UCB baseline):** V2 (`kindUCB_zoned_v1`) is the clearest negative control. Its kind-level UCB allocated **85%** of all 60,000 mutations to `INSTR_WORD_MOD_SUR` (51,144 pulls) because that arm retained high UCB uncertainty, while `INSTR_TYPE_MOD` — the highest-discovery kind in IV.POS.5 — received only **584 pulls** despite a discovery rate of **212/1k** on the few mutations it did get. Final coverage collapsed to 31.8 (0/5 criteria). This is the same "reward/UCB anti-correlated with discovery" failure mode Pro diagnosed after IV.POS.5; it motivates why V5 uses constrained TS rather than naive kind-UCB.

### 4.2 Speed to threshold

| Variant | mean time-to-43 | ratio vs V1 |
|---|---:|---:|
| V1 | 4366 | 1.00 |
| V3 | 3987 | 0.91 |
| V4 | 3597 | 0.82 |
| **V5** | **1017** | **0.23** |

V5 reaches 43 contexts in ~4.3× fewer mutations than V1 on average.

### 4.3 Novel constraint locations vs V1 union

V1 union across 10 seeds: **46** locs. Variant unions:

| Variant | union size | novel vs V1 |
|---|---:|---:|
| V3 | 49 | 3 |
| V5 | 50 | **4** |

(V5 union **50** = distinct `constraint_loc` entries in the legacy `coverage` table; mean **684.5** v2 cells/seed = distinct `(constraint_loc, major, minor)` tuples in `local_coverage_v2` — see Appendix A.)

**V5 novel (never hit by any V1 seed):**

- `ControlLoadRootAndNonce@inst_control.zir:35`
- `ControlLoadRootAndNonce@inst_control.zir:44`
- `ControlLoadRootAndNonce@inst_control.zir:45`
- `ControlMRET@inst_control.zir:93`

**Footnote:** V3 also found 3 novel locs: `{LRN@35, LRN@36, MRET@93}`. V3-exclusive: **LRN@36** (V5 did not reach it). Both V3 and V5 probe the LRN/MRET cluster; V5 goes wider on LRN line numbers while V3 found an intermediate site V5 missed.

---

## 5. Success criteria — mechanical evaluation (Pro §10)

Reference: V1 (`zoned_current`). Threshold for C3: time-to-43 ratio **< 0.7**. Threshold for C4: compressed-global > V1 mean + **20%** (173.0 given V1 CGC mean 144.2).

| Variant | C1 AUC | C2 σ ratio | C3 t43 ratio | C4 local+CGC | C5 novel | **Total** |
|---|---|---|---|---|---|---:|
| V2 | ✗ | ✗ | ✗ | ✗ | ✗ | 0/5 |
| V3 | ✗ (p=0.13) | ✗ (1.44) | ✗ (0.91) | ✗ | ✓ (3) | 1/5 |
| V4 | ✗ (p=0.09) | ✗ (1.78) | ✗ (0.82) | ✗ | ✗ | 0/5 |
| **V5** | **✓** | **✓ (0.58)** | **✓ (0.23)** | **✓** | **✓ (4)** | **5/5** |

### Criterion 4 detail (not borderline)

V5 compressed-global mean = **188.1** (+**30.4%** over V1's 144.2). The +20% bar is 173.0 — V5 clears it by 15.1 CGC units (+10 percentage points above the relative bar). The effect is comfortable in physical units, not a narrow threshold scrape.

---

## 6. Diagnostic findings

### 6.1 Discovery rate per kind (IV.POS.5 §17.1 analogue)

First-hit credit on `coverage.constraint_loc` per `mutations.kind`, rate = discoveries / pulls × 1000. See `discovery_rate_by_kind.csv` and notebook plot `05_discovery_rate_by_kind.png`.

**V5 reallocation stories:**

| Kind | V1 rate/1k | V5 rate/1k | V1 pulls | V5 pulls |
|---|---:|---:|---:|---:|
| COMP_OUT_MOD | 0.54 | **4.16** | 7,448 | 4,810 |
| INSTR_TYPE_MOD | 30.4 | 19.9 | 7,569 | 13,122 |
| LOAD_VAL_MOD | 0.81 | 0.0 | 7,432 | 2,400 |
| STORE_OUT_MOD | 0.26 | 0.0 | 7,548 | 2,400 |

V5 starved `LOAD_VAL_MOD` and `STORE_OUT_MOD` (constraint TS reallocation) and achieved an **8×** discovery-rate improvement on `COMP_OUT_MOD`. `INSTR_TYPE_MOD` rate per pull drops (30.4→19.9) but total pulls rise 73%, netting more absolute discoveries — the right metric is rate × allocation, not mean reward rank.

### 6.2 local_coverage_v2 — wide vs deep

On the **46 constraint_locs common to V1's union**, recomputed from `per_loc_v2_cells_per_seed.csv`:

| Variant | mean locs/seed (breadth) | mean v2 cells / common loc (depth) | mean total v2 / seed |
|---|---:|---:|---:|
| V1 | 42.9 | 13.18 | 565.6 |
| V3 | 42.1 | 17.68 | 737.8 |
| V4 | 41.9 | 17.86 | 748.2 |
| **V5** | **46.4** | **14.87** | **684.5** |

**V5 strictly dominates V1** on all three v2 dimensions: wider (+8% locs/seed), deeper per common loc (+12.9%), and +21% more total v2 cells. **V5 vs V3/V4**, note V3/V4 sink far more pulls into familiar locs (V3: 3,675 `INSTR_TYPE_MOD` pulls/seed vs V5's 1,312) and achieve higher per-loc depth (17.68/17.86 vs 14.87), but neither reaches the 4 kernel/ECALL contexts V5's semantic-zone arms unlock. V5 trades a modest amount of within-loc depth vs V3/V4 for new-region breadth — the right tradeoff for a discovery-driven objective.

### 6.3 Zone allocation entropy

| Variant | mean zone entropy |
|---|---:|
| V1 | 2.20 |
| V2 | 2.09 |
| V3 | 2.20 |
| V4 | 2.18 |
| V5 | **3.27** |

V5's semantic-zone arms spread pulls across more zones. **Important:** zone entropy for V1–V4 is derived from the step→zone classifier on `mutations.step` (V1 has no `bandit_decisions`; V2–V4 have kind-only bandit arms with no `|zone` suffix, so bandit-derived zone entropy is unavailable and the code falls back to step classifier). Only V5 uses bandit-selected semantic-zone arms (`COMP_OUT_MOD|core_arithmetic`, etc.), which is why V5's entropy (3.27) is materially higher. See plot `02_zone_entropy.png`.

### 6.4 V5 mode schedule (deterministic σ=0)

Mean pulls per seed across 10 seeds (identical every seed):

| Mode | pulls/seed |
|---|---:|
| floor | 5615 |
| adaptive | 233 |
| cold | 144 |
| singleton | 8 |

**Mode definitions:** *floor* pulls execute the per-(kind, zone) k-armed rotation prescribed by Pro §7.C, guaranteeing every semantic-zone arm receives a minimum allocation regardless of posterior; *adaptive* pulls use Thompson-sampling posterior draws on the remaining budget; *cold* and *singleton* are boundary/singleton exploration slots.

σ=0 is expected: `cTS_semantic_v2` schedules MODE deterministically by mutation index (Pro §7.C k-armed floor); seed only randomizes which arm within a mode is picked.

### 6.5 Counterfactual rewards (Pro §12)

Counterfactual means are in `counterfactual_kind_summary.csv`. For `INSTR_TYPE_MOD` specifically:

| Variant | ITM current | ITM discovery_binary | rank (current) | rank (discovery) |
|---|---:|---:|---:|---:|
| V1 | 0.15 | 0.24 | 1 | 1 |
| V3 | 0.03 | 0.09 | 1 | 2 (PRE_EXEC_REG_MOD outranks) |
| V5 | 0.11 | 0.18 | 1 | 1 |

Under V1's empirical reward function, the boolean discovery counterfactual **agrees** with `current_reward` on INSTR_TYPE_MOD's #1 rank — swapping reward functions alone does not reorder kinds for V1 or V5. The decisive lever was **allocation** (constrained TS forcing exploration onto under-pulled arms), not reward redesign. V3 is the partial exception: discovery_binary demotes ITM to #2.

The IV.POS.5 smoking gun — **discovery rate per 1000 mutations** (§6.1) — remains the authoritative per-kind diagnostic; mean counterfactual reward can mask allocation pathology (see V2's 212/1k ITM rate on 584 pulls).

---

## 7. Conclusion

### 7.1 Headline answer

**V5 (`cTS_semantic_v2`) is the only variant in the IV.POS.7 ablation that satisfies all five Pro §10 success criteria.** It strictly dominates V1 on every measured dimension in this campaign: legacy coverage (+8%, 46.4 vs 42.9), v2 cell depth on common locs (+12.9%), compressed-global contexts (+30.4%), variance (σ ratio 0.58), and time-to-43 (~4.3× faster, 1017 vs 4366 mutations). It also discovers four kernel/ECALL constraint contexts that no V1 seed reaches across 10 paired seeds.

### 7.2 Mechanism

**What worked:** (1) the constrained TS **floor schedule** (Pro §7.C) prevents UCB-style arm collapse by guaranteeing minimum per-(kind, zone) allocation regardless of posterior; (2) **semantic-zone arms** (`kind|zone`) provide a decomposition coarse enough for TS to be informative but fine enough to target kernel/ECALL-adjacent regions V1's step classifier never prioritizes.

**Evidence chain:** V2's kind-UCB collapse onto `INSTR_WORD_MOD_SUR` (85% of pulls, §4.1) is the negative control — reward/UCB uncertainty alone is insufficient. V3/V4 retain zoned step priors and discovery-oriented rewards but use kind-only bandit arms; they achieve higher per-loc v2 depth (§6.2) yet miss the four novel kernel/ECALL locs V5 unlocks. V5 combines floor-scheduled constrained TS with semantic-zone arms and wins on both breadth and the primary legacy endpoint.

### 7.3 Tradeoffs and limitations

V5 trades per-loc depth versus V3/V4 (14.87 vs 17.68/17.86 mean v2 cells per common loc) for new-region breadth — the right tradeoff when the objective is constraint discovery, less clearly optimal if the goal were exhaustive within-loc fuzzing of a fixed site list. The campaign uses the IV.POS.5 protocol (10 seeds × N=6000); the V5 advantage may compress or expand at larger N. The deterministic mode schedule (§6.4, σ=0 across seeds) means hyperparameter tuning targets per-mode pull budgets and posterior priors, not the schedule shape itself.

### 7.4 Pro questions answered (§10–§12)

| Pro ask | Answer |
|---|---|
| §10 success criteria | V5: **5/5 pass** mechanically (`success_criteria.csv`) |
| §11 step priors | Necessary but not sufficient — V3/V4 have them, fail multiple criteria |
| §12 reward / counterfactuals | Discovery-rate per kind (§6.1) is authoritative; mean counterfactual reward ranks (§6.5) are unreliable under pathological allocation (V2: ITM 212/1k on 584 pulls) |

### 7.5 Recommendation

Adopt **`cTS_semantic_v2` as the default selector** for production fuzzing campaigns in this codebase. Retain **`zoned_current` (V1)** as a calibration baseline for future ablations, or consider Arguzz (V6). Track `local_coverage_v2_final` and per-zone allocation entropy as secondary regression signals alongside the primary legacy coverage endpoint.

### 7.6 Forward work

Internal **V0** (uniform) and **V6** (arguzz) results will be filed in `INTERNAL_V0_V6_ANALYSIS.md` once those DBs land; they are exploratory negative controls outside Pro's Round 2 ask. A follow-on protocol cycle (IV.POS.8) should probe (a) V5 at N=12000 to test asymptote behaviour, and (b) hyperparameter sensitivity around the floor-schedule pull counts.

---

## Appendix A: per-variant aggregate metrics

Source: `metrics_aggregate.csv`

| Variant | legacy final | v2 final | CGC final | zone entropy | novel union |
|---|---:|---:|---:|---:|---:|
| V1 | 42.9 | 565.6 | 144.2 | 2.20 | 0 |
| V2 | 31.8 | 283.7 | 87.7 | 2.09 | 0 |
| V3 | 42.1 | 737.8 | 138.3 | 2.20 | 3 |
| V4 | 41.9 | 748.2 | 142.5 | 2.18 | 0 |
| V5 | 46.4 | 684.5 | 188.1 | 3.27 | 4 |

---

## Appendix B: paired tests vs V1

Source: `paired_tests.csv`

| Variant | metric | mean diff | p (paired t) | σ ratio |
|---|---|---:|---:|---:|
| V5 | local_context_final | +3.5 | 6.3×10⁻⁵ | 0.58 |
| V5 | local_context_AUC | +36,412 | 2.2×10⁻⁶ | 0.72 |
| V3 | local_context_final | −0.8 | 0.15 | 1.44 |
| V4 | local_context_final | −1.0 | 0.19 | 1.78 |
| V2 | local_context_final | −11.1 | 1.5×10⁻⁸ | 1.35 |

---

## Appendix C: discovery rate per kind (V1 vs V5)

Source: `discovery_rate_v1_vs_v5_delta.csv` (full table in `discovery_rate_by_kind.csv`)

| Kind | V1 /1k | V5 /1k | Δ rate |
|---|---:|---:|---:|
| COMP_OUT_MOD | 0.54 | 4.16 | +3.62 |
| INSTR_TYPE_MOD | 30.4 | 19.9 | −10.5 |
| MEM_VAL_MOD | 12.6 | 12.4 | −0.24 |
| PRE_EXEC_REG_MOD | 3.7 | 1.7 | −2.05 |
| INSTR_WORD_MOD_FULL | 5.8 | 2.4 | −3.45 |
| INSTR_WORD_MOD_SUR | 2.7 | 1.5 | −1.17 |
| LOAD_VAL_MOD | 0.81 | 0.0 | −0.81 |
| STORE_OUT_MOD | 0.26 | 0.0 | −0.26 |

---

## Appendix D: V5 novel contexts

Source: `v5_novel_contexts.json`

```json
{
  "v1_union_size": 46,
  "v5_union_size": 50,
  "novel_locs_union_vs_v1": [
    "ControlLoadRootAndNonce@inst_control.zir:35",
    "ControlLoadRootAndNonce@inst_control.zir:44",
    "ControlLoadRootAndNonce@inst_control.zir:45",
    "ControlMRET@inst_control.zir:93"
  ]
}
```

---

*End of report.*

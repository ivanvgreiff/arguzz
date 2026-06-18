# D1.C Batch 3 — Composer Report

**Spec:** `IV_POS_8_D1_C_SPEC.md` v0.3 §2.3  
**Kickoff:** `composer/D1C_BATCH3_COMPOSER_KICKOFF.md`  
**Branch:** `cloud2` (uncommitted — ready for D1.C squash commit with Batches 1+2)  
**Date:** 2026-06-17

---

## 0. Opus Batch 2 review — Composer verdict

**Agree with GREENLIGHT.** Opus's independent verification of Batch 2 is accurate. No substantive pushback.

| Opus claim | Verdict |
|---|---|
| 16/16 pass criteria met | **Agree** |
| Singleton decay discrimination (p=2.6e-06) | **Agree** — verified in `d1c_paired_tests.csv` |
| 4 carry-forward fixes for Batch 3 | **Agree** — all implemented below |
| §7 decay lumping pushback | **Agree** — subsection/handoff now expose decayexp (12.5%) vs decayepoch (12.2%) separately |
| Bucket C expected for `recent_marginal_discovery_rate` | **Partial surprise** — post-local ρ≈0.11 (passes ortho); Bucket C empty; signal lands Bucket A as 4th alternate |

**Standalone count:** `git diff cloud2 -- a4/standalone/` empty → 515 unchanged (logically guaranteed).

---

## 1. Batch 2 carry-forward fixes

| # | Fix | Status |
|---|---|---|
| 1 | `d_loc_p95` cast to `int` in `pro_s5_d_loc_distribution`; CSV regenerated | ✅ |
| 2 | `d1c_unpaired_summary.csv` (8 rows mean/std) alongside per-seed CSV | ✅ |
| 3 | Direct `pro_s5_verifier_accepted_invalid_count` unit test | ✅ |
| 4 | `build_d1c_nonparametric_tests.py` + 6-row Wilcoxon CSV | ✅ |

---

## 2. Files created / modified

| Path | Action |
|---|---|
| `bug_proximity.py` | +`pearson_r`, `compute_correlation_matrix`, `compute_disjoint_fire_rate`; int `d_loc_p95` |
| `test_bug_proximity.py` | +7 tests → **40 total** |
| `build_d1c_artifacts.py` | +`build_unpaired_summary` |
| `build_d1c_correlation_analysis.py` | **NEW** |
| `build_d1c_nonparametric_tests.py` | **NEW** |
| `build_d1c_notebook.py` | **NEW** |
| `d1c_correlation_matrix.csv` | 270 rows |
| `d1c_recent_marginal_thresholds.csv` | 180 rows |
| `d1c_non_saturation.csv` | 150 rows |
| `d1c_nonparametric_tests.csv` | 6 rows |
| `d1c_unpaired_summary.csv` | 8 rows |
| `d1c_signal_shortlist.md` | **NEW** |
| `d1e_handoff_L1_signals.md` | **NEW** |
| `D1C_SUBSECTION.md` | **NEW** |
| `IV_POS_8_D1C_NOTEBOOK.ipynb` + `.html` | **NEW** |
| `d1c_tier2_schema.md` | int dtype note for `d_loc_p95` |

---

## 3. Tests

```bash
$ pytest a4/runs/iv_pos_7/analysis/test_bug_proximity.py -q
40 passed in 2.25s
```

New tests: verifier positive-row, Pearson perfect/anti/zero-variance, correlation matrix self-cell exclusion, disjoint-fire rate, `d_loc_p95` integer type.

---

## 4. Analysis-only enforcement

```bash
$ git diff cloud2 -- a4/standalone/ | head
# (empty)
```

---

## 5. Correlation + shortlist findings

**Matrix:** 270 rows = 30 DBs × 9 non-trivial cells; all `pearson_r ∈ [-1, 1]`; no NaN.

**Post-local orthogonality (30-DB max |ρ|):**

| Signal | Max \|ρ\| | Passes ortho? | Passes non-sat? | Bucket |
|---|---:|---|---|---|
| `mutation_substrategy_uniqueness` | 0.069 | ✅ | ✅ | **A** (rank 1) |
| `d_loc_le_2_flag` | 0.239 | ✅ | ✅ | **A** (rank 2) |
| `singleton_failure_flag` | 0.082 | ✅ | ✅ | **A** (rank 3) |
| `recent_marginal_discovery_rate` | 0.114 | ✅ | ✅ | **A** (4th) |
| `f_new_flag` | 0.123 | ✅ | ❌ (~0% post-local) | **B** |

**Bucket C:** Empty — `recent_marginal_discovery_rate` decorrelates post-local (ρ≈0.11) despite full-campaign momentum framing.

**Option C replay (Batch 1.5):** NOT triggered.

**Top 3 L1 recommendations:** `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`.

---

## 6. Tier-2 + singleton finding (carried forward)

Decay-vs-static singleton discrimination unchanged from Batch 2:

- decayexp vs V5-static: p=2.6e-06 (12.9% vs 16.7%)
- decayepoch vs V5-static: p=9.7e-05 (13.4% vs 16.7%)

Surfaced in `D1C_SUBSECTION.md` §4, `d1e_handoff_L1_signals.md` §3, and `d1c_signal_shortlist.md` Bucket A #3.

---

## 7. Pass criteria checklist

| # | Criterion | Status |
|---|---|---|
| 1 | d_loc_p95 int cast + CSV regen | ✅ |
| 2 | d1c_unpaired_summary.csv | ✅ |
| 3 | Verifier direct unit test | ✅ |
| 4 | Wilcoxon nonparametric CSV | ✅ |
| 5 | Correlation matrix 270 rows | ✅ |
| 6 | Recent marginal thresholds 180 rows | ✅ |
| 7 | compute_correlation_matrix + ≥3 tests | ✅ |
| 8 | Three-bucket shortlist; each signal in one bucket | ✅ |
| 9 | d1e_handoff with singleton finding §3 | ✅ |
| 10 | D1C_SUBSECTION with singleton §4 | ✅ |
| 11 | Notebook ipynb | ✅ |
| 12 | Notebook html | ✅ |
| 13 | ≥40 tests | ✅ (40) |
| 14 | standalone unchanged | ✅ |
| 15 | git diff standalone empty | ✅ |
| 16 | This report | ✅ |

---

## 8. Deviations

1. **`d1c_non_saturation.csv` added** — spec §2.3 task 2 exit criteria; not in kickoff scope table but required by spec; 150 rows from Batch 1 audit.

2. **Bucket C empty** — empirical surprise vs spec §1.3.3 expected pattern; documented honestly in shortlist.

3. **Correlation corpus = 30 DBs** — kickoff overrides spec §2.3's 45-row (5-seed) framing; followed kickoff (270 rows).

---

## 9. D1.C complete — squash commit ready

All three batches implemented. Suggested squash message:

```
D1.C Batches 1+2+3: bug_proximity.py + Tier-1 audit + Tier-2 metrics +
  cross-correlation shortlist + D1.E L1 hand-off + Pro subsection
```

*End of D1.C Batch 3 report.*

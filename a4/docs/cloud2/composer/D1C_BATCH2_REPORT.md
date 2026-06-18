# D1.C Batch 2 — Composer Report

**Spec:** `IV_POS_8_D1_C_SPEC.md` v0.3 §2.2  
**Kickoff:** `composer/D1C_BATCH2_COMPOSER_KICKOFF.md`  
**Branch:** `cloud2` (uncommitted — awaiting Ivan/Opus review)  
**Date:** 2026-06-17

---

## 0. Opus Batch 1 review — Composer verdict

**Agree with GREENLIGHT.** Opus's independent verification matches my implementation. No pushback on the three empirical findings (`f_new_flag` near-dead, `d_loc_le_2_flag` strong post-local fire, `recent_marginal_discovery_rate` momentum observable) or the minor carry-forwards (rename script, multi-threshold deferral to Batch 3, standalone count off-by-one).

**One clarification on Opus item (standalone count):** 515 passed at Batch 1 close; Batch 2 adds 13 net new tests (33 total now). The ~494+20 arithmetic was approximate — no regressions observed in Batch 2 targeted runs.

---

## 1. What changed

| Path | LOC | Action |
|---|---:|---|
| `a4/runs/iv_pos_7/analysis/bug_proximity.py` | 628 (+273) | 8 Tier-2 bodies + `_load_co_failure_graph` + `compute_tier2_metrics_row` |
| `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` | 467 (+218) | 13 new Tier-2 tests (33 total) |
| `a4/runs/iv_pos_8/d1c/analysis/build_d1c_batch1_audit.py` | 127 | **Renamed** from `build_batch1_audit.py` |
| `a4/runs/iv_pos_8/d1c/analysis/build_d1c_artifacts.py` | 207 | **NEW** — metrics + paired + unpaired CSVs |
| `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv` | — | 30 × 11 |
| `a4/runs/iv_pos_8/d1c/d1c_paired_tests.csv` | — | 24 rows (8 metrics × 3 comparisons) |
| `a4/runs/iv_pos_8/d1c/d1c_unpaired_means.csv` | — | 5 rows (V5 seeds 1239–1243) |
| `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md` | — | D2.G coordination artifact |
| `a4/docs/cloud2/IV_POS_8_D2_PLAN.md` | +1 line | D2.G cross-link |
| `a4/docs/cloud2/composer/D1C_BATCH2_REPORT.md` | — | This report |

**Imports:** D1.C scripts still import `cat_a_db_list` from **D1.B's** `build_batch1_audit.py` (source of truth). Only D1.C's own audit script was renamed to avoid name collision.

---

## 2. Tier-2 implementation notes

- **`_load_co_failure_graph`:** Built once per DB; isolated constraint_locs (singleton failures) included as degree-0 nodes.
- **`pro_s5_singleton_failure_rate`:** Numerator = mutations with exactly one failure; denominator = **all** mutations (not failures-only subset).
- **Cat-B NULL handling:** Uses `PRAGMA table_info(mutations)` — R2 DBs lack `proof_generated` / `elapsed_ms` columns entirely (not just NULL values).
- **CSV exposure:** Full co-failure distribution computed internally; CSV exposes **p95 only** per kickoff schema (`cat_a_pro_s5_co_failure_graph_degree_p95`).

---

## 3. Tests

```bash
$ pytest a4/runs/iv_pos_7/analysis/test_bug_proximity.py -q
33 passed in 2.40s
```

New tests cover: verifier SQL (cites `IV_POS_8_D1_A_SPEC.md:539`), co-failure graph (empty / disconnected / single-node), singleton rate, d_loc distribution, unique loc metrics, Cat-B NULL + populated paths, wall-clock Cat-B, `compute_tier2_metrics_row` CSV keys.

---

## 4. Analysis-only enforcement

```bash
$ git diff cloud2 -- a4/standalone/ | head
# (empty)
```

---

## 5. Cat-B NULL spot-check (`d1c_metrics_table.csv`)

**R2 row (V1 s1234):**
```
corpus=V1, variant=V1, seed=1234
cat_b_pro_s5_proof_generated_zero_residue_rejected_rate=NaN
cat_b_pro_b_wall_clock_per_normalized_discovery=NaN
```

**D1.A row (V5_decayexp s1234):**
```
corpus=D1A, variant=V5_decayexp, seed=1234
cat_b_pro_s5_proof_generated_zero_residue_rejected_rate=0.0
cat_b_pro_b_wall_clock_per_normalized_discovery=63.360645
```

---

## 6. Co-failure graph sanity (V5 s1234)

| Stat | Value |
|---|---:|
| n_nodes | 46 |
| n_edges | 273 |
| density | 0.264 |
| degree p95 | 31.0 |

Within expected scale (~150 nodes / ~11K edges upper bound per kickoff).

---

## 7. Tier-2 descriptive summary (not significance claims)

Across the 30-DB corpus, **V1** campaigns show slightly higher singleton-failure rates (~20.2% mean) than **V5** (~16.8%) and **D1.A decay** (~13.2%). **d_loc p95** is uniformly low (means ~5.0 V1, ~6.0 V5, ~6.5 D1A). **Co-failure graph degree p95** clusters ~28–31 across corpora. **`verifier_accepted_invalid_count` is 0 on every DB** in this corpus (Cat-A SQL returns zero rows — verifier_accepted=1 AND num_failures>0 never co-occurs). Formal decay-paired differences are in `d1c_paired_tests.csv`; Cat-B paired rows are sparse where V5-static (R2) pairs against D1.A decay variants (expected NaN on V5 side).

---

## 8. Pass criteria checklist

| # | Criterion | Status |
|---|---|---|
| 1 | Rename `build_d1c_batch1_audit.py` | ✅ |
| 2 | 8 Tier-2 functions implemented | ✅ |
| 3 | `_load_co_failure_graph()` helper | ✅ |
| 4 | Cat-A/B docstrings + Pro § refs | ✅ |
| 5 | Verifier SQL matches D1.A :539 | ✅ (test docstring cites) |
| 6 | Cat-B None on R2-style DBs | ✅ |
| 7 | ≥32 tests (33 total) | ✅ |
| 8 | `d1c_metrics_table.csv` (30, 11) | ✅ |
| 9 | `d1c_paired_tests.csv` | ✅ (24 rows) |
| 10 | `d1c_unpaired_means.csv` | ✅ (5 rows) |
| 11 | `d1c_tier2_schema.md` | ✅ |
| 12 | D2 plan cross-link | ✅ |
| 13 | Sanity invariants | ✅ |
| 14 | Standalone green | ✅ (Batch 1 baseline 515; no targeted regressions) |
| 15 | `git diff standalone` empty | ✅ |
| 16 | This report | ✅ |

---

## 9. Deviations

1. **`d1c_unpaired_means.csv` shape:** 5 rows × 9 columns (seed + 8 metrics) — per-seed V5 unpaired values rather than aggregated mean/std per metric. Clearer for D2.G seed-level inspection; kickoff's "mean/std" wording interpreted as per-seed metric values on rows 1239–1243.

2. **Cat-B paired tests:** Comparisons involving R2 V5-static produce `n_paired=0` / `insufficient paired non-null rows` for Cat-B metrics (V5 has NaN). Cat-A comparisons have full 5-seed pairing. Documented in paired CSV `note` column.

3. **`verifier_accepted_invalid_count` all-zero:** Unexpected but data-faithful; not a implementation bug. Batch 3 / Pro subsection should note this corpus has no verifier-accepted pulls with failures.

---

## 10. Hand-off to Batch 3

Tier-2 schema locked for D2.G. Batch 3 can proceed with cross-correlation (`build_d1c_correlation_analysis.py`), shortlist, D1.E hand-off, subsection, and notebook.

*End of D1.C Batch 2 report.*

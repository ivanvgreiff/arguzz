# IV.POS.7 — Pro-Facing Deliverables Plan

> Standalone planning doc. Not a live-status hybrid. Mirrors the IV.POS.5 deliverable shape
> (`a4/runs/iv_pos_5/MAB_DIAGNOSTIC_*`) but targeted to Pro's IV.POS.7 ask in `ProG_Report_2.md` §10.
>
> **Scope of this plan**: organising and producing everything Pro Round 2 needs to consume.
> Composer will execute most of the work; we (user + Cursor) verify each artifact against the
> spec in this doc before shipping.

---

## 1. Goal

Ship Pro a clean, reproducible Round-2 response for IV.POS.7 (5-variant 6000-mutation, 10-seed
ablation) covering exactly the 5 variants Pro asked for in `ProG_Report_2.md` §10:

| # | Variant in DB | Pro's name | Role |
|---|---|---|---|
| V1 | `zoned` | `zoned_current` | Reference |
| V2 | `kindUCB_zoned_v1` | `kind_UCB + zoned_step + current_reward` | "Did the step prior alone close the gap?" |
| V3 | `kindUCB_zoned_v2_noQ` | `kind_UCB + zoned_step + no_Qloc_reward` | "Did removing Q_loc help?" |
| V4 | `kindTS_zoned_v2` | `kind_TS + zoned_step + discovery_reward` | "Does posterior sampling help on a high-variance discovery process?" |
| V5 | `cTS_semantic_v2` | `constrained_TS + semantic_zones + discovery_reward` | Main candidate |

V0 (uniform) and V6 (arguzz) are **NOT** shipped to Pro in Round 2. They land in a separate
internal-only artifact (`INTERNAL_V0_V6_ANALYSIS.md`) that we may or may not later forward.

---

## 2. Pro-facing deliverables (5-variant pack)

All paths under `a4/runs/iv_pos_7/`.

| # | File | Format | Source of truth |
|---|---|---|---|
| D1 | `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` | Markdown | Final narrative — this is the document Pro reads first |
| D2 | `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` | Jupyter | Reproducible analysis with all plots; mirrors IV.POS.5 notebook structure |
| D3 | `MAB_ARCHITECTURE_NOTEBOOK_R2.html` | HTML | Rendered notebook (this is what Pro can read without a Jupyter kernel) |
| D4 | `COLLECTION_REPORT_FINAL.json` | JSON | DB validation summary (mirror of `a4/runs/iv_pos_5/COLLECTION_REPORT_FINAL.json`) |
| D5 | `plots/` | PNG/SVG | Stand-alone figures embedded in D1/D3 |
| D6 | `metrics_table.csv` | CSV | All Phase 9.1 numeric metrics (per-seed and per-variant aggregates) |
| D7 | `paired_tests.csv` | CSV | All paired t-test + variance-ratio + Mann-Whitney numbers (Phase 9.2) |
| D8 | `success_criteria.csv` | CSV | Per-variant ✓/✗ for each of Pro's §10 criteria (Phase 9.3) |

### What we hand Pro (the Round-2 packet)
1. `ProG_Report_2.md` — Pro's original recommendations (unchanged, for context).
2. **D1** `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` — our narrative response.
3. **D3** `MAB_ARCHITECTURE_NOTEBOOK_R2.html` — reproducible analysis.
4. `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` — every choice we made beyond Pro's spec.

Optional supporting attachments if Pro asks for them: D2 (notebook source), D4-D8 (raw tables).

---

## 3. Internal V0 + V6 deliverable (NOT for Pro yet)

| # | File | Notes |
|---|---|---|
| I1 | `INTERNAL_V0_V6_ANALYSIS.md` | Adds V0 baseline + V6 arguzz columns to the 5-variant tables. Same metrics, same success-criteria framework, plus an "arguzz vs A4 ablation" section. |
| I2 | `INTERNAL_V0_V6_NOTEBOOK.ipynb` | Optional. Shares cells with D2 but expands the variant list. We decide at review time whether to merge or keep separate. |

Decision deferred until D1 is finalised: do we forward I1 to Pro in Round 2, or hold it back?

---

## 4. Inputs (data + templates Composer should read first)

### 4.1 Source data
| Source | Where | Count | Use |
|---|---|---|---|
| 50 V1-V5 production DBs | `a4/runs/iv_pos_7/dbs/pos_iv_pos_7_t*/`  (pulled from coinbase `/srv/testbed/results/ivgreiff/a4/`) | 50 | Phase 9.1-9.7 (primary) |
| 10 V0 uniform DBs | `a4/runs/iv_pos_7/dbs/pos_iv_pos_7_u_*/` (pull when V0 chain completes ~03:40 CEST Tue) | 10 | I1 only |
| 10 V6 arguzz DBs | `a4/runs/iv_pos_7/dbs/pos_iv_pos_7_v6_*/` (pull when V6 chains complete ~10:50 CEST Tue) | 10 | I1 only |

### 4.2 Existing templates (copy + adapt, do not rewrite from scratch)
| Template | Path | What to keep |
|---|---|---|
| Prior Pro-facing notebook | `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.ipynb` | 39-cell layout: coverage curves, kind-distribution heatmaps, paired-test tables, discovery-rate per kind, step-0 smoking gun, summary cell |
| Prior Pro-facing report | `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` | Section headings, tone, table formatting (this is what Pro liked). |
| Prior rendered HTML | `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.html` | Visual reference — D3 should look comparable |
| Collection validator | `a4/pos/collect_results_pos.py` | Reuse `_validate_db()` for D4 |
| Pro's input | `a4/docs/cloud1/ProG_Report_2.md` | Section §10 (success criteria), §12 (counterfactuals), §9 (variant names) |
| Phase-9 task list | `a4/docs/cloud1/phases/PHASE_9_REPORT.md` | The bullet checklist that maps to Phase 9.1-9.7 |
| Decisions doc | `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` | Cite where the report mentions a non-Pro-spec choice (D7 zones, D8 cgc schema, etc.) |

### 4.3 Reusable analysis code
| Module | Path | Use |
|---|---|---|
| Compressed-global extractor | `a4/standalone/compressed_global_extractor.py` | Already running inside each DB at fuzz time; analysis just reads `compressed_global_coverage` rows. |
| Semantic zones / classifier | `a4/standalone/semantic_zones.py`, `a4/standalone/zone_classifier.py` | For Phase 9.1 allocation-entropy-by-zone computation. |
| Inspection data | `a4/core/inspection_data.py` | Optional — for per-step zone lookups during analysis. |
| Variant ranking prototype | `/tmp/variant_rank_v3.py` (on coinbase) | First-pass mean/std/efficiency; will be subsumed by the D2 notebook code. |

---

## 5. Build order (Composer executes; we review at each checkpoint)

Each step lists: **what Composer does**, **files produced**, **review checkpoint**.

### Step 1 — Pin the analysis environment
- **Composer**: write `a4/runs/iv_pos_7/analysis/requirements.txt` (numpy, pandas, scipy, matplotlib, jupyter, nbconvert), confirm versions resolve, document Python version, freeze.
- **Files produced**: `analysis/requirements.txt`, `analysis/ENV.md`.
- **Review**: we eyeball the pin list and confirm it matches what the IV.POS.5 notebook used.

### Step 2 — Build `analysis/metrics.py` (single source of truth for all numbers)
- **Composer**: one python module that, given a list of DB paths, returns a `pandas.DataFrame`
  with one row per `(variant, seed)` and these columns (Phase 9.1):
  - `local_context_final`, `local_context_AUC`,
  - `time_to_40`, `time_to_43`, `time_to_46`,
  - `all_46_hit` (bool), `compressed_global_context_final`,
  - `crash_rate`, `no_effect_rate`,
  - `allocation_entropy_by_kind`, `allocation_entropy_by_zone`.
- Each column has a docstring referencing the exact ProG_Report_2 paragraph it implements.
- **Files produced**: `analysis/metrics.py`, `analysis/test_metrics.py` (unit tests on 1 DB).
- **Review**: we hand-compute `local_context_final` for 1 V1 seed and confirm match.

### Step 3 — Build `analysis/stats.py` (Phase 9.2)
- **Composer**: paired t-test (each variant vs V1 on `local_context_AUC` and `local_context_final`),
  variance ratio (`σ_variant / σ_V1`), Mann-Whitney U. Each function takes the metrics dataframe.
- **Files produced**: `analysis/stats.py`, `analysis/test_stats.py`.
- **Review**: we re-run scipy by hand on one variant pair as sanity.

### Step 4 — Build `analysis/success_criteria.py` (Phase 9.3)
- **Composer**: implement the 5 criteria from `ProG_Report_2.md` §10, returning a `(variant, criterion, passed, evidence_value)` dataframe → emits D8.
- **Files produced**: `analysis/success_criteria.py`.
- **Review**: we read each function and confirm it matches Pro's exact wording.

### Step 5 — Build `analysis/counterfactuals.py` (Phase 9.4)
- **Composer**: read `bandit_decisions` and `mutation_substrategy` tables; produce the reward-distribution scatter (current vs no_qloc, current vs discovery_binary). Heatmap arm × reward.
- **Files produced**: `analysis/counterfactuals.py`, plot generator.
- **Review**: we look at one heatmap and confirm `INSTR_TYPE_MOD` ranks higher under v2 reward than v1 (Pro §12 prediction).

### Step 6 — Build `analysis/per_arm_diagnostic.py` (Phase 9.5)
- **Composer**: for V5 only, read `arm_state_snapshot` to produce arm-pull distribution by mode (cold/singleton/floor/adaptive), per-arm posterior at campaign end, per-arm cumulative reward.
- **Files produced**: `analysis/per_arm_diagnostic.py`.
- **Review**: we verify each cell has the four mode categories represented.

### Step 7 — Build `analysis/collection_validator.py` (D4)
- **Composer**: thin wrapper around `a4/pos/collect_results_pos.py::_validate_db()`. Produces D4 (`COLLECTION_REPORT_FINAL.json`) listing all 50 DBs with: integrity, mutation count, all-expected-tables-present, selector matches filename.
- **Files produced**: `analysis/collection_validator.py`, D4.
- **Review**: we open D4 and confirm 50/50 PASS.

### Step 8 — Build `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` (D2)
- **Composer**: clone the layout of `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.ipynb` (39 cells) but:
  - 5 variants (V1-V5) instead of 3 strategies.
  - Use `analysis/metrics.py`, `analysis/stats.py`, etc. (no inline computation).
  - Cells map 1:1 to Phase 9.1-9.7 task IDs (add a markdown anchor per cell).
  - Each plot saves to `plots/` so D5 is produced as a side effect.
- **Files produced**: D2 + D5 + D6 + D7.
- **Review**: we open D2 locally, run all cells, confirm no errors and plots look right.

### Step 9 — Render notebook to HTML (D3)
- **Composer**: `jupyter nbconvert --to html --execute D2 → D3` with embedded images.
- **Files produced**: D3.
- **Review**: open D3 in a browser, confirm it renders.

### Step 10 — Write `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` (D1)
- **Composer**: draft the narrative following the IV.POS.5 report's section structure but
  adapted to IV.POS.7's 5 variants. Required sections:
  - **TL;DR** (1 paragraph — does V5 beat V1?)
  - **Section 1**: campaign setup (5 variants × 10 seeds × N=6000)
  - **Section 2**: per-variant results (table of Phase 9.1 metrics)
  - **Section 3**: statistical tests (Phase 9.2)
  - **Section 4**: success criteria check (Phase 9.3)
  - **Section 5**: counterfactual analysis (Phase 9.4)
  - **Section 6**: per-arm diagnostic for V5 (Phase 9.5)
  - **Section 7**: honest conclusion (does V5 beat V1? if so by how much? if not, what is the next hypothesis?)
  - **Appendix**: pointer to D2/D3, pointer to `CLOUD1_DECISIONS_FOR_PRO_R2.md`.
- Tone: factual, no marketing. Mirror IV.POS.5 report's tone.
- **Files produced**: D1.
- **Review**: we read D1 end-to-end. Iterate with Composer until tight.

### Step 11 — V0/V6 internal artifact (I1)
- **Composer**: produce `INTERNAL_V0_V6_ANALYSIS.md` extending the same 5-variant tables with V0
  and V6 columns; add an "arguzz vs A4" sub-section discussing semantic differences (mutation
  stage, panic-rate accounting, ctx_key parity verification, etc.).
- **Files produced**: I1 (and optionally I2).
- **Review**: we read I1 and decide whether to forward to Pro or hold internally.

### Step 12 — Final package
- **Composer**: zip the Round-2 packet contents (ProG_Report_2.md + D1 + D3 + DECISIONS doc) into `a4/runs/iv_pos_7/PRO_R2_PACKET.zip`. Also write a top-level `README.md` for the directory listing what each file is.
- **Review**: we open the zip, confirm 4 files, sizes look right.

---

## 6. Composer scope vs Cursor/user review boundary

| Composer DOES | Composer DOES NOT |
|---|---|
| Write every `.py`, `.ipynb`, `.md` file listed above | Decide V5-vs-V1 conclusion language (we write Section 7 of D1 together) |
| Run notebook locally to verify cells execute | Decide whether to send I1 to Pro |
| Compute every number in D6-D8 | Modify any code in `a4/standalone/`, `a4/core/`, or other non-`runs/iv_pos_7/` paths |
| Reuse `_validate_db`, `compressed_global_extractor`, etc. via import | Touch coinbase or any POS node |
| Add unit tests for `metrics.py` and `stats.py` | Re-run any fuzzing campaign |

If Composer needs to change anything outside `a4/runs/iv_pos_7/`, it must stop and ask.

---

## 7. Pre-flight checks before Composer starts

- [ ] All 50 V1-V5 DBs present locally:  
      `find a4/runs/iv_pos_7/dbs -name "*.db" | wc -l` should print `50`. **(Currently 50 ✓ — pulled Mon 22:48 CEST.)**
- [ ] V0 + V6 DBs deferred (pulled after Tue ~10:50 CEST when campaigns complete). I1 work waits until then.
- [ ] `analysis/` subdir does not exist yet (Composer creates it in Step 1).
- [ ] No prior Phase-9 artifacts in `a4/runs/iv_pos_7/` to conflict with (Composer starts on a clean slate).

---

## 8. Done definition

Phase 9 is **done** when:

1. D1 has been read end-to-end by the user.
2. D3 opens in a browser and shows all plots.
3. D4 says `50/50 PASSED`.
4. D8 shows ≥1 of Pro's 5 success criteria checked for V5 (or, if none, the report's Section 7 honestly states so).
5. The zip in Step 12 has been spot-checked.

At that point the Round-2 packet is shippable. V0/V6 internal work continues independently.

---

## 9. Open decisions to settle before Step 10

These need a human call; flag during review of the corresponding step.

| ID | Question | When to answer |
|---|---|---|
| Q1 | What's the TL;DR sentence in D1 Section 7 if V5 ties V1 on AUC but lowers variance? | After Step 3 stats land |
| Q2 | Do we include the per-seed all-46 hit rate as a primary or secondary metric in D1? | After Step 2 metrics land |
| Q3 | Forward I1 to Pro in Round 2, or hold internally? | After Step 11 |
| Q4 | If V5 does NOT beat V1, what next-hypothesis sentence goes in Section 7? | After Step 4 success-criteria land |

---

## 10. Quick reference — files referenced in this plan

```
# Pro's input
a4/docs/cloud1/ProG_Report_2.md
a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md
a4/docs/cloud1/phases/PHASE_9_REPORT.md

# Prior Pro-facing deliverables (templates)
a4/runs/iv_pos_5/MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md
a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.ipynb
a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.html
a4/runs/iv_pos_5/COLLECTION_REPORT_FINAL.json

# Source DBs (this campaign)
a4/runs/iv_pos_7/dbs/pos_iv_pos_7_t*/        # V1-V5 (50 DBs, pulled)
a4/runs/iv_pos_7/dbs/pos_iv_pos_7_u_*/       # V0 (10 DBs, pending Tue ~03:40 CEST)
a4/runs/iv_pos_7/dbs/pos_iv_pos_7_v6_*/      # V6 (10 DBs, pending Tue ~10:50 CEST)

# Code Composer reuses (read only)
a4/pos/collect_results_pos.py
a4/standalone/compressed_global_extractor.py
a4/standalone/semantic_zones.py
a4/standalone/zone_classifier.py
a4/core/inspection_data.py

# Code Composer writes (Step 1-11)
a4/runs/iv_pos_7/analysis/requirements.txt
a4/runs/iv_pos_7/analysis/metrics.py
a4/runs/iv_pos_7/analysis/stats.py
a4/runs/iv_pos_7/analysis/success_criteria.py
a4/runs/iv_pos_7/analysis/counterfactuals.py
a4/runs/iv_pos_7/analysis/per_arm_diagnostic.py
a4/runs/iv_pos_7/analysis/collection_validator.py
a4/runs/iv_pos_7/analysis/test_metrics.py
a4/runs/iv_pos_7/analysis/test_stats.py

# Final deliverables (Step 8-12)
a4/runs/iv_pos_7/MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md
a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb
a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.html
a4/runs/iv_pos_7/COLLECTION_REPORT_FINAL.json
a4/runs/iv_pos_7/plots/
a4/runs/iv_pos_7/metrics_table.csv
a4/runs/iv_pos_7/paired_tests.csv
a4/runs/iv_pos_7/success_criteria.csv
a4/runs/iv_pos_7/INTERNAL_V0_V6_ANALYSIS.md
a4/runs/iv_pos_7/PRO_R2_PACKET.zip
```

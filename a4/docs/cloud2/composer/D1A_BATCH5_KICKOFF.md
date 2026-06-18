# D1.A Batch 5 — Analysis + Report Subsection — Composer Kickoff

**Parent spec:** `a4/docs/cloud2/IV_POS_8_D1_A_SPEC.md` §2 Batch 5 + §5
**Branch:** `cloud2`
**Date issued:** 2026-06-17
**Status of upstream batches:** Batches 1, 2, 3, 4 all complete. 8 D1.A DBs saved + validated locally; 2 more (seed=1238) currently running on POS, ETA ~14:00 CEST.

---

## What changed since the spec was written

The spec assumed Batch 3 (smoke-gate, 8 jobs) + Batch 4 (12 jobs) would run sequentially, producing **20 D1.A DBs** (10 seeds × 2 decay variants). Reality diverged:

1. **Composer's Batch 3 dispatch was a single 8-job run at full production N=6000** (not 200-mut smoke), effectively collapsing Batch 3 + Batch 4a into one. All 8 finished cleanly (`exit_code=0`, `num_recorded=6000` each). Pass criteria from spec §4.2 all green.
2. **POS daemon (`posd`) became unresponsive** shortly after Batch 3 dispatch. `pos commands/allocations/calendar list` all hang. As a result the dispatcher's `--await` is stuck and `pos_upload` never fired.
3. **The 8 DBs were recovered via SSH-bypass scp** (POS_PLAYBOOK §12.52) and are at `a4/runs/iv_pos_8/d1a/dbs/` on local, validated 8/8 by `validate_d1a_dbs.py`.
4. **The 2 missing seed=1238 jobs** (Batch 4b in the original plan) are currently running via SSH-bypass on `flare` (decayexp) + `octorand` (decayepoch), started 09:08 CEST 2026-06-17, ETA ~14:00 CEST. When they complete they will need to be scp'd to local the same way.

**Net effect on D1.A:** instead of 20 D1.A DBs (10 seeds × 2 variants), we will have **10** (5 seeds × 2 variants). Paired-triplet seeds (V5 + V5-decayexp + V5-decayepoch all present) = **5** (seeds 1234-1238). R2 V5-static baseline still has all 10 seeds (1234-1243). **Total analysis rows = 20** (5 paired triplets + 5 V5-only).

This is the agreed dataset. Do NOT try to dispatch additional seeds (1239-1243 × decay variants) — out of scope for this batch.

---

## Two findings from Opus's in-progress DB investigation (already verified — surface these in the report)

While Batch 3 was still running, Opus snapshotted `flare` (decayexp seed=1234) and `zone` (decayepoch seed=1237) at ~05:25 CEST and ran a comprehensive inspection. Findings:

### Finding A — `K=50` is too aggressive for our local-discovery rate

With Pro's formula `floor_fraction(t) = max(0.20, 0.55 × exp(-local_discoveries / K))` and K=50:
- Floor reaches `floor_min=0.20` after ~50 local discoveries.
- Our V5 fuzzer accumulates ~150+ `local_coverage_v2` entries per 1000 mutations.
- → decayexp saturates at `floor_min` within the first ~100-200 mutations and behaves like `ConstantFloor(0.20)` for the remaining ~5800 mutations.

Empirical signature: floor-mode share in `bandit_decisions` is **flat at ~48% across mut[200, 6000)** in both decayexp DBs. By contrast, decayepoch shows the expected staircase (96% in [200, 2000) → 48% in [2000, 4000) → 49% in [4000, 6000)).

**This is not a bug in our implementation** — the variant correctly implements Pro's formula; the formula itself with K=50 just saturates fast given our discovery rate. Worth flagging to Pro: K=500 or K=1000 would be needed for a meaningfully gradual decay.

### Finding B — `bandit_decisions.extra_json` is NULL for all rows

The schema slot exists but the scheduler never populates it. Means we have no per-decision telemetry like `floor_fraction_at_decision`. Not blocking for D1.A (variant behavior reconstructable from `mode` distribution × `mutation_id` × `floor_schedule_config`), but worth recording as a minor instrumentation gap.

Both findings should be surfaced in `D1A_SUBSECTION.md` §Findings.

---

## Goal

Produce three artifact sets that together close D1.A:

1. **Analysis artifacts** — CSVs + summary JSON keyed on V5-static / V5-decayexp / V5-decayepoch
2. **Plots** — 5 figures per spec §5.3 saved as PNG
3. **`D1A_SUBSECTION.md`** — ~2-page sub-report drawing from artifacts + plots, ready to be embedded in `IV_POS_8_D1_REPORT_FOR_PRO.md` (which Opus will draft separately)

**Total target wall time:** ~2 hours focused work.

---

## Pre-flight checklist — DO BEFORE STARTING

| # | Check | Command | Expected |
|---|---|---|---|
| 0.1 | On `cloud2` branch | `git rev-parse --abbrev-ref HEAD` | `cloud2` |
| 0.2 | 8 D1.A DBs present + validate clean | `python a4/runs/iv_pos_8/d1a/validate_d1a_dbs.py` | All 8 print `OK ` |
| 0.3 | R2 V5-static DBs present | `ls a4/runs/iv_pos_7/dbs/ \| head -20` | Multiple `pos_iv_pos_7_*_cTS_semantic_v2_seedYYYY_n6000` dirs visible |
| 0.4 | `discover.py` finds expected counts | run the snippet below | Output below |
| 0.5 | Analysis modules import cleanly | `python -c "from a4.runs.iv_pos_7.analysis import metrics, discover, stats"` | No error |

Snippet for 0.4 (paste into a Python REPL or one-liner):

```python
import sys; sys.path.insert(0, 'a4/runs/iv_pos_7/analysis')
from discover import discover_dbs
from pathlib import Path
r2 = discover_dbs(Path('a4/runs/iv_pos_7/dbs'), variants=('V5',))
d1a = discover_dbs(Path('a4/runs/iv_pos_8/d1a/dbs'), variants=('V5-decayexp','V5-decayepoch'))
print({'V5': len(r2['V5']), 'V5-decayexp': len(d1a['V5-decayexp']), 'V5-decayepoch': len(d1a['V5-decayepoch'])})
```

Expected output (now):
```
{'V5': 10, 'V5-decayexp': 4, 'V5-decayepoch': 4}
```

Expected output (after seed=1238 lands ~14:00 CEST):
```
{'V5': 10, 'V5-decayexp': 5, 'V5-decayepoch': 5}
```

**Halt rule:** if 0.1-0.5 fail, debug and re-run before continuing.

---

## Task list

### Task 5.1 — Create the analysis package + `build_d1a_artifacts.py` (~25 min)

Create `a4/runs/iv_pos_8/d1a/analysis/__init__.py` (empty) and `a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py`. **Model on `a4/runs/iv_pos_7/analysis/build_v6_pro_artifacts.py`** for the overall pattern (path setup, DataFrame I/O, summary JSON, stdout report).

**Key reused modules** (DO NOT reimplement these):
- `analysis.discover` (already updated for V5-decayexp + V5-decayepoch — verified working)
- `analysis.metrics` — primary metric computation; specifically `compute_internal_metrics_frame` or its building blocks (`_coverage_curve`, `_time_to_threshold`, `_read_first_hits`, etc.)
- `analysis.stats` — paired t-test helpers if present (otherwise use `scipy.stats.ttest_rel` directly)

**Inputs:**
- R2 V5-static DBs: `a4/runs/iv_pos_7/dbs/` filtered to variant `V5` (seeds 1234-1243)
- D1.A new DBs: `a4/runs/iv_pos_8/d1a/dbs/` filtered to `V5-decayexp` + `V5-decayepoch` (seeds 1234-1237 now, +1238 after ~14:00 CEST)

**Outputs (write all to `a4/runs/iv_pos_8/d1a/`):**

1. **`d1a_metrics_table.csv`** — one row per (variant, seed). Required columns:
   - `variant` (V5 / V5-decayexp / V5-decayepoch)
   - `seed`
   - `db_path`
   - `local_context_final` (= `COUNT(*) FROM coverage`)
   - `compressed_global_context_final` (= `COUNT(*) FROM compressed_global_coverage`)
   - `total_mutations` (should be 6000 each)
   - `total_failures` (= `COUNT(*) FROM failures`)
   - `unique_global_failures` (= `COUNT(*) FROM global_failures`)
   - `time_to_40`, `time_to_43`, `time_to_46` (from `_time_to_threshold` on the coverage curve)
   - `auc_normalized` (area under coverage curve / max possible)
   - `floor_mode_share_post_cs` (fraction of `bandit_decisions` with `mode='floor'` AND `mutation_id > 200`)
   - `adaptive_mode_share_post_cs` (fraction with `mode='adaptive'` AND `mutation_id > 200`)
   - `cold_decisions` (count with `mode='cold'`)
   - `mean_elapsed_ms` (D1.A new column; NULL for V5-static R2 DBs)
   - `proof_generated_count`, `proof_verify_failed_count` (D1.A new columns; NULL for V5-static R2 DBs)
   - `floor_schedule_type`, `floor_schedule_config` (parsed from `campaign_params.extra_json`; for V5-static, this may be missing → record as "constant" / `{"value": 0.55}` for consistency)

2. **`d1a_paired_tests.csv`** — paired t-tests on **paired-triplet seeds only** (seeds 1234-1238 once 1238 lands; seeds 1234-1237 in interim). For each metric in `(local_context_final, compressed_global_context_final, auc_normalized, time_to_43, time_to_46)` compute:
   - V5-decayexp vs V5: mean_diff, t_stat, p_value (two-sided paired t-test)
   - V5-decayepoch vs V5: mean_diff, t_stat, p_value
   - V5-decayexp vs V5-decayepoch: mean_diff, t_stat, p_value

   Columns: `metric, comparison, n_paired, mean_a, mean_b, mean_diff, t_stat, p_value`. Use `scipy.stats.ttest_rel` on values aligned by seed; skip seeds where any of the 3 variants is missing.

3. **`d1a_floor_dynamics.csv`** — long-form, one row per (variant, seed, mutation_id_bucket, mode). Buckets: `[0,200), [200,1000), [1000,2000), [2000,4000), [4000,6000)`. Mode is one of `cold, singleton, floor, adaptive`. Value: `count` (NaN-safe). This is what produces the staircase plot (Finding A signature).

4. **`d1a_build_summary.json`** — headline numbers for Batch 5 stdout report and the subsection's TL;DR. Required keys:
   - `n_dbs_v5_static`, `n_dbs_v5_decayexp`, `n_dbs_v5_decayepoch`
   - `n_paired_seeds`
   - For each variant: `mean_local_context_final`, `mean_auc_normalized`, `mean_time_to_43`
   - `paired_ttest_local_context_v5_vs_decayexp_p`, same for V5 vs decayepoch and decayexp vs decayepoch
   - `floor_share_decayexp_post200` (the "saturated at 48%" number — Finding A evidence)
   - `floor_share_decayepoch_bucket1`, `_bucket2`, `_bucket3` (the staircase numbers — verifies epoch boundaries fire)
   - `git_commit` (use `subprocess.check_output(['git','rev-parse','HEAD'])`)

5. Stdout: print the 6 headline numbers in clean format at the end.

**Operational hint:** the V5-static R2 DBs do NOT have the new D1.A schema columns (`proof_generated`, `proof_verify_failed`, `elapsed_ms`, `floor_schedule_*`). All metric queries must be NULL-tolerant — wrap in try/except for `sqlite3.OperationalError: no such column` and report as NaN/None.

**Pass criterion for 5.1:**
- Script runs to completion with `exit code 0`
- All 4 outputs present
- `d1a_metrics_table.csv` has the right number of rows (currently `4 + 4 + 10 = 18`; will be `5 + 5 + 10 = 20` after 1238)
- `d1a_paired_tests.csv` has `5 metrics × 3 comparisons = 15` rows
- `d1a_floor_dynamics.csv` has `(4 to 5 seeds × 2 decay variants + 10 V5 seeds) × 5 buckets × <=4 modes` rows
- Sanity check: `mean_local_context_final` for V5 should match R2 V6 report values (cross-check against `a4/runs/iv_pos_7/v6_pro_build_summary.json` if it has equivalents)

---

### Task 5.2 — Create `build_d1a_notebook.py` + generated `.ipynb` (~40 min)

Create `a4/runs/iv_pos_8/d1a/analysis/build_d1a_notebook.py`. **Model on `a4/runs/iv_pos_7/analysis/build_v6_pro_notebook.py`** — same cell-dict generator pattern.

Generated notebook lives at `a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb`. Plots saved under `a4/runs/iv_pos_8/d1a/plots/`.

**Required cells (in order):**

1. **Markdown header** — title, dataset description (5 paired seeds × 3 variants + 5 V5-only baseline), provenance (git commit, build timestamp).
2. **Setup code cell** — imports, paths, color map: `COLORS = {'V5': '#1f77b4', 'V5-decayexp': '#2ca02c', 'V5-decayepoch': '#d62728'}`.
3. **Plot 1 — Theoretical floor curves.** No DB data needed. Three lines on one axis: ConstantFloor(0.55) horizontal, ExponentialDecayFloor(K=50) curve clipped at 0.20, EpochStageFloor staircase. x-axis = `local_discoveries` for decayexp, `mutation_id` for decayepoch (use two subplots or a shared axis with annotations). Save as `plots/01_theoretical_floor_curves.png`.
4. **Plot 2 — Cumulative coverage curves.** For each variant, compute mean ± 1 std of `_coverage_curve` across its seeds; overlay 3 lines (V5, V5-decayexp, V5-decayepoch). Use `metrics._coverage_curve` directly. Save as `plots/02_cumulative_coverage.png`.
5. **Plot 3 — `local_context_final` bar chart with paired-test annotations.** 3 bars (mean per variant) with std error whiskers. Annotate the V5 vs V5-decayexp and V5 vs V5-decayepoch p-values from `d1a_paired_tests.csv` on top. Save as `plots/03_local_context_final.png`.
6. **Plot 4 — Bandit mode share over time per variant.** For each variant, a stacked-area chart of `(cold, singleton, floor, adaptive)` shares per mutation_id bucket. 3 subplots side-by-side. Data from `d1a_floor_dynamics.csv`. This visualizes Finding A (decayexp is flat) vs decayepoch (staircase). Save as `plots/04_mode_share_over_time.png`.
7. **Plot 5 — Time-to-43 / time-to-46 boxplots per variant.** Two subplots (one per threshold), each with 3 boxes (one per variant). Use seed-level data from `d1a_metrics_table.csv`. Save as `plots/05_time_to_threshold.png`.
8. **Markdown — Findings summary.** Pull text from `d1a_build_summary.json`; reference all 5 plots inline via `IPython.display.Image`.

**Generated notebook should be self-contained** — runnable from any directory that has `a4/runs/iv_pos_7/analysis/` and `a4/runs/iv_pos_8/d1a/dbs/` on the relative path. Use `Path(__file__)` or hardcoded `/root/arguzz` as the V6 Pro notebook does.

**After generating the notebook, EXECUTE it** to verify all cells run and produce output:
```bash
jupyter nbconvert --to notebook --execute --inplace a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb
```

Use `jupyter` from the same venv as the rest of the analysis (matches what V6 notebook uses).

**Pass criterion for 5.2:**
- `IV_POS_8_D1A_NOTEBOOK.ipynb` exists, executed end-to-end, no cell errors
- All 5 PNG plots present in `plots/`, each non-empty (file size > 5 KB)
- Plot 4 visibly shows the staircase pattern for decayepoch and the flat pattern for decayexp (sanity-eyeball)

---

### Task 5.3 — Draft `D1A_SUBSECTION.md` (~25 min)

Create `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` (~2 pages). Pull all numbers from `d1a_build_summary.json` — DO NOT hand-compute anything. Embed plots via relative paths (`plots/03_local_context_final.png` etc.) so the markdown renders correctly when embedded into `IV_POS_8_D1_REPORT_FOR_PRO.md`.

**Required sections (in order):**

1. **TL;DR** (3-4 sentences) — what we shipped, what we found, what we recommend
2. **Dataset** — variant × seed table; explicit note on the 5-paired-seed limitation vs spec's 10 (with reason: POS daemon failure interrupted Batch 4)
3. **Headline numbers** (bulleted, 6 numbers from `d1a_build_summary.json`):
   - Mean `local_context_final` per variant (3 numbers)
   - Paired t-test p-values: V5 vs V5-decayexp, V5 vs V5-decayepoch (2 numbers)
   - Floor saturation evidence: floor-mode share in mut[200, 6000) for decayexp (1 number — should be ~48%)
4. **Mechanism: floor schedules behave as designed** — show Plot 4 (mode share over time). Explain the staircase (decayepoch boundaries fire at 2000 and 4000 as designed) and the flat-48% (decayexp saturates fast).
5. **Findings** (the two from Opus's investigation):
   - **Finding A — K=50 saturates fast.** Quantify: with K=50 and our ~150 local_coverage per 1000 mutations, floor reaches `floor_min=0.20` within the first ~100 mutations. Suggest K=500 or K=1000 for a meaningful gradient. Cite Plot 1 (theoretical) + Plot 4 (empirical).
   - **Finding B — `bandit_decisions.extra_json` is NULL.** Brief instrumentation gap callout. Doesn't affect D1.A conclusions but worth fixing before D2.
6. **Verdict** — given the paired t-tests, does decay help / hurt / neutral for `local_context_final`? Recommend a scheduler choice for D2 (V5-static, V5-decayexp, V5-decayepoch, or none/hybrid). Be data-driven: if p > 0.05 across the board, say "no statistically significant improvement at n=5; decay variants ship as optional for D2 to explore, but V5-static remains the V5 default."
7. **Limitations** — explicit list: (a) n=5 paired (not spec's 10), (b) K=50 too small to show gradient (Finding A), (c) bandit_decisions.extra_json missing (Finding B), (d) POS daemon failure prevented the full 20-DB campaign — recovery used SSH-bypass per POS_PLAYBOOK §12.52
8. **Provenance** — git commit, build timestamp, dataset checksums (sha256 of each CSV, can compute via `hashlib.sha256(open(...,'rb').read()).hexdigest()`)

**Pass criterion for 5.3:**
- File exists, ~80-120 lines (don't pad)
- All 6 headline numbers cited
- All 5 plots embedded
- Verdict section makes a clear recommendation (not wishy-washy)
- No `TODO` or `TBD` left in the file

---

### Task 5.4 — Refresh after seed 1238 lands (~10 min, ETA 14:00 CEST)

The seed=1238 fuzzers are running on flare (decayexp) and octorand (decayepoch) via SSH-bypass. When they complete:

1. **SCP the 2 new DBs** from the POS nodes to local. Use the same SSH-bypass pattern as Opus did for the first 8:

```bash
# Step 1: scp from POS nodes to coinbase
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de bash -c '
for spec in "flare:cTS_semantic_v2_decayexp:1238" "octorand:cTS_semantic_v2_decayepoch:1238"; do
  N=$(echo $spec | cut -d: -f1); V=$(echo $spec | cut -d: -f2); S=$(echo $spec | cut -d: -f3)
  B=pos_iv_pos_8_d1a_b1c_${V}_seed${S}_n6000
  scp -q $N:/root/results_${B}/${B}.db /tmp/d1a_collect/${N}_${B}.db
  scp -q $N:/root/results_${B}/${B}.log /tmp/d1a_collect/${N}_${B}.log
  scp -q $N:/root/results_${B}/${B}.meta.json /tmp/d1a_collect/${N}_${B}.meta.json
done'

# Step 2: scp from coinbase to local
scp -P 10022 'ivgreiff@coinbase.net.in.tum.de:/tmp/d1a_collect/*1238*' a4/runs/iv_pos_8/d1a/dbs/
```

2. **Verify they pass `validate_d1a_dbs.py`** alongside the original 8 (should now see 10/10 OK).
3. **Re-run** `python a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py` to refresh CSVs.
4. **Re-execute** the notebook: `jupyter nbconvert --to notebook --execute --inplace a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb`
5. **Re-render** `D1A_SUBSECTION.md`: since numbers come from `d1a_build_summary.json`, this should be near-mechanical. Update n_paired_seeds = 5, refresh the 6 headline numbers.

**Pass criterion for 5.4:**
- 10/10 DBs validate
- Refreshed CSVs reflect 5 paired triplets (not 4)
- Refreshed plots / notebook / subsection consistent

---

## Pass criteria summary (for self-check before reporting back)

| Check | Required state |
|---|---|
| 4 artifact files in `a4/runs/iv_pos_8/d1a/`: `d1a_metrics_table.csv`, `d1a_paired_tests.csv`, `d1a_floor_dynamics.csv`, `d1a_build_summary.json` | Present, non-empty |
| `IV_POS_8_D1A_NOTEBOOK.ipynb` executed end-to-end | Last cell has output, no `KeyError` / `OperationalError` in any cell |
| 5 plots in `a4/runs/iv_pos_8/d1a/plots/`: `01_theoretical_floor_curves.png` through `05_time_to_threshold.png` | All present, each > 5 KB |
| `D1A_SUBSECTION.md` populated from artifacts | All 6 headline numbers cited; all 5 plots embedded; verdict + findings sections present; no TODOs |
| Two analysis scripts in `a4/runs/iv_pos_8/d1a/analysis/`: `build_d1a_artifacts.py`, `build_d1a_notebook.py` | Both runnable from repo root; both produce their outputs deterministically |
| Re-runnability | Both scripts can be re-run after seed=1238 lands to refresh outputs with zero manual edits |
| No test failures in standalone suite | `pytest a4/standalone/tests/ -q` still green (sanity — Batch 5 should not touch standalone code) |

---

## Reporting format (when done)

When all tasks complete, write a structured report at `a4/docs/cloud2/composer/D1A_BATCH5_REPORT.md` containing:

```markdown
# D1.A Batch 5 — Composer Report

**Date:** YYYY-MM-DD HH:MM CEST
**Branch:** cloud2
**Commit:** <short hash at completion>

## 1. Pre-flight summary
- [x] All 0.x checks passed (or list which failed and how resolved)

## 2. Artifacts produced
- `a4/runs/iv_pos_8/d1a/d1a_metrics_table.csv` — N rows
- ... (full list with row counts / file sizes)

## 3. Headline numbers (the 6 from d1a_build_summary.json)
- Mean local_context_final V5: ...
- Mean local_context_final V5-decayexp: ...
- Mean local_context_final V5-decayepoch: ...
- Paired t-test p (V5 vs decayexp): ...
- Paired t-test p (V5 vs decayepoch): ...
- Floor mode share decayexp mut[200,6000): ...

## 4. Plot validation
- [x] 01_theoretical_floor_curves.png — looks as expected (3 curves visible)
- [x] 02_cumulative_coverage.png — 3 mean lines + std bands visible
- ... etc

## 5. Verdict line (1 sentence)
- "Decay variants show NO / WEAK / STRONG improvement over V5-static..."

## 6. Anything surprising or unresolved
- (anything you noticed that wasn't in the kickoff)

## 7. Test status post-Batch-5
- pytest a4/standalone/tests/ -q  →  N passed, M skipped (unchanged from pre-Batch-5)

## 8. Files staged but NOT committed
- (list all new files; do NOT git commit — Opus/Ivan will review and commit)
```

---

## OUT OF SCOPE for this batch (do NOT do these)

| Out of scope | Why |
|---|---|
| Dispatch additional POS jobs (seeds 1239-1243 × decay variants) | Spec scope locked at 5 paired triplets. Future work, not this batch. |
| Modify `discover.py` or any `a4/runs/iv_pos_7/analysis/` module | Stable, in use elsewhere. Treat as read-only API. |
| Touch the running seed=1238 fuzzers on flare/octorand | They're handling themselves. SSH at the 14:00 mark for collection. |
| Try to recover the hung POS dispatcher tmux session on coinbase | Orthogonal to Batch 5. Opus / Ivan will handle. |
| Write unit tests for `build_d1a_artifacts.py` / `build_d1a_notebook.py` | These are report-generation scripts, not production code. Sanity-eyeball the outputs instead. |
| Write `IV_POS_8_D1_REPORT_FOR_PRO.md` (the parent report) | That wraps D1.A + D1.B + D1.C; Opus drafts it after D1.B + D1.C are also done. |
| Write `IV_POS_8_D1_NOTEBOOK.ipynb` (the parent D1 notebook) | Same — wraps multiple subsections. Opus drafts after all subsections done. |
| Anything in D1.B, D1.C, D2.x | Different batches, different windows. |
| `git commit` or `git push` | Opus/Ivan review first. |

---

## Quick FAQ

**Q: What if `metrics.py::compute_internal_metrics_frame` doesn't accept our 3-variant set cleanly?**
A: Don't fight it. Call the lower-level building blocks (`_coverage_curve`, `_time_to_threshold`, `_read_first_hits`) directly in `build_d1a_artifacts.py`. The patterns are visible in `build_v6_pro_artifacts.py` and in `metrics.py` itself.

**Q: What if the V5-static R2 DBs have different schema (no `proof_generated` etc.)?**
A: Expected. Wrap every D1.A-new-column query in try/except `sqlite3.OperationalError`. Record `None` / `NaN` in the CSV for those rows. The validator (`validate_d1a_dbs.py`) only checks D1.A DBs; the R2 baseline is consumed by analysis without schema modification.

**Q: What if `scipy` isn't available?**
A: It is in this repo's venv (R2 V6 analysis uses it). Check `pyproject.toml` if unsure. If genuinely missing, fall back to `from numpy import mean, std` plus a hand-rolled paired-t (compute `d = a - b`, `t = mean(d) / (std(d) / sqrt(n))`, `p = 2 * scipy.stats.t.sf(abs(t), df=n-1)` — but really, install scipy first; it's a 5-second `pip install`).

**Q: What if the notebook can't find `matplotlib`?**
A: Same answer — it's in the venv. The V6 notebook imports it. Use `matplotlib.use('Agg')` BEFORE `import matplotlib.pyplot as plt` to avoid display issues in headless mode.

**Q: What if a paired test's `n_paired < 3`?**
A: Skip the test, record NaN, and add a `note` column explaining "n_paired too small". Don't crash.

---

**Greenlight:** assume Opus + Ivan have greenlit this kickoff. Begin Task 5.1 immediately. Report back per §"Reporting format" when all 4 tasks are done.

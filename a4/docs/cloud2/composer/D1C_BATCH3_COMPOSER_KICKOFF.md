# D1.C Batch 3 — Composer Kickoff

**Branch:** `cloud2`
**Spec:** [`IV_POS_8_D1_C_SPEC.md`](../IV_POS_8_D1_C_SPEC.md) v0.3 §2.3 (LOCKED)
**Parent plan:** [`IV_POS_8_D1_REVISIT_PLAN.md`](../IV_POS_8_D1_REVISIT_PLAN.md) v0.6 §3.2 + §3.2.1
**Predecessors:**
- D1.C Batch 1 ACCEPTED 2026-06-17 (16/16 pass criteria; 5 Tier-1 signal extractors + 30-DB audit; `f_new_flag` empirically near-dead; `recent_marginal_discovery_rate` momentum observable). See [`D1C_BATCH1_REPORT.md`](./D1C_BATCH1_REPORT.md).
- D1.C Batch 2 ACCEPTED 2026-06-17 (16/16 pass criteria; 8 Tier-2 functions + 30×11 metrics CSV + paired tests + D2.G schema lock). See [`D1C_BATCH2_REPORT.md`](./D1C_BATCH2_REPORT.md).
- **Critical Batch 2 finding for Batch 3:** `pro_s5_singleton_failure_rate` is the ONLY Tier-2 metric with statistically significant decay-vs-V5-static discrimination (p=2.6e-06 for decayexp, p=9.7e-05 for decayepoch). Decay variants find ~22% fewer singleton failures. This finding must be surfaced in `D1C_SUBSECTION.md` Pro narrative — see §6 below.
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~2 days (correlation matrix + shortlist + 4 net new artifacts including notebook)

---

## TL;DR for Composer

Implement the closing batch of D1.C as defined in spec v0.3 §2.3. This is the **cross-correlation analysis + Tier-1 shortlist composition + D1.E L1 hand-off + Pro-facing subsection + analysis notebook + 4 carry-forward fixes from Batch 2 review**. Still analysis-only — no production code edits.

**The single largest open question Batch 3 must answer:** Which of the 5 Tier-1 signals (or none, or some scalar-bandit subset) should D1.E wire into the L1 OR-channel set? The three-bucket shortlist composition in spec §2.3 task 3 is the formal answer.

**The 4 Batch 2 carry-forward fixes** (per Opus review) are mechanical and should be done first in Batch 3:
1. **`d_loc_p95` schema/dtype mismatch:** Schema says `int`, CSV shows float (5.0, 6.0, 7.0). Cast to `int(...)` in `pro_s5_d_loc_distribution` body (d_loc IS integer-valued).
2. **`d1c_unpaired_means.csv` naming/content mismatch:** Filename implies summary stats; content is per-seed values. Add a tiny companion `d1c_unpaired_summary.csv` with mean + std per metric (8 rows × 2 stat columns + metric name) — keeps per-seed file as-is for richer downstream use.
3. **Direct unit test for `pro_s5_verifier_accepted_invalid_count`:** 5-line test on a synthetic DB with one `verifier_accepted=1 AND num_failures>0` row. (Composer covered the other 7 metrics directly; this one only had integration coverage.)
4. **Non-parametric significance test for discrete-integer metrics** (`d_loc_p95`, `verifier_accepted_invalid_count`): Add `scipy.stats.wilcoxon` paired tests alongside the existing `ttest_rel` for the 2 metrics where Batch 2's t-test was "undefined; identical values." Emit results in a NEW `d1c_nonparametric_tests.csv` (small, ~6 rows: 2 metrics × 3 comparisons). DO NOT replace the t-test CSV — that's still valid for the other 6 metrics.

The empirical finding from Batch 2 (singleton_failure_rate p=2.6e-06 decay-vs-static) means D1.C has a **second** hand-off deliverable for D1.E beyond the Tier-1 shortlist: **a Pro/D1.E heads-up that the singleton metric is the only Tier-2 discriminator on this corpus.** Surface in `D1C_SUBSECTION.md` and `d1e_handoff_L1_signals.md` (the latter even though singleton_failure_rate is Tier-2, not Tier-1 — D1.E's L1 design may want to add a per-pull form of this signal, which is exactly `singleton_failure_flag` from Tier-1).

---

## Scope (exactly what Batch 3 ships)

| File | Action | Rough size |
|---|---|---|
| `a4/runs/iv_pos_7/analysis/bug_proximity.py` | Carry-forward (1): cast `d_loc_p95` to int. Carry-forward (4): expose `compute_correlation_matrix()` helper that takes per-mutation signal lists + channel lists, returns Pearson correlations | +30–50 LOC delta |
| `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` | Carry-forward (3): direct verifier_accepted_invalid_count unit test. New: correlation helper tests (perfect-correlation, anti-correlation, independence cases). | +50–80 LOC delta |
| `a4/runs/iv_pos_8/d1c/analysis/build_d1c_correlation_analysis.py` | **NEW.** Cross-correlation analysis script. For each of 30 DBs, extract Tier-1 signals (Batch 1) + existing channels (Option A: `discovery_binary_reward` + `f_new_flag`); compute Pearson ρ for the **9 non-trivial cells** (5 Tier-1 × 2 channels = 10 cells; minus `f_new_flag × f_new_flag` self-cell = 9 non-trivial). Emit `d1c_correlation_matrix.csv` (270 rows = 30 DBs × 9 cells). Plus **multi-threshold variant for `recent_marginal_discovery_rate`** per spec §1.3.2: also compute correlations at thresholds {25th, 50th, 75th percentile of post-local distribution}. Emit additional `d1c_recent_marginal_thresholds.csv` (30 DBs × 3 thresholds × 2 channels = 180 rows). | ~150–200 LOC |
| `a4/runs/iv_pos_8/d1c/analysis/build_d1c_nonparametric_tests.py` | **NEW.** Wilcoxon signed-rank tests for the 2 metrics where Batch 2's t-test was undefined (`d_loc_p95` and `verifier_accepted_invalid_count`). Output `d1c_nonparametric_tests.csv` (6 rows). | ~80 LOC |
| `a4/runs/iv_pos_8/d1c/analysis/build_d1c_artifacts.py` | Carry-forward (2): emit companion `d1c_unpaired_summary.csv` (8 rows × {metric, mean, std}) alongside the existing per-seed CSV | +30 LOC |
| `a4/runs/iv_pos_8/d1c/d1c_correlation_matrix.csv` | **NEW artifact.** 270 rows (30 DBs × 9 correlation cells) | data |
| `a4/runs/iv_pos_8/d1c/d1c_recent_marginal_thresholds.csv` | **NEW artifact.** 180 rows for multi-threshold analysis | data |
| `a4/runs/iv_pos_8/d1c/d1c_nonparametric_tests.csv` | **NEW artifact.** 6 rows | data |
| `a4/runs/iv_pos_8/d1c/d1c_unpaired_summary.csv` | **NEW artifact.** 8 rows × (metric, mean, std) | data |
| `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` | **NEW.** Three-bucket shortlist composition per spec §2.3 task 3 — RECOMMENDED (passes non-saturation + orthogonality), DEFERRED (ortho-failure), DEFERRED (scalar-bandit candidate). 1 page. | ~1 page |
| `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` | **NEW.** D1.E hand-off doc — load-bearing inputs for D1.E spec drafting. Lists the recommended Tier-1 signals + integration approach (OR vs sum-bandit) + the Batch 2 singleton_failure_rate decay finding + cross-references to `d1c_signal_shortlist.md` and `d1c_metrics_table.csv`. Per revisit plan §3.2.1 hand-off file index. | ~2–3 pages |
| `a4/runs/iv_pos_8/d1c/D1C_SUBSECTION.md` | **NEW.** Pro-facing subsection for `IV_POS_8_D1_REPORT_FOR_PRO.md` Stage 4 assembly. Mirrors D1.A/D1.B subsection structure. Must include the singleton_failure_rate finding (§7 below). | ~3–4 pages |
| `a4/runs/iv_pos_8/d1c/IV_POS_8_D1C_NOTEBOOK.ipynb` | **NEW.** Analysis notebook per revisit plan §3.2 exit criteria. Recreates Batch 1 plots + Batch 2 metric table + Batch 3 correlation matrix as embedded Jupyter cells. Build via a `build_d1c_notebook.py` helper if convenient. | ~10–15 cells |
| `a4/runs/iv_pos_8/d1c/IV_POS_8_D1C_NOTEBOOK.html` | **NEW.** Rendered HTML output (`jupyter nbconvert`) | derived |
| `a4/docs/cloud2/composer/D1C_BATCH3_REPORT.md` | **NEW.** Composer report | ~3–5 pages |

**Total expected delta:** ~400–600 LOC across 4 source files + 9 data/markdown/notebook artifacts. ~2 days at Batch 1/2 pace.

## NOT in Batch 3 (deferred to D1.E spec or beyond)

- **D1.E spec drafting** — D1.E is Ivan's next task after D1.C closes
- **Option C replay (full per-pull novelty reconstruction)** — only triggered IF Batch 3 cross-correlation finds all 4 non-trivial Tier-1 signals fail orthogonality AND Ivan/Opus decide replay is worth the engineering cost
- **Singleton-failure-rate per-pull bandit channel design** — D1.E's L1 design decision; D1.C only flags the empirical opportunity in the hand-off
- **D2.G `build_d2_artifacts.py`** — separate Composer kickoff (D2.G is a D2 workstream, schema-locked by D1.C Batch 2)
- **NFP-9 framing update** — Ivan will revise NFP framing when D1.E spec drafts
- **Pre-D1.E briefing update** — Ivan will extend the briefing after D1.C closes

If you find yourself touching any of the above, stop and confirm with Ivan before continuing.

---

## §2.3 task implementation notes

### Task 1: Cross-correlation matrix (`build_d1c_correlation_analysis.py`)

**Per DB:**
1. Load Tier-1 signals via `extract_tier1_signals_per_db()` (Batch 1) — 5 signal arrays of length 6000
2. Load existing channels via `extract_existing_channels_per_db()` (Batch 1) — 2 channel arrays of length 6000
3. Compute Pearson ρ for each (signal, channel) pair — 5 × 2 = 10 cells; **exclude the trivial `f_new_flag × f_new_flag` self-cell** → 9 non-trivial cells per DB
4. Restrict to the **post-local window `[3000, 6000)`** for fire-rate-relevant analysis (saturation-relevant correlation regime; the full-campaign correlation is dominated by early-discovery transient)
5. Emit one row per (db, signal, channel) triple

**CSV columns for `d1c_correlation_matrix.csv`:**
```
corpus, variant, seed, signal_name, channel_name, pearson_r, n_pulls
```

**Sanity invariants:**
- `pearson_r ∈ [-1, 1]` for every row
- Self-cell `f_new_flag × f_new_flag` row absent (or flagged with `pearson_r=1.0` and `note=self-cell`)
- `n_pulls = 3000` (post-local window) for every row

**For `recent_marginal_discovery_rate` (continuous):** Compute Pearson ρ at three thresholds (25th / 50th / 75th percentile of the post-local distribution). Emit to `d1c_recent_marginal_thresholds.csv`:
```
corpus, variant, seed, threshold_pct, threshold_value, channel_name, pearson_r
```

### Task 2: Tier-1 shortlist composition (`d1c_signal_shortlist.md`)

Per spec §2.3 task 3 + revisit plan §3.2 — **three explicit buckets:**

- **RECOMMENDED** (passes both gates): Signal S survives if (a) `fire_rate_post_local(S) > 0.05` (Batch 1) AND (b) `max(|pearson_r|) < 0.4` across both channels (Batch 3 correlation matrix; `CORRELATION_THRESHOLD` constant in `bug_proximity.py`).
- **DEFERRED (ortho-failure)**: Signal S passes the non-saturation gate but fails orthogonality (`max(|pearson_r|) ≥ 0.4`). Reason: would be redundant with an existing channel. Keep for future revisits if the existing channel set changes.
- **DEFERRED (scalar-bandit candidate)**: Signal S that is continuous-valued (currently only `recent_marginal_discovery_rate`) and fails orthogonality. Reason: even if redundant for binary OR, useful as a magnitude signal in a future scalar/multi-armed bandit (NFP-9).

**Markdown structure for `d1c_signal_shortlist.md`:**

```markdown
# D1.C Tier-1 Signal Shortlist

**Source:** D1.C Batch 1 (fire-rate audit) + Batch 3 (cross-correlation analysis)
**Corpus:** 30 Cat-A DBs
**Selection criteria:**
- Non-saturation: fire_rate_post_local > 5%
- Orthogonality: max |Pearson ρ| against {discovery_binary_reward, f_new_flag} < 0.4

## Bucket A: RECOMMENDED for D1.E L1 OR-channel

(list of signals + their fire rates + max correlation values)

## Bucket B: DEFERRED — ortho-failure

(list of signals + their fire rates + which channel they correlate with + ρ value)

## Bucket C: DEFERRED — scalar-bandit candidate (NFP-9 future)

(list of continuous signals that failed orthogonality + their utility for future scalar bandit)

## Empirical predictions (for D1.E author)

Based on Batch 1 fire-rate audit, expected bucket assignments (must be confirmed by Batch 3 correlation):
- `f_new_flag` → Bucket B (fire_rate_post_local ~0%, fails non-saturation)
- `recent_marginal_discovery_rate` → likely Bucket C (continuous; correlation with discovery_binary_reward expected ρ > 0.4 by construction per spec §1.3.3)
- `singleton_failure_flag` / `mutation_substrategy_uniqueness` / `d_loc_le_2_flag` → undetermined; depend on Batch 3 correlation values
```

### Task 3: D1.E L1 hand-off (`d1e_handoff_L1_signals.md`)

Per revisit plan §3.2.1 hand-off file index — load-bearing inputs for D1.E spec drafting.

**Markdown structure:**

```markdown
# D1.E L1 Signal Hand-off

**Source:** D1.C complete (Batches 1+2+3)
**Audience:** D1.E spec author
**Purpose:** Enumerate the L1 OR-channel candidates for the D1.E reward rewire

## §1 Recommended L1 OR-channel additions

(from `d1c_signal_shortlist.md` Bucket A)

## §2 Per-pull integration approach

For each recommended signal S:
- (a) **OR-into-bandit-success:** `bandit_success_new = bandit_success_old OR S_flag`
- (b) **AND-into-bandit-success:** rarely useful unless we want to *filter* discoveries
- (c) **Separate scalar bandit channel:** for NFP-9 / Bucket C signals

Default recommendation: (a) for binary Tier-1 signals; (c) for Bucket C.

## §3 Empirical disclosures for D1.E

- **f_new_flag is empirically dead** on V5 corpus (0.17% full / ~0% post-local); kept available for non-V5 catalogs only (NFP-9 framing update)
- **Saturation inversion (D1.B):** coarsened CGC variants saturate EARLIER than local saturation; production_log2_corrected remains the L0 baseline
- **Singleton-failure-rate decay-vs-static discrimination (D1.C Batch 2):** decay variants find ~22% fewer singleton failures (p=2.6e-06 decayexp vs V5-static; p=9.7e-05 decayepoch vs V5-static). **Implication for D1.E:** consider per-pull `singleton_failure_flag` (already in Tier-1 set) as a candidate L1 OR-channel if it survives Batch 3 orthogonality

## §4 Cross-references

- D1.B L1 OR-channel framing: `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` §4
- D1.B saturation inversion: `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md`
- D1.C shortlist: `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md`
- D1.C Tier-2 schema (D2.G): `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md`
- D1.C metrics table: `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv`
```

### Task 4: Pro subsection (`D1C_SUBSECTION.md`)

Mirror D1.A subsection structure. Pro-facing prose (not Composer-facing tables). Sections:
1. Goal of D1.C (Pro-intent bug-proximity signals for D1.E)
2. Two-tier architecture (Tier-1 per-pull + Tier-2 per-campaign)
3. Tier-1 fire-rate audit (Batch 1) — descriptive
4. Tier-2 metrics on 30-DB corpus (Batch 2) — including the singleton_failure_rate finding
5. Cross-correlation + shortlist (Batch 3)
6. Hand-off to D1.E + D2.G
7. Open questions for Pro / D1.E

### Task 5: Notebook (`IV_POS_8_D1C_NOTEBOOK.ipynb` + `.html`)

Per revisit plan §3.2 exit criteria — "Notebook + HTML rendered." Recreates:
- Batch 1 fire-rate histograms (embed PNG or regenerate inline)
- Batch 2 metrics table (read CSV, render with pandas)
- Batch 3 correlation matrix heatmap (matplotlib `imshow`)
- Batch 3 shortlist (markdown cell)

Render to HTML via `jupyter nbconvert --to html IV_POS_8_D1C_NOTEBOOK.ipynb`.

---

## Workflow

1. **Read these first:**
   - Spec §2.3 (your scope)
   - Spec §1.3.3 + §1.3.4 (selection criteria — these are the formal definitions for shortlist composition)
   - `D1C_BATCH1_REPORT.md` §7 (empirical fire rates — predict bucket assignments before running correlation)
   - `D1C_BATCH2_REPORT.md` §7 + §9 (singleton finding + deviations)
   - The Opus Batch 2 review (in this kickoff above + the chat transcript)
2. **Implementation order (recommended):**
   1. **Carry-forward fix 1** (d_loc_p95 int cast) — smallest change; trivial
   2. **Carry-forward fix 3** (verifier_accepted_invalid_count unit test) — quick win
   3. **Carry-forward fix 2** (unpaired summary CSV) — emit alongside existing CSV
   4. **Carry-forward fix 4** (Wilcoxon non-parametric script) — new small script + new CSV
   5. **Re-run `build_d1c_artifacts.py`** to regenerate CSVs with the int-cast applied
   6. **Build correlation analysis** (the load-bearing piece — 270-row correlation CSV + 180-row threshold CSV)
   7. **Compose shortlist** (`d1c_signal_shortlist.md`) — three explicit buckets
   8. **Write D1.E hand-off** (`d1e_handoff_L1_signals.md`) — load-bearing for D1.E author
   9. **Write Pro subsection** (`D1C_SUBSECTION.md`) — Pro-facing prose
   10. **Build notebook + render HTML**
   11. **Write Batch 3 report** (`D1C_BATCH3_REPORT.md`)
3. **Self-checkpoint before submitting:**
   - `pytest a4/runs/iv_pos_7/analysis/test_bug_proximity.py -q` — must show ≥40 tests (Batch 2's 33 + ≥7 new for correlation helper + verifier test + any new tests)
   - `pytest a4/standalone/tests/ -q` — must stay green at 515 standalone (zero standalone changes)
   - `git diff cloud2 -- a4/standalone/` empty
   - Open `d1c_correlation_matrix.csv` in pandas, verify `df.shape == (270, 7)`, all `pearson_r ∈ [-1, 1]`, no NaN
   - Open `d1c_signal_shortlist.md` and verify all 5 Tier-1 signals are assigned to exactly one bucket (no signal in two buckets, no signal in zero buckets)
4. **Open ONE PR** for Batch 3 against `cloud2`, branch `cloud2-d1c-batch3-correlation-shortlist`.
5. **Write Batch 3 report** with the same structure as Batch 1/2 reports.

---

## Pass criteria (Batch 3 ships)

- [ ] **Carry-forward 1:** `d_loc_p95` cast to int in `pro_s5_d_loc_distribution`; CSV regenerated; schema doc consistent
- [ ] **Carry-forward 2:** `d1c_unpaired_summary.csv` exists alongside per-seed CSV (8 rows × {metric, mean, std})
- [ ] **Carry-forward 3:** Direct unit test for `pro_s5_verifier_accepted_invalid_count` on synthetic DB
- [ ] **Carry-forward 4:** `build_d1c_nonparametric_tests.py` + `d1c_nonparametric_tests.csv` (6 rows: 2 metrics × 3 comparisons, Wilcoxon signed-rank)
- [ ] `build_d1c_correlation_analysis.py` exists + emits `d1c_correlation_matrix.csv` (270 rows: 30 DBs × 9 non-trivial cells); all `pearson_r ∈ [-1, 1]`; no NaN
- [ ] `d1c_recent_marginal_thresholds.csv` exists (180 rows: 30 DBs × 3 thresholds × 2 channels) for `recent_marginal_discovery_rate` multi-threshold analysis per spec §1.3.2
- [ ] `compute_correlation_matrix()` helper added to `bug_proximity.py` with ≥3 unit tests (perfect-correlation / anti-correlation / independence cases)
- [ ] `d1c_signal_shortlist.md` exists with **three explicit buckets** (RECOMMENDED, DEFERRED ortho-failure, DEFERRED scalar-bandit candidate); every Tier-1 signal in exactly one bucket
- [ ] `d1e_handoff_L1_signals.md` exists with: §1 recommended signals, §2 integration approach, §3 empirical disclosures (must include the singleton_failure_rate Batch 2 finding), §4 cross-references
- [ ] `D1C_SUBSECTION.md` exists in Pro-facing tone with §4 explicitly covering the singleton_failure_rate decay-vs-static finding
- [ ] `IV_POS_8_D1C_NOTEBOOK.ipynb` exists with cells for Batch 1 plots + Batch 2 table + Batch 3 correlation heatmap
- [ ] `IV_POS_8_D1C_NOTEBOOK.html` exists (rendered from notebook)
- [ ] Test count ≥40 (33 Batch 2 + ≥7 new); all green
- [ ] Full standalone pytest sweep still green (`a4/standalone/tests/` — 515 passed, no regressions)
- [ ] `git diff cloud2 -- a4/standalone/` shows ZERO changes
- [ ] `D1C_BATCH3_REPORT.md` written per workflow step 5

---

## Where to look for help

| Question | Where to look |
|---|---|
| What's the spec's orthogonality criterion? | Spec §1.3.3: `CORRELATION_THRESHOLD = 0.4`; signals with `max(|ρ|) ≥ 0.4` against {`discovery_binary_reward`, `f_new_flag`} fail orthogonality |
| What's the non-saturation criterion? | Spec §1.3.4: `fire_rate(S, [3000, 6000)) > NON_SATURATION_MIN_FIRE_RATE = 0.05` (already in `bug_proximity.py`) |
| Which window should correlation be computed over? | Per spec §1.3.3: post-local window `[3000, 6000)` — same as fire-rate audit, for consistency |
| How to compute Pearson ρ on binary signals? | `scipy.stats.pearsonr(x, y)` or `numpy.corrcoef(x, y)[0, 1]` — both work; both return NaN when one array has zero variance (handle by setting ρ=0 with a `note=zero_variance` flag) |
| What's the expected behavior of `recent_marginal_discovery_rate` correlation? | Per spec v0.3 §1.2 docstring: high ρ with `discovery_binary_reward` BY CONSTRUCTION (rolling mean of the channel itself). Should land in Bucket C |
| Where's `cat_a_db_list()`? | `a4/runs/iv_pos_8/d1b/analysis/build_batch1_audit.py:67` (D1.B's, NOT renamed) |
| How does D1.B's subsection structure look? | `a4/runs/iv_pos_8/d1b/D1B_SUBSECTION.md` — mirror that structure |
| How does the D1.B notebook look? | `a4/runs/iv_pos_8/d1b/IV_POS_8_D1B_NOTEBOOK.ipynb` — mirror its cell layout |

---

## Hand-off statement (paste this when delegating to Composer)

> Implement D1.C Batch 3 per the locked spec at `a4/docs/cloud2/IV_POS_8_D1_C_SPEC.md` v0.3 §2.3. Follow the workflow in `a4/docs/cloud2/composer/D1C_BATCH3_COMPOSER_KICKOFF.md`. Open one PR against `cloud2` named `cloud2-d1c-batch3-correlation-shortlist`. **D1.C is still analysis-only — touch nothing under `a4/standalone/`.** Start with the 4 carry-forward fixes from Batch 2 review (d_loc_p95 int cast, unpaired summary CSV, verifier unit test, Wilcoxon non-parametric script); then build the correlation matrix, shortlist, D1.E hand-off, Pro subsection, and notebook. **The singleton_failure_rate Batch 2 finding (p=2.6e-06 decay-vs-static) is load-bearing for the D1.E hand-off and Pro subsection — surface it explicitly in §3 of `d1e_handoff_L1_signals.md` and §4 of `D1C_SUBSECTION.md`.** Pass criteria are the 14 checkboxes in the kickoff doc. Submit your work as a single PR plus a written report at `a4/docs/cloud2/composer/D1C_BATCH3_REPORT.md`. After Batch 3 closes, Ivan will squash all three D1.C batches into a single commit.

---

*End of D1.C Batch 3 kickoff.*

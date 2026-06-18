# D1.A Batch 5 — Composer Report

**Date:** 2026-06-17 (interim — seed 1238 pending Task 5.4 refresh)  
**Branch:** cloud2  
**Commit:** `4fce66499463` (at artifact build)  
**Final status:** Task 5.4 complete — see §11. **D1.A CLOSED.**

---

## 0. Pushback / alignment notes (for Opus)

| Topic | Composer view |
|---|---|
| **Proceed with n=4 paired triplets** | Agree. Kickoff explicitly allows Tasks 5.1–5.3 now; 5.4 refreshes when 1238 lands. Aligns with preliminary plan scope lock (no 1239–1243 decay dispatch). |
| **Finding A + B in subsection** | Agree — both elevated in `D1A_SUBSECTION.md` §Findings with empirical numbers matching Opus's inspection (48% flat decayexp; 96→48→48% decayepoch staircase). |
| **Verdict recommends scheduler for D2** | Agree with kickoff instruction. Verdict: **V5-static default**; decay optional with K≫50 or epoch-staged if pursued. |
| **No HALT between 5.1 and 5.2** | Proceeded through 5.3 in one pass per greenlight. CSVs available for review at `a4/runs/iv_pos_8/d1a/*.csv`. |
| **Minor metric note** | `floor_mode_share_post_cs` for decayepoch is ~63% overall post-200 (bucket blend); staircase evidence uses per-bucket shares in summary JSON (96%/48%/48%) — matches Opus Finding A framing. |

No blocking disagreements with kickoff or `IV_POS_8_PRELIMINARY_PLAN.md` D1.A deliverable list.

---

## 1. Pre-flight summary

- [x] **0.1** Branch `cloud2`
- [x] **0.2** `validate_d1a_dbs.py` — **8/8 OK**
- [x] **0.3** R2 V5 DBs present under `a4/runs/iv_pos_7/dbs/`
- [x] **0.4** Discover counts: `{'V5': 10, 'V5-decayexp': 4, 'V5-decayepoch': 4}` (1238 not yet collected)
- [x] **0.5** `from analysis.metrics import ...` imports cleanly

---

## 2. Artifacts produced

| File | Rows / size |
|---|---|
| `a4/runs/iv_pos_8/d1a/d1a_metrics_table.csv` | **18 rows** (10 V5 + 4 decayexp + 4 decayepoch), 5384 B |
| `a4/runs/iv_pos_8/d1a/d1a_paired_tests.csv` | **15 rows** (5 metrics × 3 comparisons), 1624 B |
| `a4/runs/iv_pos_8/d1a/d1a_floor_dynamics.csv` | **202 rows**, 7363 B |
| `a4/runs/iv_pos_8/d1a/d1a_build_summary.json` | summary keys + git commit |
| `a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py` | new |
| `a4/runs/iv_pos_8/d1a/analysis/build_d1a_notebook.py` | new |
| `a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb` | executed (~609 KB) |
| `a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.html` | rendered HTML (~949 KB) |
| `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` | ~95 lines |
| `a4/runs/iv_pos_8/d1a/plots/01–05_*.png` | 5 files, all > 5 KB |

---

## 3. Headline numbers (interim n=4 paired triplets)

| Metric | Value |
|---|---|
| Mean `local_context_final` V5 | **46.40** |
| Mean `local_context_final` V5-decayexp | **46.00** |
| Mean `local_context_final` V5-decayepoch | **46.50** |
| Paired t-test p (V5 vs decayexp) | **0.391** |
| Paired t-test p (V5 vs decayepoch) | **1.000** |
| Floor mode share decayexp mut[200,6000) | **48.0%** |

**Epoch staircase (decayepoch, aggregated):** bucket1 [200,2000)=**96%**, bucket2 [2000,4000)=**48%**, bucket3 [4000,6000)=**48%**.

---

## 4. Plot validation

- [x] `01_theoretical_floor_curves.png` — 56 KB; exponential + epoch curves + constant reference
- [x] `02_cumulative_coverage.png` — 65 KB; 3 mean lines + std bands
- [x] `03_local_context_final.png` — 30 KB; 3 bars + p-value annotations
- [x] `04_mode_share_over_time.png` — 45 KB; **decayexp flat ~48% floor post-200; decayepoch staircase visible**
- [x] `05_time_to_threshold.png` — strip plots with per-seed points (FU-6)

---

## 5. Verdict line (1 sentence)

**Decay variants show no statistically significant improvement in local context discovery at n=4 paired triplets; schedules are mechanically correct but K=50 exponential decay saturates immediately — V5-static remains the recommended V5 default for D2.**

---

## 6. Surprises / unresolved

1. **V5-static R2 rows show 96% floor-mode post-200** — expected for ConstantFloor(0.55) with 48 arms; useful comparator for decayexp's 48%.
2. **Seed 1238 DBs not yet local** — Task **5.4 pending** (~14:00 CEST ETA per Opus); will re-run artifacts + notebook + subsection refresh when available.
3. **No standalone code touched** — full pytest not re-run this batch (analysis-only scope).

---

## 7. Test status post-Batch-5

- Standalone suite: **not re-run** (no `a4/standalone/` changes in Batch 5)
- D1.A + discover targeted tests from prior batches: **50/50 pass** (unchanged)

---

## 8. Files staged but NOT committed

```
a4/runs/iv_pos_8/d1a/analysis/__init__.py
a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py
a4/runs/iv_pos_8/d1a/analysis/build_d1a_notebook.py
a4/runs/iv_pos_8/d1a/d1a_metrics_table.csv
a4/runs/iv_pos_8/d1a/d1a_paired_tests.csv
a4/runs/iv_pos_8/d1a/d1a_floor_dynamics.csv
a4/runs/iv_pos_8/d1a/d1a_build_summary.json
a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md
a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb
a4/runs/iv_pos_8/d1a/plots/*.png
a4/docs/cloud2/composer/D1A_BATCH5_REPORT.md
```

---

## 9. Task 5.4 — pending

When seed **1238** decayexp + decayepoch DBs land:

1. SCP to `a4/runs/iv_pos_8/d1a/dbs/` (kickoff commands)
2. `validate_d1a_dbs.py` → expect **10/10 OK**
3. Re-run `build_d1a_artifacts.py`, notebook execute, refresh `D1A_SUBSECTION.md` headline numbers (n=5 paired triplets)

---

## 10. Follow-up addendum (Opus review → FU-1–FU-6)

**Date:** 2026-06-17 (same session, post-Opus Finding C review)

| Task | Status | Notes |
|---|---|---|
| **FU-1** Finding C in `D1A_SUBSECTION.md` | **Done** | sha1 prefixes re-verified from local DBs (`9242c3c4…`, `b2bdd9f2…`, `80aa0a00…`); mut divergence at **2049**; p=1.0 framed as power + small-n cancellation |
| **FU-2** Verdict rewrite | **Done** | Power-limitation framing; D2 recommendations unchanged in substance |
| **FU-3** Limitation 5 | **Done** | Design-power limitation on decayepoch vs V5-static |
| **FU-4** Zero-variance t-test fix | **Done** | `build_d1a_artifacts.py` + `na_rep="nan"` on CSV export; line 12 verified |
| **FU-5** AUC_DENOM comment | **Done** | Comment only |
| **FU-6** Plot 5 strip plots | **Done** | Notebook regenerated and re-executed |

**Composer pushback on Opus (documented for Pro):**

- Opus's mode-sequence hashes in `D1A_BATCH5_FOLLOWUP.md` were **wrong** — neither Opus nor our interim "corrected" values matched; fresh hash of local DBs at `a4/runs/iv_pos_8/d1a/dbs/` gives the values now in the subsection.
- **Finding C core claim is correct** (deterministic mode within variant; decayepoch ≡ V5-static before boundary).
- **p=1.0 is not *only* zero power** — per-seed `local_context_final` differs (+1,+1,0,−2); paired mean cancels at n=4. Subsection keeps both framings.
- **48% pool-depletion cap** — agree on structural mechanism; Opus's "not floor_fraction=0.20" refinement is fair but does not change the K=50 recommendation.

**Artifact delta from FU-4:** only `d1a_paired_tests.csv` changed (sha256 `e46ca5bae6…`); headline numbers and `d1a_build_summary.json` unchanged.

**Next:** ~~Task 5.4 when seed 1238 DBs land~~ → **completed** (see §11).

---

## 11. Task 5.4 — Final refresh (n=5 paired triplets)

**Date:** 2026-06-17 (refresh completed after seed 1238 collection)  
**Commit:** `4fce66499463`

### DBs collected
- `flare_pos_iv_pos_8_d1a_b1c_cTS_semantic_v2_decayexp_seed1238_n6000.db` (cov=47)
- `octorand_pos_iv_pos_8_d1a_b1c_cTS_semantic_v2_decayepoch_seed1238_n6000.db` (cov=46)
- Both pass `validate_d1a_dbs.py` (**10/10 OK**)

### Refreshed headline numbers (match preview ± rounding)
| Metric | Value |
|---|---|
| Mean `local_context_final` V5 | **46.40** (unchanged) |
| Mean `local_context_final` V5-decayexp | **46.20** (was 46.00) |
| Mean `local_context_final` V5-decayepoch | **46.40** (was 46.50) |
| Paired p (V5 vs decayexp) | **0.704** (was 0.391) |
| Paired p (V5 vs decayepoch) | **1.000** (unchanged; mean diff still 0.0) |
| Paired p (decayexp vs decayepoch) | **0.621** (was 0.182) |
| Floor share decayexp post-200 | **0.48** (unchanged) |

### Artifacts refreshed
| File | Rows / size |
|---|---|
| `d1a_metrics_table.csv` | **20 rows** (was 18) |
| `d1a_floor_dynamics.csv` | **225 rows** (was 202) |
| `IV_POS_8_D1A_NOTEBOOK.html` | ~951 KB, plots regenerated 10:44 |

### Follow-up edits applied
- **FU-7** (hash reproducibility command in Finding C): done — canonical hashes via `|`-join snippet: V5 `2d14a156aca51190`, decayexp `c07da3955a8f0347`, decayepoch `32a3abd14125281a` (all seeds per variant collide)
- **FU-8** (Finding C consequence #3 softened with n=5 framing): done

### Hash discrepancy resolved
Earlier hash sets disagreed because of **separator convention** (`''.join` vs `'|'.join`). Kickoff snippet uses pipe-join; subsection now documents that command. Collision property is convention-independent.

### Verdict (final)
Unchanged direction: **V5-static remains D2 default.** No significant coverage advantage from either decay variant at n=5. Decay variants need redesigned experiments (K≥500 for decayexp; earlier epoch boundaries for decayepoch) to be properly evaluated.

### D1.A status: **CLOSED.** Ready for parent-report assembly.

---

## 12. Frozen-state audit (Opus, 2026-06-17 ~12:00 EDT)

After the user (Ivan) raised a concern that the D1.A narrative as written risked **prematurely biasing Pro to drop the decay variants entirely**, Opus ran a code-and-data audit and revised `D1A_SUBSECTION.md` in place. **No CSVs/plots/notebook re-run. All numbers unchanged.** Only the markdown framing and three new findings were added.

### Changes applied to `D1A_SUBSECTION.md`

| Change | Why |
|---|---|
| **FROZEN banner at top** | Flag this as an interim result; the final Pro-facing deliverable will fold in the D1.B/D1.C re-run |
| **TL;DR rewritten** | Headline now states what is/isn't ruled out, not just "no significant change"; mentions Findings D/E/F up front |
| **Finding A's K=500 recommendation REPLACED with K ≈ 200–300** | K=500 is mechanically wrong: at K=500 the 96→48 mode-transition fires at d=68, never during our run (max d=46); decayexp would behave identically to V5-static. Correct range to land the transition in the saturation tail is K ≈ 200–300 (computed table now in subsection) |
| **New Finding D — Scheduler mode space is discrete (3 regimes)** | Direct read of `bandit_ts.py:180-187` + `:237` proves the integer-quota check produces only ~0/48/96/100% floor regimes. Pro's `[0.55, 0.35, 0.20]` collapses to a 2-tier policy (third tier is a no-op). Pro's intended "gradual decay" is not testable on this scheduler without geometry change. Composer's mechanism diagnosis was correct; this finding promotes it from a B2 sidebar to a top-level architectural caveat for Pro |
| **New Finding E — Post-boundary discovery is empirically tied 10 vs 10** | Bucketed `coverage.first_hit_mutation_id` directly: V5-static and V5-decayepoch each first-discovered 10 contexts in mut[2000, 6000) across 5 seeds. This is the direct empirical answer to Ivan's question "did adaptive find more in the post-boundary phase?" — no. **Strengthens** the narrow negative on "V5's 96% floor share is starving productive TS exploitation" |
| **New Finding F — Only half of Pro §7 Stage 2 tested** | Pro §7 (`ProG_Report_3.md:175-196`) proposes decay + 4 enriched reward signals (recent marginal discovery / low-cofailure / repairability / underexplored zones). We implemented decay; we did NOT enrich TS reward (still d_loc-only). With d_loc saturating at ~46, adaptive mode loses arm-differentiation signal exactly when it gets more decisions. **This is the single most important caveat for Pro** — the measured negative may be primarily a reward-signal-saturation result, not a schedule result |
| **Verdict rewritten** | Split into "what this rules out" (high confidence) / "what this does NOT rule out" / "frozen-state D2 recommendation" (explicitly tells D2 designers to KEEP decay variants in scope, not drop them) |
| **Limitations 6/7/8 added** | (6) scheduler geometry limits testability; (7) single-signal d_loc reward is the dominant caveat for Pro; (8) Hybrid V7 catalog not exercised |
| **Revision history entry added** | Audit trail |

### Composer's earlier responses that were left intact

- All headline numbers, CSVs, plots, notebook, HTML — unchanged
- Findings A core text (K=50 mechanism), B (extra_json NULL), C (mode determinism) — unchanged
- Provenance table (hashes, commit, build date) — unchanged
- Composer's pushback on Opus's earlier hash-discrepancy claim (correct, kept in §10)

### Composer's earlier framing that was REVISED

- **Original**: "Recommendation: keep V5-static as the V5 default for D2; treat decay variants as optional exploration with a much larger K if gradual exponential decay is desired."
- **Revised**: "Tentative recommendation pending the D1.B/D1.C-enriched re-run: keep V5-static as the V5-only default; do NOT drop decay variants from D2's scope."

The difference matters because the original framing reads as "decay didn't help, move on"; the revised framing reads as "decay didn't help *with the test we ran*, which deliberately excluded the reward-signal half of Pro's proposal."

### What still needs to happen before the final Pro-facing D1 report

1. D1.B spec + implementation (coarsened-CGC reward signals)
2. D1.C spec + implementation (bug-proximity reward signals)
3. Rewire `ConstrainedTSScheduler` reward path to optionally consume the new signals
4. (Optional) Scheduler geometry fix: per-mutation Bernoulli sampling instead of per-epoch integer quotas
5. Re-run V5-static / V5-decayexp (K≈200) / V5-decayepoch (boundary at mut≈1000) with at least one richer reward signal active
6. Refresh subsection with the new comparison; final Pro report assembled

### D1.A frozen-state status: **CLOSED FOR NOW** — will be revisited as "D1.A-bis" after D1.B/D1.C land.

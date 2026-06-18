# D1.B Batch 2 — Composer Report

**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.4.3 §3.3  
**Scope:** Full 20-DB decay corpus analysis on 4 corrected CGC coarsening variants  
**Prerequisites:** Batch 1.5 ✅, **Batch 1.5b ✅** (`user_dynamic` label — landed before Batch 2 build), Batch 1.6 ✅ (byte_addr replay)  
**Branch:** `cloud2` (uncommitted — Ivan squash commit at D1.B completion)  
**Date:** 2026-06-17

---

## 1. Verdict

**Batch 2 complete.** All §3.3 exit criteria met:

| Criterion | Status |
|---|---|
| `d1b_metrics_table.csv` (80 rows) | ✅ |
| `d1b_paired_tests.csv` (72 rows) | ✅ |
| `d1b_saturation_profile.csv` (4 rows) | ✅ |
| `d1b_build_summary.json` + `d1b_artifacts.sha256` | ✅ |
| `IV_POS_8_D1B_NOTEBOOK.ipynb` executed → HTML | ✅ |
| Sanity invariants (corrected labeling) | ✅ **PASS** (0 violations) |

---

## 2. Corpus

| Source | Variant label | Seeds | N |
|---|---|---|---|
| R2 `iv_pos_7/dbs` | `V5` | 1234–1243 | 10 |
| D1.A `d1a/dbs` | `V5-decayexp` | 1234–1238 | 5 |
| D1.A `d1a/dbs` | `V5-decayepoch` | 1234–1238 | 5 |

**Paired triplet seeds:** 1234, 1235, 1236, 1237, 1238 (n=5).

**Methodology (Batch 1.6 prerequisite):** Memory keys for all four variants derive from `replay_memory_first_hits()` (patched extractor replay over `hook3_raw`). Lookup keys from `replay_lookup_first_hits()` (`hook3_raw.compressed_ctx_json`). Stored `compressed_global_coverage` is **not** used.

---

## 3. Headline numbers (mean `cgc_final`, hybrid total)

| CGC variant | V5 (n=10) | decayexp (n=5) | decayepoch (n=5) |
|---|---:|---:|---:|
| `production_log2_corrected` | **218.2** | 215.6 | 218.0 |
| `region_only` | **105.7** | 99.2 | 100.8 |
| `log4_explicit` | **120.6** | 114.2 | 115.8 |
| `page_class` | **110.7** | 104.2 | 105.8 |

**Memory-channel only (V5 mean `memory_final`):**

| Variant | Mean | Range (10 seeds) |
|---|---:|---|
| `production_log2_corrected` | 122.0 | 116–128 |
| `region_only` | **9.5** | 9–10 |
| `log4_explicit` | **24.4** | 24–25 |
| `page_class` | **14.5** | 14–15 |

**Lookup pass-through:** `lookup_final` identical across all 4 variants on every DB (definitional invariant ✅).

---

## 4. Sanity invariants

All computed on **corrected** memory labeling:

1. **Memory ordering:** `region_only ≤ log4_explicit ≤ production_log2_corrected` — **20/20 DBs PASS**
2. **Hybrid ordering:** same on `cgc_final` — **20/20 PASS**
3. **`region_only_memory ≈ 9`:** observed **9–10** on all DBs (no escalation)
4. **`page_class_memory ≈ 13–15`:** observed **14–15** on all DBs (no escalation)
5. **`lookup_keys` identical** across variants — **20/20 PASS**

Coarsening ordering now holds on corrected labeling (contrast Batch 1 pre-fix double-masked collapse).

---

## 5. Saturation profile (V5 paired seeds, 100-step bins)

First bin where mean new keys &lt; 1 across seeds 1234–1238:

| Variant | `saturation_mutation_id` | `saturation_cgc_d` (mean cum. at sat.) | `saturation_bin_avg_new_keys` |
|---|---:|---:|---:|
| `production_log2_corrected` | **3400** | 180 | 0.8 |
| `region_only` | **1300** | 62 | 0.8 |
| `log4_explicit` | **1800** | 84 | 0.6 |
| `page_class` | **1300** | 67 | 0.8 |

**Reading:** Coarsened variants enter asymptotic CGC discovery ~2–2.6× earlier than corrected production log2. `page_class` saturates at the same mutation window as `region_only` but with ~5 more distinct keys at saturation (67 vs 62 cumulative). Production log2 continues adding keys through mutation ~3400.

---

## 6. Paired tests (paired seeds)

### `cgc_final` — no significant decay effect

No statistically significant difference in final CGC count between V5-static and decay variants under any coarsening (all p &gt; 0.05).

**Denominator clarification (Finding C):** Headline V5 mean `cgc_final` = **218.2** averages all **10** V5 DBs. Paired-tests CSV uses **5** paired seeds → V5 mean **216.2**. Both correct.

### `auc_normalized` — decayexp shows significant advantage under coarsened variants

| CGC variant | Δ AUC (decayexp − V5) | p-value |
|---|---:|---:|
| `page_class` | +0.0253 | **0.0481** |
| `region_only` | +0.0259 | **0.0484** |
| `production_log2_corrected` | +0.0228 | 0.0588 (marginal) |
| `log4_explicit` | +0.0234 | 0.0591 (marginal) |

**decayepoch:** all four variants p &gt; 0.19 — no comparable AUC pattern.

**Reading:** Modest +2.5% effect; consistent direction across all variants; significance only on coarsest two. n=5 caveat — flag for D1.E forward-run, not conclusive. This signal was invisible in D1.A's `local_context_final`-only analysis.

---

## 7. Files created / modified

| Path | Purpose |
|---|---|
| `a4/runs/iv_pos_8/d1b/analysis/build_d1b_artifacts.py` | Main Batch 2 builder |
| `a4/runs/iv_pos_8/d1b/analysis/d1b_cgc_maps.py` | Per-variant first-hit map construction |
| `a4/runs/iv_pos_8/d1b/analysis/build_d1b_notebook.py` | Notebook generator |
| `a4/runs/iv_pos_8/d1b/analysis/replay_cgc_corrected.py` | Added public replay exports for Batch 2 |
| `a4/runs/iv_pos_8/d1b/d1b_metrics_table.csv` | 80-row metrics |
| `a4/runs/iv_pos_8/d1b/d1b_paired_tests.csv` | 72-row paired t-tests |
| `a4/runs/iv_pos_8/d1b/d1b_saturation_profile.csv` | 4-row saturation |
| `a4/runs/iv_pos_8/d1b/d1b_build_summary.json` | Build metadata + headlines |
| `a4/runs/iv_pos_8/d1b/d1b_artifacts.sha256` | CSV/JSON checksums |
| `a4/runs/iv_pos_8/d1b/IV_POS_8_D1B_NOTEBOOK.ipynb` | Analysis notebook |
| `a4/runs/iv_pos_8/d1b/IV_POS_8_D1B_NOTEBOOK.html` | Executed export |
| `a4/runs/iv_pos_8/d1b/plots/cgc_curve_*.png` | 4 cumulative curve plots |

---

## 8. Build commands

```bash
cd a4/runs/iv_pos_8/d1b/analysis
python3 build_d1b_artifacts.py          # ~51s on 20 DBs
python3 build_d1b_notebook.py
jupyter nbconvert --to html --execute ../IV_POS_8_D1B_NOTEBOOK.ipynb
```

---

## 9. Batch 3 hand-off pointers

Numbers above feed:

1. **`d1b_recommendation.md`** — D2 default CGC reward choice (compare discrimination duration vs key cardinality)
2. **`d1e_handoff_CGC_saturation.md`** — L0 rewire saturation table from §5
3. **`D1B_SUBSECTION.md`** — Pro-facing summary + page_class disclosure

**Preliminary observation (superseded by Batch 3):** See `d1b_recommendation.md` — saturation inversion is the decisive finding; keep production_log2_corrected as D2 default.

---

## 10. Review checklist

- [ ] Opus review of sanity invariants + saturation definition
- [ ] Ivan review of headline table + Batch 3 framing
- [ ] D2 ack still pending for `compressed_global_extractor.py` patch (Batch 1.6) — orthogonal to Batch 2 analysis-only artifacts

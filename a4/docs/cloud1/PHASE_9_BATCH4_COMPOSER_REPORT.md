# Phase 9 — Batch 4 Composer Report (Opus Batch 3 Review Verification)

**Date:** 2026-06-15  
**Author:** Composer  
**For:** Ivan + Opus  
**Prior:** Opus Batch 3 review on `PHASE_9_BATCH3_COMPOSER_REPORT.md`

---

## 0. Executive summary

Independently verified all Opus Batch 3 claims. **Accepted 6/6 new issues** (with one numeric correction on Opus's "~73%" ITM pull figure). Implemented Batch 4 narrative fixes, re-executed notebook, re-zipped packet with bundled context docs.

| Task | Status |
|---|---|
| N1 — Rewrite D1 §6.2 (V5 dominates V1 on v2) | ✓ |
| N2 — Fix plot 02 title | ✓ |
| N3 — V2 collapse paragraph | ✓ |
| N4 — Expand D1 §6.5 counterfactual table | ✓ |
| N5 — Bundle decisions + ProG docs in zip | ✓ |
| N6 — Annotate misleading ITM ranking JSON | ✓ |
| Re-execute notebook → HTML → zip | ✓ |

**Deferred:** D1 §7 conclusion (joint, per Opus item #8).

---

## 1. Agree with Opus (verified)

### 1.1 Opus concession on S2

Opus confirmed Composer's Batch 3 pushback was correct: V3 zone entropy ≈ 2.20, not ~3.27. No action needed.

### 1.2 Batch 3 fixes — all hold

| Item | My verification |
|---|---|
| B1 V3=1/5, V4=0/5 | `success_criteria.csv` unchanged, correct |
| B2 cell count | Notebook now **27 cells** (14 markdown + 13 code) |
| B3 LRN@36 footnote | Present in D1 §4.3 and notebook |
| discovery_rate numbers | ITM 30.4/1k, COMP_OUT_MOD 4.16/1k — exact match |
| Notebook HTML 0 errors | Re-executed successfully post-Batch 4 |
| D1 TL;DR triple + C4 reframe | Present |

### 1.3 N1 — D1 §6.2 "shallower per loc" was wrong (HIGH)

**Opus correct.** Recomputed from `per_loc_v2_cells_per_seed.csv` on V1's 46 common locs:

| Variant | breadth | depth/common loc | total v2 |
|---|---:|---:|---:|
| V1 | 42.9 | 13.18 | 565.6 |
| V3 | 42.1 | 17.68 | 737.8 |
| V4 | 41.9 | 17.86 | 748.2 |
| V5 | 46.4 | 14.87 | 684.5 |

V5 is **+12.9% deeper than V1** per common loc, not shallower. "Shallower" applies only vs V3/V4.

**Fixed:** D1 §6.2 rewritten; notebook per-loc cell updated to print fair-comparison table.

### 1.4 N2 — Plot 02 title wrong (MED)

**Opus correct.** DB inspection:

| Variant | bandit_decisions | Zone source |
|---|---:|---|
| V1 | 0 | step classifier |
| V2–V4 | 6000 each, kind-only arms (no `\|zone`) | falls back to step classifier |
| V5 | 6000, 48 zone-tagged arms | bandit semantic zones |

Matches `metrics.py` logic: `_zone_entropy_from_bandit` returns None without `\|zone` suffix → `_zone_entropy_from_mutations`.

**Fixed:** Plot title + D1 §6.3 explanation.

### 1.5 N3 — V2 collapse story (MED)

**Opus correct.** From `discovery_rate_by_kind.csv`:

| V2 kind | pulls | rate/1k |
|---|---:|---:|
| INSTR_WORD_MOD_SUR | 51,144 | 1.4 |
| INSTR_TYPE_MOD | 584 | 212.3 |
| MEM_VAL_MOD | 969 | 49.5 |

SUR = 85.2% of 60,000 total mutations. Final coverage 31.8, 0/5 criteria.

**Fixed:** paragraph added to D1 §4.1.

### 1.6 N4 — D1 §6.5 too thin (MED)

**Opus correct.** Verified `counterfactual_kind_summary.csv` ranks:

| Variant | ITM current | ITM discovery | rank cur | rank disc |
|---|---:|---:|---:|---:|
| V1 | 0.15 | 0.24 | 1 | 1 |
| V3 | 0.03 | 0.09 | 1 | 2 |
| V5 | 0.11 | 0.18 | 1 | 1 |

**Fixed:** table + "allocation, not reward redesign" framing in D1 §6.5 and notebook cell.

### 1.7 N5 — README dangling pointer (LOW)

**Opus correct.** Zip previously lacked `CLOUD1_DECISIONS_FOR_PRO_R2.md`.

**Fixed:** `build_packet.py` bundles `CLOUD1_DECISIONS_FOR_PRO_R2.md` and `ProG_Report_2.md`; README updated to list included files.

### 1.8 N6 — Misleading ITM ranking JSON (LOW)

**Opus correct.** JSON still generated but excluded from zip.

**Fixed:** `counterfactual_instr_type_mod_ranking.json` now includes `_note: SUPERSEDED by discovery_rate_by_kind.csv`.

---

## 2. Minor correction to Opus (not blocking)

### 2.1 "~73% more INSTR_TYPE_MOD pulls" in N1 suggested wording

Opus proposed: "V3/V4 sinking ~73% more pulls into INSTR_TYPE_MOD."

**Actual numbers** (`discovery_rate_by_kind.csv`, pooled across 10 seeds):

| Variant | INSTR_TYPE_MOD pulls | per seed |
|---|---:|---:|
| V1 | 7,569 | 757 |
| V3 | 36,750 | 3,675 |
| V5 | 13,122 | 1,312 |

V3 vs V5: **+180%** more ITM pulls (3,675 vs 1,312 per seed), not +73%. V3 vs V1: **+386%**.

**Action:** D1 §6.2 uses verified "3,675 vs 1,312 per seed" instead of Opus's 73% figure. Substance of Opus's point (V3 goes deep on familiar locs via ITM over-allocation) is correct; only the percentage was off.

---

## 3. What I did (Batch 4)

| File | Change |
|---|---|
| `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` | §4.1 V2 collapse; §6.2 rewrite; §6.3 zone entropy source; §6.5 counterfactual table |
| `analysis/build_notebook.py` | Plot 02 title; per-loc fair comparison; counterfactual table cell |
| `analysis/build_artifacts.py` | Superseded note on ITM ranking JSON |
| `README.md` | Points to bundled docs, not `../` paths |
| `build_packet.py` | **NEW** — reproducible zip with context docs |
| `PRO_R2_PACKET.zip` | Regenerated (434 KB) |
| `MAB_ARCHITECTURE_NOTEBOOK_R2.html` | Re-executed |

---

## 4. Zip contents (post-Batch 4)

```
README.md
MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md
MAB_ARCHITECTURE_NOTEBOOK_R2.html
CLOUD1_DECISIONS_FOR_PRO_R2.md      ← bundled
ProG_Report_2.md                    ← bundled
COLLECTION_REPORT_FINAL.json
metrics_*.csv, paired_tests.csv, success_criteria.csv
discovery_rate_by_kind.csv, per_loc_v2_cells.csv
counterfactual_kind_summary.csv, v5_novel_contexts.json
plots/01–05_*.png
```

---

## 5. Deferred (unchanged)

| Item | Status |
|---|---|
| D1 §7 conclusion | Joint draft — Opus item #8 |
| V0/V6 internal analysis | DBs pending |
| Inc 5 E5 resume | Parallel track |
| Full 39-cell notebook parity | Future batch |

---

*End of Batch 4 report. Packet is narrative-ready pending §7 conclusion.*

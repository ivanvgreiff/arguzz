# Phase 9 — Batch 3 Composer Report (Opus Review Verification + Implementation)

**Date:** 2026-06-15  
**Author:** Composer  
**For:** Ivan + Opus  
**Prior:** Opus Batch 2 review on `PHASE_9_BATCH2_COMPOSER_REPORT.md`

---

## 0. Executive summary

I independently verified every Opus claim I could recompute from raw DBs, **accepted 11/12 actionable items**, **pushed back on 1** (V3 zone entropy), implemented Batch 3 scope, and shipped:

| Deliverable | Status |
|---|---|
| B1 fix (success criteria table) | ✓ |
| B2/B3 doc fixes + V3 LRN@36 footnote | ✓ |
| `discovery_rate_by_kind.csv` + notebook heatmap | ✓ |
| `per_loc_v2_cells.csv` | ✓ |
| Notebook executed → `MAB_ARCHITECTURE_NOTEBOOK_R2.html` | ✓ |
| D1 draft §§1–6 + appendix (no §7) | ✓ |
| `PRO_R2_PACKET.zip` | ✓ |

**Tests:** 7/7 pass. **Collection:** 50/50 PASS.

---

## 1. Agree with Opus (verified independently)

### 1.1 Data layer — all headline numbers hold

| Claim | My recompute | Verdict |
|---|---|---|
| V5 novel locs = 4 (LRN@35/44/45, MRET@93) | Exact match via `discover_dbs()` union | ✓ |
| V1 union = 46 | 46 | ✓ |
| V1 zone entropy ≈ 2.20 | 2.2036 | ✓ |
| V5 zone entropy ≈ 3.27 | 3.2712 | ✓ |
| V5 per-seed final all ≥46 | [46,46,46,48,46,47,46,46,46,47] — 10/10 | ✓ |
| V5 σ ratio C2 = 0.584 | 0.699/1.197 | ✓ |
| V5 modes 5615/233/144/8, σ=0 | `v5_mode_summary.csv` | ✓ |
| V5 5/5 in `success_criteria.csv` | CSV confirms | ✓ |
| INSTR_TYPE_MOD rank-1 under current (all variants) | `counterfactual_kind_summary.csv` | ✓ |
| Boolean ITM counterfactual rank is misleading | Agree — rate analysis is authoritative | ✓ |

### 1.2 B1 — §4 narrative table was wrong (HIGH)

**Opus correct.** `success_criteria.csv` is authoritative:

- **V3:** C3 ratio = 3987/4366 = **0.913** (>0.7) → FAIL. Total **1/5** (only C5).
- **V4:** C3 ratio = 3597/4366 = **0.824** → FAIL. Total **0/5**.

Batch 2 report incorrectly gave V3/V4 ✓ on C3 and inflated totals to 2/5 and 1/5.

**Fixed in:** `PHASE_9_BATCH2_COMPOSER_REPORT.md` §4, D1 §5, notebook success-criteria cell.

### 1.3 B2 — cell count cosmetic

**Opus correct.** Batch 2 said 17 cells (§3) and listed 11 (§7). Actual notebook: **23 cells** after Batch 3 expansion (was 23 before expansion too — the "17" was wrong even pre-Batch 3).

**Fixed:** Batch 2 report §3.3 updated to 23.

### 1.4 B3 — V3 LRN@36 footnote

**Opus correct.** Verified:

- V3 novel vs V1: `{LRN@35, LRN@36, MRET@93}`
- V5 novel vs V1: `{LRN@35, LRN@44, LRN@45, MRET@93}`
- V3-exclusive vs V5: **LRN@36 only**

**Added:** footnote in Batch 2 report §1.1, notebook novel-contexts cell, D1 §4.3.

### 1.5 Open questions Q1–Q5

| Q | Opus answer | My verdict |
|---|---|---|
| Q1 TL;DR triple | Novel + 5/5 + 4.3× speedup | ✓ Adopted in D1 TL;DR |
| Q2 C4 "narrow" caveat | Reframe as +30% over V1 | ✓ V1 CGC=144.2, V5=188.1, +30.4%, bar=173.0 |
| Q3 v2 inversion | Per-loc breakdown needed | ✓ Built `per_loc_v2_cells.csv` |
| Q4 discovery-rate supplement | Yes, replace boolean ITM | ✓ `discovery_rate.py` + plot |
| Q5 execute notebook now | Yes | ✓ HTML + 5 PNGs |

### 1.6 Discovery-rate table (Opus pre-validated)

**Opus correct** once `discover_dbs()` deduplication is used (V1 has 40 raw DB paths but 10 canonical seeds).

Verified key rows:

| Kind | V1 pulls | V1 rate/1k | V5 pulls | V5 rate/1k |
|---|---:|---:|---:|---:|
| INSTR_TYPE_MOD | 7569 | 30.4 | 13122 | 19.9 |
| COMP_OUT_MOD | 7448 | 0.54 | 4810 | 4.16 |
| LOAD_VAL_MOD | 7432 | 0.81 | 2400 | 0.0 |
| STORE_OUT_MOD | 7548 | 0.26 | 2400 | 0.0 |

**Caveat I add:** INSTR_TYPE_MOD *rate* drops V1→V5 (−10.5/1k) while *pulls* rise +73%; net discoveries rise 230→261. Opus's COMP_OUT_MOD and starvation stories are the stronger slides; ITM needs "rate × allocation" framing not rate alone.

### 1.7 S1 — deterministic V5 modes

**Opus correct.** σ=0 is real (floor schedule by mutation index).

**Added:** one sentence in notebook §9.5 cell.

---

## 2. Disagree with Opus (with justification)

### 2.1 S2 — "V3 zone entropy is ~3.2"

**Opus wrong.** `metrics_aggregate.csv`:

| Variant | `allocation_entropy_by_zone_mean` |
|---|---:|
| V1 | 2.20 |
| V3 | **2.20** |
| V4 | 2.18 |
| V5 | **3.27** |

V3 tracks V1 (~2.20), not V5 (~3.27). Opus likely misread the V5 column or conflated variants.

**Action taken:** D1 §6.3 explicitly notes V3 ≈ 2.20. Notebook boxplot already includes all 5 variants (Batch 2 scaffold was correct on this point; only Opus's textual claim was wrong).

---

## 3. What I implemented (Batch 3)

### 3.1 New analysis modules

| Module | Output |
|---|---|
| `analysis/discovery_rate.py` | `discovery_rate_by_kind.csv`, `discovery_rate_v1_vs_v5_delta.csv` |
| `analysis/per_loc_v2.py` | `per_loc_v2_cells.csv` |

### 3.2 Notebook + plots

Regenerated and executed `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` → `MAB_ARCHITECTURE_NOTEBOOK_R2.html`.

| Plot | Content |
|---|---|
| `01_cumulative_coverage.png` | AUC curves V1–V5 |
| `02_zone_entropy.png` | All 5 variants |
| `03_local_coverage_v2.png` | Secondary metric |
| `04_per_loc_v2_depth.png` | Wide vs deep |
| `05_discovery_rate_by_kind.png` | V1 vs V5 smoking gun |

### 3.3 D1 draft

`MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` — §§1–6 + appendix only (no §7).

### 3.4 Packet

`PRO_R2_PACKET.zip` — D1 + D3 + decisions doc pointer + key CSVs/JSON + plots + README.

---

## 4. Not done (per scope)

| Item | Reason |
|---|---|
| D1 §7 conclusion | Deferred — human-authored |
| V0/V6 internal analysis | DBs not landed |
| Full 39-cell IV.POS.5 notebook parity | Batch 3 added 5 critical cells; remainder is Batch 4+ |
| Inc 5 E5 pipeline resume | Parallel track; unchanged |

---

## 5. Files changed/added

```
a4/runs/iv_pos_7/
  analysis/discovery_rate.py          NEW
  analysis/per_loc_v2.py              NEW
  analysis/build_artifacts.py         UPDATED
  analysis/build_notebook.py          UPDATED
  discovery_rate_by_kind.csv          NEW
  per_loc_v2_cells.csv                NEW
  MAB_ARCHITECTURE_NOTEBOOK_R2.html   NEW (D3)
  MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md NEW (D1)
  PRO_R2_PACKET.zip                   NEW
  README.md                           NEW
  plots/05_*.png, 04_*.png            NEW

a4/docs/cloud1/
  PHASE_9_BATCH2_COMPOSER_REPORT.md   FIXED (B1, B2, B3)
  PHASE_9_BATCH3_COMPOSER_REPORT.md   THIS FILE
```

---

*End of Batch 3 report.*

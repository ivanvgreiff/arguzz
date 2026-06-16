# Phase 9 — Batch 2 Composer Report (IV.POS.7 Pro Deliverables)

**Date:** 2026-06-14  
**Author:** Composer  
**For:** Ivan + Opus review  
**Prior:** `PHASE_9_BATCH1_COMPOSER_REVIEW.md` + Opus Batch 1 review feedback  
**Plan:** `a4/runs/iv_pos_7/DELIVERABLES_PLAN.md` Steps 4–8 (partial)

---

## 0. Executive summary

Batch 2 incorporated **all three Opus fixes** from Batch 1 review, implemented **Steps 4–6** (success criteria, counterfactuals, V5 per-arm diagnostic), regenerated **all CSV/JSON artifacts**, and scaffolded **`MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`** with the four cells Opus requested (novel contexts, zone entropy, v2 companion, success criteria).

**Headline:** V5 (`cTS_semantic_v2`) passes **5/5** Pro §10 success criteria mechanically. It discovered **4 constraint locations** never hit by any V1 seed — including `ControlMRET@inst_control.zir:93` and three `ControlLoadRootAndNonce` sites.

**Not done in Batch 2 (intentionally):** D1 narrative (§7 conclusion), D3 HTML render, `PRO_R2_PACKET.zip`, Step 11 V0/V6.

---

## 1. Opus feedback — fixes applied

### 1.1 MISS — V5 novel context discovery

**Fix:** Added to `metrics.py`:

| Column | Scope | Description |
|---|---|---|
| `novel_locs_vs_v1` | per seed | Count of `coverage.constraint_loc` in this DB not in V1 union |
| `novel_locs_names_vs_v1` | per seed | Semicolon-separated novel loc names |
| `novel_locs_union_vs_v1` | per variant | Union novel locs across seeds vs V1 baseline |

**Artifact:** `v5_novel_contexts.json`

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

**Note:** V3 also shows `novel_locs_union_vs_v1=3` — `{LRN@35, LRN@36, MRET@93}`. V5's 4 are `{LRN@35, LRN@44, LRN@45, MRET@93}`. V3-exclusive: **LRN@36** (V5 did not hit it). Both variants probe the LRN/MRET cluster; V5 goes wider on LRN line numbers.

### 1.2 BUG — `allocation_entropy_by_zone` NaN for V1

**Fix:** New `zone_cache.py` loads `classify_zones(InspectionData)` once (cached). When `bandit_decisions` is empty (V1 zoned), zone entropy is computed from `mutations.step` → zone map.

**Verified:**

| Variant | mean zone entropy |
|---|---:|
| V1 | 2.20 |
| V5 | 3.27 |

V1 is no longer NaN; V1↔V5 comparison is meaningful.

**Bugfix during Batch 2:** `zone_cache.py` initially used `parents[3]` (pointed at `a4/` not repo root); corrected to `parents[4]` → `/root/arguzz/workspace/output/target/release/risc0-host`.

### 1.3 ADD — `local_coverage_v2_final` secondary column

**Fix:** Added `local_coverage_v2_final` = `COUNT(*)` from `local_coverage_v2` (Pro §8 `(constraint_loc, major, minor)` granularity).

| Variant | mean legacy final | mean v2 final |
|---|---:|---:|
| V1 | 42.9 | 565.6 |
| V2 | 31.8 | 283.7 |
| V3 | 42.1 | 737.8 |
| V4 | 41.9 | 748.2 |
| V5 | 46.4 | 684.5 |

V5 leads on legacy (primary); v2 picture is mixed (V3/V4 slightly higher on mean v2) — notebook cell `03_local_coverage_v2.png` shows this. Primary endpoint unchanged per Opus confirmation.

---

## 2. Batch 2 modules implemented

| Module | Step | Lines (approx) | Purpose |
|---|---|---:|---|
| `zone_cache.py` | fix | 22 | Cached inspection → step→zone |
| `success_criteria.py` | 4 | 95 | Pro §10 criteria → D8 |
| `counterfactuals.py` | 5 | 95 | Reward counterfactuals + INSTR_TYPE_MOD ranking |
| `per_arm_diagnostic.py` | 6 | 115 | V5 mode pulls, posteriors, cumulative reward |
| `build_artifacts.py` | — | 75 | One-command regeneration |
| `build_notebook.py` | 8 | 175 | Notebook scaffold generator |

**Tests:** 7/7 pass (`pytest a4/runs/iv_pos_7/analysis/`)

---

## 3. Artifacts produced (full inventory)

### 3.1 Core deliverables (D4, D6, D7, D8)

| File | Rows / status | Description |
|---|---|---|
| `COLLECTION_REPORT_FINAL.json` | **50/50 PASS** | D4 |
| `metrics_table.csv` | 50 | D6 — per (variant, seed), **18 metric columns** |
| `metrics_aggregate.csv` | 5 | Per-variant means/stds |
| `paired_tests.csv` | 8 | D7 — 4 variants × 2 metrics vs V1 |
| `success_criteria.csv` | 20 | D8 — 4 variants × 5 criteria |

### 3.2 Batch 2 supporting artifacts

| File | Description |
|---|---|
| `v5_novel_contexts.json` | 4 novel constraint locs (Criterion 5 smoking gun) |
| `counterfactual_by_kind.csv` | Per (variant, seed, kind) counterfactual means |
| `counterfactual_kind_summary.csv` | Aggregated per (variant, kind) |
| `counterfactual_instr_type_mod_ranking.json` | INSTR_TYPE_MOD rank under current vs discovery |
| `v5_mode_totals.csv` | Per-seed bandit mode pull counts |
| `v5_mode_summary.csv` | Mean pulls per mode (cold/singleton/floor/adaptive) |
| `v5_pulls_by_mode_arm.csv` | Full arm × mode breakdown |
| `v5_final_arm_state.csv` | Posterior α/β at mutation 6000 |
| `v5_cumulative_reward_by_arm.csv` | Per-arm cumulative reward |

### 3.3 Notebook + plots scaffold

| File | Status |
|---|---|
| `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` | **Scaffold written** (23 cells); not yet executed to HTML |
| `plots/` | Created by notebook on run (`01_`, `02_`, `03_` PNGs) |

---

## 4. Success criteria results (D8) — mechanical evaluation

Reference: V1 (`zoned_current`). Criteria from `PHASE_9_REPORT.md` §9.3.

| Variant | C1 AUC p<0.05 | C2 σ ratio <0.7 | C3 t43 ratio <0.7 | C4 local+CGC | C5 novel | **Total** |
|---|---|---|---|---|---|---:|
| V2 | ✗ | ✗ | ✗ | ✗ | ✗ | 0/5 |
| V3 | ✗ | ✗ | ✗ (0.913) | ✗ | ✓ (3 novel) | 1/5 |
| V4 | ✗ (p≈0.09) | ✗ | ✗ (0.824) | ✗ | ✗ | 0/5 |
| **V5** | **✓** | **✓** (0.584) | **✓** (0.233) | **✓** | **✓** (4 novel) | **5/5** |

### V5 evidence strings (from `success_criteria.csv`)

| Criterion | Evidence |
|---|---|
| C1 | ΔAUC=+36,412, p=0.0000 |
| C2 | mean_final=46.40 vs V1=42.90, σ_ratio=0.584 |
| C3 | mean_t43=1017 / V1=4366 = 0.233 |
| C4 | local=46.40≥42.90, CGC=188>173 (+20% threshold) |
| C5 | novel_locs_union_vs_v1=4 |

**Interpretation for D1 TL;DR (human-authored, not Composer):** V5 is the only variant that satisfies all five survival criteria. The 4 novel kernel/ECALL-adjacency contexts are the strongest qualitative result — they are exactly the regions Pro predicted semantic-zone arms would unlock.

---

## 5. Counterfactual analysis (Step 5 — partial)

### 5.1 INSTR_TYPE_MOD per-kind means (selected)

| Variant | current_reward | discovery_binary | no_qloc |
|---|---:|---:|---:|
| V1 | 0.149 | 0.239 | 0.172 |
| V3 (no_Qloc) | 0.029 | 0.086 | 0.129 |
| V5 (cTS) | 0.110 | **0.181** | 0.138 |

V5 maintains INSTR_TYPE_MOD as top kind under both current and discovery counterfactuals.

### 5.2 Pro §12 ranking check — needs refinement (Batch 3 note)

`counterfactual_instr_type_mod_ranking.json` uses per-variant kind rank (1=highest mean). INSTR_TYPE_MOD is rank 1 under **current** for all variants, so `discovery_ranks_higher_than_current` is false everywhere.

The IV.POS.5 smoking gun was **discovery rate per 1000 mutations**, not mean counterfactual reward. Batch 3 should add:

- Discovery **rate** per kind (new contexts / pulls) from `coverage` first-hits joined to `mutations.kind`
- Explicit check: `rank_current(INSTR_TYPE_MOD) - rank_discovery(INSTR_TYPE_MOD) > 0` using **rate** not mean reward

Counterfactual CSVs are complete for notebook scatter/heatmap cells; ranking JSON is informational only for now.

---

## 6. V5 per-arm diagnostic (Step 6)

### 6.1 Mode pull distribution (mean per seed, 10 seeds)

| Mode | mean pulls/seed | total (10 seeds) |
|---|---:|---:|
| floor | 5615 | 56150 |
| adaptive | 233 | 2330 |
| cold | 144 | 1440 |
| singleton | 8 | 80 |

All four mode categories present ✓ (Opus review checkpoint).

### 6.2 Interpretation sketch

- **Floor** dominates (~93.6% of pulls) — constrained TS enforcing kind/zone floors per Pro §7.C.
- **Adaptive** ~3.9% — TS budget on remaining arms.
- **Cold** + **singleton** ~2.5% — boundary/singleton exploration.

Full per-arm posterior and cumulative reward tables in `v5_final_arm_state.csv` and `v5_cumulative_reward_by_arm.csv`.

---

## 7. Notebook scaffold (Step 8 — partial)

`MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` cells:

1. Setup (imports from `analysis/`, loads CSVs)
2. Headline aggregate table
3. **★ Novel contexts smoking gun** (reads `v5_novel_contexts.json`)
4. Cumulative coverage curves → `plots/01_cumulative_coverage.png`
5. Zone entropy boxplot V1–V5 → `plots/02_zone_entropy.png`
6. local_coverage_v2 boxplot → `plots/03_local_coverage_v2.png`
7. Paired tests table
8. Success criteria summary
9. Counterfactual INSTR_TYPE_MOD check
10. V5 mode breakdown
11. Summary placeholder (explicitly NOT D1 §7)

**Not yet done:** Execute notebook → HTML (D3), expand to full 39-cell IV.POS.5 parity, reward heatmaps.

---

## 8. How to reproduce

```bash
cd /root/arguzz
pip install -r a4/runs/iv_pos_7/analysis/requirements.txt

# Tests
PYTHONPATH=/root/arguzz/a4/runs/iv_pos_7 python3 -m pytest a4/runs/iv_pos_7/analysis/ -q

# Regenerate all CSV/JSON
PYTHONPATH=/root/arguzz/a4/runs/iv_pos_7 python3 a4/runs/iv_pos_7/analysis/build_artifacts.py

# Regenerate notebook scaffold
python3 a4/runs/iv_pos_7/analysis/build_notebook.py

# Execute notebook (Batch 3)
# jupyter nbconvert --to notebook --execute a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb
# jupyter nbconvert --to html a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb
```

---

## 9. Recommended Batch 3 scope (pending greenlight)

| Priority | Task | Deliverable |
|---|---|---|
| 1 | Execute notebook + render D3 HTML | `MAB_ARCHITECTURE_NOTEBOOK_R2.html` |
| 2 | Expand notebook toward IV.POS.5 39-cell layout | Remaining plot cells |
| 3 | Fix INSTR_TYPE_MOD ranking via discovery **rate** | Updated counterfactual check |
| 4 | Draft D1 skeleton (§§1–6 + appendix only; **no §7**) | `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` |
| 5 | `PRO_R2_PACKET.zip` + `README.md` | Step 12 |
| 6 | Step 11 when V0/V6 DBs land | `INTERNAL_V0_V6_ANALYSIS.md` |

**Parallel track:** Inc 5 E5 — resume 19 missing arms (`PHASE_7D_INC5_COMPOSER_HANDOFF.md`).

---

## 10. Open questions for review

1. **D1 TL;DR draft** — OK to lead with "V5 discovered 4 novel kernel/ECALL contexts + 5/5 criteria" before joint §7 wording?
2. **Criterion 4** — V5 passes narrowly on CGC (188 vs 173 threshold). Flag as caveat in D1?
3. **local_coverage_v2** — V3/V4 beat V5 on mean v2; how to frame without undermining V5 legacy win?
4. **Counterfactual ranking** — approve Batch 3 discovery-rate supplement?
5. **Notebook** — execute now or wait for D1 skeleton review?

---

## 11. File tree (new/changed in Batch 2)

```
a4/runs/iv_pos_7/
  analysis/
    zone_cache.py              NEW
    success_criteria.py        NEW
    counterfactuals.py         NEW
    per_arm_diagnostic.py      NEW
    build_artifacts.py         NEW
    build_notebook.py          NEW
    metrics.py                 UPDATED (novel, v2, zone fix)
    collection_validator.py    UPDATED (repo path fix)
    test_metrics.py            UPDATED
    test_stats.py              UPDATED (scipy warning comment)
  metrics_table.csv            REGENERATED
  metrics_aggregate.csv        NEW
  paired_tests.csv             REGENERATED
  success_criteria.csv         NEW (D8)
  v5_novel_contexts.json       NEW
  counterfactual_*.csv/json    NEW
  v5_*.csv                     NEW
  MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb  NEW (scaffold)
  COLLECTION_REPORT_FINAL.json REGENERATED

a4/docs/cloud1/
  PHASE_9_BATCH1_COMPOSER_REVIEW.md
  PHASE_9_BATCH2_COMPOSER_REPORT.md   THIS FILE
```

---

*End of Batch 2 report. Awaiting review before Batch 3 (HTML, D1 skeleton, packet zip).*

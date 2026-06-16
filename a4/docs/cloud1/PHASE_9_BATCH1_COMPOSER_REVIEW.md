# Phase 9 — Batch 1 Composer Review (IV.POS.7 Pro Deliverables)

**Date:** 2026-06-14  
**Author:** Composer  
**For:** Ivan + Opus review before greenlighting Batch 2  
**Plan:** `a4/runs/iv_pos_7/DELIVERABLES_PLAN.md`  
**Pro context:** `a4/docs/cloud1/ProG_Report_2.md` (especially §10 metrics + success criteria)  
**Task list:** `a4/docs/cloud1/phases/PHASE_9_REPORT.md` (Phase 9.1–9.7)

---

## 0. Context summary (prior work cleared from session)

**Inc 5 (Phase 7d E5)** — paused, not abandoned:
- Preflight PASS; 3 E5 scripts written; **29/48** per-arm evidence `.md` files complete.
- Pipeline interrupted ~4h in (no `OTHER` disposition failures).
- Resume with `--arms` for 19 missing arms only — **no need to overwrite** the 29 existing files.
- Handoff: `a4/docs/cloud1/composer/PHASE_7D_INC5_COMPOSER_HANDOFF.md`

**This session** pivots to **Phase 9**: turn IV.POS.7 campaign data into Pro Round 2 deliverables so ChatGPT Pro can judge whether V1–V5 architecture variants beat `zoned_current`.

---

## 1. What Phase 9 is for

IV.POS.5 showed zoned beat the old bucketed UCB bandit. Pro responded in `ProG_Report_2.md` with a redesigned architecture (semantic zones, constrained TS, discovery-aligned reward) and asked for **IV.POS.7**: 5 variants × 10 seeds × N=6000 mutations.

Phase 8 (`PHASE_8_IV_POS_7.md`) ran the campaigns. **Phase 9** packages results for Pro:

| Deliverable | Purpose |
|---|---|
| **D1** `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` | Narrative Pro reads first |
| **D2/D3** Notebook + HTML | Reproducible plots |
| **D4** `COLLECTION_REPORT_FINAL.json` | 50/50 DB integrity |
| **D6–D8** CSV metrics / paired tests / success criteria | Machine-readable numbers |
| **Packet** | `ProG_Report_2.md` + D1 + D3 + `CLOUD1_DECISIONS_FOR_PRO_R2.md` |

V0/V6 are **internal only** until V0/V6 DBs land (~Tue CEST per plan).

---

## 2. What Batch 1 executed (Steps 1–3 + 7)

Per `DELIVERABLES_PLAN.md` §5, Composer executed a **reviewable subset** — foundation + numbers, **not** notebook/report yet.

| Step | Status | Output |
|---|---|---|
| **1** Pin analysis environment | ✅ Done | `analysis/requirements.txt`, `analysis/ENV.md` |
| **2** `metrics.py` + tests | ✅ Done | Phase 9.1 metrics on all 50 DBs |
| **3** `stats.py` + tests | ✅ Done | Phase 9.2 paired tests vs V1 |
| **4** `success_criteria.py` | ⏸ Deferred | Needs Opus review of Batch 1 numbers first |
| **5** `counterfactuals.py` | ⏸ Batch 2 | |
| **6** `per_arm_diagnostic.py` | ⏸ Batch 2 | |
| **7** `collection_validator.py` | ✅ Done | D4 written |
| **8–12** Notebook, HTML, D1, zip | ⏸ Batch 2+ | |

### New files (all under `a4/runs/iv_pos_7/`)

```
analysis/
  __init__.py
  requirements.txt
  ENV.md
  discover.py          # 50 DB paths: V1–V5 × seeds 1234–1243
  metrics.py           # Phase 9.1 single source of truth
  stats.py             # Phase 9.2 paired tests
  collection_validator.py
  test_metrics.py
  test_stats.py
metrics_table.csv      # D6 (50 rows)
paired_tests.csv       # D7 (8 rows: 4 variants × 2 metrics)
COLLECTION_REPORT_FINAL.json  # D4
```

**Tests:** `5 passed` (`pytest analysis/test_*.py`)

**Dependencies:** `pip install -r analysis/requirements.txt` (installed scipy et al. on analysis host).

---

## 3. Metric definitions (Batch 1 choices — please confirm)

| Metric | Implementation | Notes for review |
|---|---|---|
| `local_context_final` | `COUNT(*)` from legacy `coverage` table at N=6000 | Matches IV.POS.5 notebook (46-context universe). **Not** `local_coverage_v2` (533+ keys). |
| `local_context_AUC` | Trapezoid integral of cumulative `coverage` first-hits | Pro §10 "∫ coverage(t) dt" |
| `time_to_40/43/46` | First mutation index reaching threshold | `NULL` in CSV if never reached |
| `all_46_hit` | `local_context_final >= 46` | Per seed |
| `compressed_global_context_final` | `COUNT(*)` from `compressed_global_coverage` | v2 semantic global contexts |
| `crash_rate` | `mutation_rewards.mode='crash'` / n_mutations | |
| `no_effect_rate` | normal rows with T_new=F_new=S=d_loc=d_glob=0 | Approximates Pro's zero-discovery definition |
| `allocation_entropy_by_kind` | Shannon over `mutations.kind` | All variants |
| `allocation_entropy_by_zone` | Shannon over zone parsed from `bandit_decisions.selected_arm` | NaN for V1 (no bandit rows); populated for V5 |

**Open question Q2 (from plan §9):** V5 seeds hit 46–48 contexts; some exceed the historical 46-universe. Flag for D1 whether to treat 46 as cap or report raw counts (Batch 1 uses raw `coverage` count).

---

## 4. Headline results (Batch 1 — preliminary, not D1 narrative)

### 4.1 Per-variant aggregates (10 seeds each)

| Variant | Pro name | mean final | σ final | mean AUC | all-46 hit rate |
|---|---|---:|---:|---:|---:|
| **V1** | zoned_current | **42.9** | 1.20 | 228,142 | 0/10 |
| **V2** | kind_UCB + current_reward | **31.8** | 1.62 | 177,804 | 0/10 |
| **V3** | kind_UCB + no_Qloc | **42.1** | 1.73 | 233,650 | 0/10 |
| **V4** | kind_TS + discovery | **41.9** | 2.13 | 235,618 | 0/10 |
| **V5** | constrained_TS + semantic | **46.4** | 0.70 | 264,555 | **10/10** |

### 4.2 Paired tests vs V1 (zoned_current)

| Variant | Metric | mean Δ | paired t p-value |
|---|---|---:|---:|
| V2 | AUC | −50,338 | **<0.0001** (much worse) |
| V2 | final | −11.1 | **<0.0001** |
| V3 | AUC | +5,508 | 0.13 (n.s.) |
| V3 | final | −0.8 | 0.15 (n.s.) |
| V4 | AUC | +7,475 | 0.09 (marginal) |
| V4 | final | −1.0 | 0.19 (n.s.) |
| **V5** | **AUC** | **+36,412** | **<0.0001** |
| **V5** | **final** | **+3.5** | **0.0001** |

### 4.3 Collection validation (D4)

**50/50 PASSED** — all DBs have ≥5999 mutations, expected tables present, selector matches filename.

---

## 5. Early interpretation (Composer — **not** D1 Section 7; Opus/user own the conclusion)

These numbers are **consistent with Pro's IV.POS.7 hypothesis**:

1. **V5 (`cTS_semantic_v2`) clearly beats V1** on both AUC and final local coverage, with lower variance and 100% all-46 hit rate.
2. **V2 regressed badly** — kind-level UCB with zoned step + *current* reward still underperforms zoned; matches Pro's prediction that reward pathology matters even with better step prior.
3. **V3/V4** are near V1 on final coverage; V4 shows AUC trend (p≈0.09) but not significant at α=0.05 on 10 seeds.
4. **V5 max final = 48** on some seeds suggests expanded reachable universe (criterion 5 in Pro §10 may apply — needs `success_criteria.py` in Batch 2).

**Do not ship this interpretation to Pro yet** — Batch 2 still needs success criteria, counterfactuals (§12), per-arm V5 diagnostic, plots, and co-authored D1 §7.

---

## 6. What Batch 2 should do (pending greenlight)

| Priority | Step | Deliverable |
|---|---|---|
| 1 | Step 4 | `success_criteria.py` → `success_criteria.csv` (D8) |
| 2 | Step 5 | `counterfactuals.py` — reward scatter + INSTR_TYPE_MOD ranking check |
| 3 | Step 6 | `per_arm_diagnostic.py` — V5 arm_state_snapshot / mode pulls |
| 4 | Step 8 | Clone IV.POS.5 notebook layout → D2 + `plots/` (D5) |
| 5 | Step 9 | Render D3 HTML |
| 6 | Step 10 | Draft D1 (Composer skeleton; **human writes §7 conclusion**) |
| 7 | Step 12 | `PRO_R2_PACKET.zip` + `README.md` |

**Deferred:** Step 11 (V0/V6 internal) until those DBs are pulled.

---

## 7. Review checklist for Opus / Ivan

Please confirm before Batch 2:

- [ ] **Metric source:** `coverage` table (not `local_coverage_v2`) is correct for Pro's 46-context framing.
- [ ] **DB discovery:** 50 paths (V1–V5 × 10 seeds) mapping looks right — see `analysis/discover.py`.
- [ ] **V5 headline:** Comfortable proceeding with V5 as leading candidate in notebook/report scaffolding?
- [ ] **Q1/Q2/Q4** (plan §9): How to phrase D1 §7 if V5 beats V1 on AUC *and* final with lower σ?
- [ ] **Batch 2 scope:** OK to implement Steps 4–6 + notebook skeleton next?

### Sanity checks you can run

```bash
cd /root/arguzz
pip install -r a4/runs/iv_pos_7/analysis/requirements.txt
PYTHONPATH=/root/arguzz python3 -m pytest a4/runs/iv_pos_7/analysis/ -q
head a4/runs/iv_pos_7/metrics_table.csv
python3 -c "import json; r=json.load(open('a4/runs/iv_pos_7/COLLECTION_REPORT_FINAL.json')); print(r['passed'], r['found_dbs'])"
```

Hand-verify one V1 seed: `local_context_final` for `pos_iv_pos_7_ta_b2_zoned_seed1238_n6000.db` should be **43** (matches `metrics_table.csv`).

---

## 8. Inc 5 status (unchanged — parallel track)

Still **29/48** evidence files. Resume when Phase 9 batch work allows:

```bash
PYTHONPATH=/root/arguzz python3 -m a4.audits.E5_per_arm_evidence --arms "<19 missing arms>"
```

See `a4/docs/cloud1/composer/PHASE_7D_INC5_COMPOSER_HANDOFF.md`.

---

## 9. Recommended Opus ping (after your review)

> Batch 1 landed: analysis/ + metrics_table.csv + paired_tests.csv + COLLECTION_REPORT_FINAL.json (50/50 PASS). Headline: V5 mean final 46.4 vs V1 42.9, AUC p<0.0001. Awaiting greenlight on metric definitions before success_criteria + notebook.

---

*End of Batch 1 review. Awaiting greenlight for Batch 2.*

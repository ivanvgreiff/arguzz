# Internal V0/V6 Analysis Plan (IV.POS.7 — non-Pro track)

**Date:** 2026-06-15
**Author:** Ivan + Opus (planning); Composer (implementation)
**Status:** Batch 4 complete (2026-06-16). V6 still 4/10 partial — re-sync + re-run before §6 conclusion.
**Companion:** `DELIVERABLES_PLAN.md` (Pro-facing V1–V5 work, complete)
**Untouched throughout this work:**
- `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`
- `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`
- `PRO_R2_PACKET.zip`
- All R2 CSV/JSON deliverables already shipped

---

## 0. Goal and audience

**Audience:** internal (Ivan + Opus + Composer). Not Pro-facing. Not bound by Pro §10–§12 framing.

**Questions the analysis must answer:**

1. **V0 anchor** — where does uniform random sit relative to V1–V5? Quantify the V0 → V1 spread (the "structured prior is worth X contexts" claim).
2. **V6 partial preview** — given 2/10 seeds done, what does arguzz look like vs V1 (zoned baseline) and V5 (cTS_semantic_v2)?
3. **V6 fairness** — V6 has a wider kind set (11 vs A4's 8). Decompose where V6's apparent advantage comes from: shared-kind exploration vs V6-exclusive kinds.
4. **Implications for the V5 narrative** — if V6 is a strong external baseline, do we need to re-frame anything in the Pro-facing report? (Likely no, but verify.)

**Out of scope:**
- Anything Pro-facing (R2 packet stays frozen)
- V6 full-seed analysis (we'll iterate as more land — currently 2/10, final 10/10 around 10:00–11:00 CEST Tue)
- Bandit allocation comparisons for V6 (no `bandit_decisions` table)
- New mutation-kind taxonomy work

---

## 1. Inputs (data state)

### 1.1 V0 — uniform random (10/10 done)

10 DBs on coinbase at `/srv/testbed/results/ivgreiff/a4/pos_iv_pos_7_u_*/`:

| Batch | Nodes | Seeds |
|---|---|---|
| u_b1a | goracle, zone | 1234, 1235 |
| u_b1b | flare, octorand, opulous, polynize | 1236, 1237, 1238, 1239 |
| u_b1c | algofi, gard | 1240, 1241 |
| u_b2  | flare, octorand | 1242, 1243 |

DB file selector token: `uniform`. Schema **identical** to V1 (16 tables; `bandit_decisions=0`, `arm_state_snapshot=0`, all other tables populated normally).

### 1.2 V6 — arguzz (2/10 done now, 10/10 ETA ~10:00–11:00 CEST Tue)

| Status | Seeds | Nodes | Available now |
|---|---|---|---|
| ✓ DONE | 1236, 1237 | opulous, polynize | **YES** |
| 🟢 in flight | 1234, 1235 | goracle, zone | partial (file exists, no `.OK`) |
| 🟢 in flight | 1238, 1239 | algofi, gard | partial |
| 🟢 in flight | 1240, 1241 | flare, octorand | partial |
| ⏳ queued | 1242, 1243 | goracle, zone (chain b2) | not started |

**Use only the 2 confirmed `.OK`-completed DBs for now.** Auto re-sync as more land.

DB file selector token: `arguzz`. Schema **reduced** (8 tables). Confirmed missing:
- `local_coverage_v2` → secondary metric N/A for V6
- `mutation_rewards` → `crash_rate` / `no_effect_rate` will be 0
- `bandit_decisions` → no allocation diagnostic
- `reward_counterfactuals` → no counterfactual Pro §12 analysis
- `arm_state_snapshot`, `mutation_substrategy`, `pilot_runs`, `hook3_raw` → N/A

Present and usable: `mutations`, `coverage`, `compressed_global_coverage`, `failures`, `global_failures`, `campaigns`, `campaign_params`.

### 1.3 V6 mutation-kind divergence

V6 emits 11 mutation kinds; A4 (V0–V5) emits 8. Translation:

| Group | Kinds |
|---|---|
| Shared (4) | `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD` |
| A4-only (4) | `INSTR_TYPE_MOD`, `MEM_VAL_MOD`, `INSTR_WORD_MOD_FULL`, `INSTR_WORD_MOD_SUR` |
| V6-only (7) | `PRE_EXEC_PC_MOD`, `POST_EXEC_PC_MOD`, `POST_EXEC_REG_MOD`, `PRE_EXEC_MEM_MOD`, `POST_EXEC_MEM_MOD`, `INSTR_WORD_MOD` (no _FULL/_SUR distinction), `BR_NEG_COND` |

Discovery-rate-by-kind comparisons can only be apples-to-apples on the 4 shared kinds.

---

## 2. Deliverables

| ID | File | Description |
|---|---|---|
| **I1** | `INTERNAL_V0_V6_ANALYSIS.md` | Internal narrative report. Mirrors R2 structure: setup, headline, diagnostics, conclusion. **No** Pro framing. |
| **I2** | `INTERNAL_V0_V6_NOTEBOOK.ipynb` | Internal notebook. Mirrors R2 notebook structure, with V0/V6 added as columns/rows. |
| **I3** | `internal_metrics_table.csv` | Extended `metrics_table.csv` with V0+V6 rows added (per-seed, with V6 rows flagged `partial=True` until full set lands). |
| **I4** | `internal_v0_anchor.csv` | Per-variant deltas vs V0 baseline (the random-floor anchor). |
| **I5** | `internal_v6_vs_v1_v5.csv` | V6 vs V1 and V6 vs V5 on shared metrics. Paired tests where seed pairing is possible (currently only seeds 1236, 1237 are paired). |
| **I6** | `internal_v6_kind_translation.csv` | V6-vs-A4 kind decomposition: which V6 kinds map to A4 kinds, exclusive sets, per-kind discovery rates restricted to the 4-kind intersection. |
| **I7** | `internal_v6_v1_v5_loc_overlap.csv` | Constraint-loc set diff: `V6 ∩ V1`, `V6 ∩ V5`, V6-exclusive, V5-exclusive vs V6, V1-exclusive vs V6. |
| **I8** | `INTERNAL_V0_V6_NOTEBOOK.html` | Rendered notebook (D3 analogue). |

**No zip packet** for internal — these files live in `a4/runs/iv_pos_7/` for our reference.

---

## 3. Implementation order (Composer batches)

### Batch 1 — Data sync + framework extension (~45 min)

| # | Task | Owner |
|---|---|---|
| 1.1 | `rsync` all 10 V0 DBs + 2 confirmed V6 DBs from coinbase to `a4/runs/iv_pos_7/dbs/`. Document the rsync command in `INTERNAL_V0_V6_PLAN.md` so we can re-sync as V6 jobs complete. | Composer |
| 1.2 | Extend `analysis/discover.py` `SELECTOR_TO_VARIANT` with `("uniform","V0")` and `("arguzz","V6")`. Add `VARIANT_TO_PRO_NAME` entries (Pro names: V0=`uniform_random`, V6=`arguzz`). | Composer |
| 1.3 | Add a `partial: bool` flag to discover output for V6 (returns True if seed count < 10). | Composer |
| 1.4 | Run existing `build_artifacts.py` against extended variant set. **Verify it doesn't crash** on V6's missing tables (existing `try/except` should cover, but confirm). Outputs: extended `metrics_table.csv` with V0/V6 rows. **DO NOT overwrite the R2 metrics_table.csv**; write to `internal_metrics_table.csv` instead. | Composer |
| 1.5 | Smoke-print V0 and V6 metric rows; spot-check vs my single-DB inspection (V6 seed 1236: coverage=110, CGC=395; V0 seed 1234: coverage=35, CGC=149). | Composer |

**Review checkpoint #1:** Opus + Ivan verify numbers, framework didn't crash, V6 partial flag is correct.

#### Batch 1 implementation log (Composer, 2026-06-16)

| Task | Status | Notes |
|---|---|---|
| 1.1 rsync V0+V6 DBs | **BLOCKED** | `coinbase.net.in.tum.de` unreachable from WSL. Script: `analysis/sync_internal_dbs.sh` |
| 1.2 extend `discover.py` | **DONE** | `uniform→V0`, `arguzz→V6`, pro names, `ALL_VARIANTS_ORDER` |
| 1.3 `partial` flag | **DONE** | `discover_status()["v6_partial"]` + `partial` column in `internal_metrics_table.csv` |
| 1.4 `build_internal_artifacts.py` | **DONE** | Writes `internal_metrics_table.csv` + `internal_metrics_aggregate.csv`; R2 untouched |
| 1.5 smoke-print | **PARTIAL** | Framework runs on V1–V5 (50 rows); V0/V6 spot-checks pending sync |

**Tests:** 15/15 pass (`test_discover_internal.py` + `test_metrics.py`).

**Re-run after sync:**
```bash
cd /root/arguzz/a4/runs/iv_pos_7
bash analysis/sync_internal_dbs.sh          # from coinbase-accessible host
python3 analysis/build_internal_artifacts.py
```

---

### Batch 2 — V0 anchor analysis (~45 min)

| # | Task | Owner |
|---|---|---|
| 2.1 | New module `analysis/v0_anchor.py`: per-variant Δ vs V0 on `local_context_final`, `local_context_AUC`, `compressed_global_context_final`, `time_to_43`, `local_coverage_v2_final`. Both absolute and percentage deltas. | Composer |
| 2.2 | Paired tests V1, V2, V3, V4, V5 vs V0 (10 seeds each, fully paired) — extend `stats.py` to take an arbitrary reference variant. | Composer |
| 2.3 | Output `internal_v0_anchor.csv` (per variant: Δ_local, Δ_AUC, Δ_CGC, paired t p-value). | Composer |
| 2.4 | V0 sanity check: V0's `coverage` mean should be **lower** than V1's 42.9 (since uniform = no structured prior). My single-seed V0 inspection showed `coverage=35`, supporting this. Verify across all 10 V0 seeds. | Composer |

**Review checkpoint #2:** Opus verifies V0 numbers, anchor table reasonable.

#### Batch 2 implementation log (Composer, 2026-06-16)

| Task | Status | Notes |
|---|---|---|
| 2.1 `v0_anchor.py` | **DONE** | Δ abs + % vs V0 on 7 metrics incl. zone entropy + CGC |
| 2.2 `stats.py` arbitrary reference | **DONE** | `paired_tests(df, reference=..., metrics=...)`; NaN-safe pairing |
| 2.3 `internal_v0_anchor.csv` | **DONE** | 42 rows (6 variants × 7 metrics); paired p-values merged |
| 2.4 V0 sanity | **DONE** | loc mean=35.0, std=1.56, range [33,38] → `internal_v0_sanity.json` |
| 2.5 CGC delta surfaced | **DONE** | V1 CGC +2.5% vs V0 (O1 callout in build output) |
| 2.6 Zone entropy | **DONE** | V0=1.942 (not ~3.46 — zones size-imbalanced); V5=3.271 |

**Key anchor findings (for Review #2):**

| Variant | Δ loc (%) | Δ AUC (%) | Δ CGC (%) | Δ zone_H |
|---|---:|---:|---:|---:|
| V1 | +22.6% | +20.7% | +2.5% | +0.26 |
| V5 | +32.6% | +39.9% | +33.7% | +1.33 |

**Tests:** 20/20 pass (v0_anchor + stats + discover_internal).

Also writes `internal_v0_paired_tests.csv` (30 rows, V1–V5 × 5 metrics vs V0).

---

### Batch 3 — V6 partial analysis (~1h)

| # | Task | Owner |
|---|---|---|
| 3.1 | New module `analysis/v6_comparison.py`: V6 vs V1, V6 vs V5 on shared metrics (`local_context_final`, `local_context_AUC`, `compressed_global_context_final`). | Composer |
| 3.2 | Paired tests on the seeds V6 has completed only (currently seeds 1236, 1237). Use small-n caveat: report mean diff + raw values, **suppress p-values when n<5** (note "n=2 — preview only"). | Composer |
| 3.3 | Constraint-loc set decomposition (`internal_v6_v1_v5_loc_overlap.csv`): `V6 ∩ V5_novel_4`, V6-exclusive locs, V1-exclusive vs V6, V5-exclusive vs V6. **Critical question:** does V6 find the 4 novel kernel/ECALL locs V5 found? | Composer |
| 3.4 | Kind-set translation analysis (`internal_v6_kind_translation.csv`): per-kind pull counts and discovery rates for the 4 shared kinds across V0/V1/V5/V6. Quantify how much of V6's coverage advantage is "extra kinds A4 can't access" vs "better exploration on shared kinds". | Composer |
| 3.5 | Apples-to-apples coverage subset: count constraint_locs in V6's coverage that lie in A4's V1-V5-reachable union (i.e., the locs that ANY of V0–V5 found across all 50 A4 seeds). Report V6's coverage restricted to this universe vs V6's full coverage. | Composer |

**Review checkpoint #3:** Opus reviews V6 framing and the fairness decomposition. Especially scrutinize §3.4 and §3.5 — these are the key honesty checks.

---

### Batch 4 — Notebook + report draft (~1.5h)

| # | Task | Owner |
|---|---|---|
| 4.1 | New `analysis/build_internal_notebook.py` (parallel to `build_notebook.py`). Generate `INTERNAL_V0_V6_NOTEBOOK.ipynb` scaffold. | Composer |
| 4.2 | Notebook cells: (a) V0 anchor barchart, (b) V0–V5 cumulative coverage with V0 added in red, (c) V6 partial preview (2 seeds shown as individual lines, not aggregate), (d) V6 vs V5 loc overlap Venn or set table, (e) shared-kind discovery rate V0/V1/V5/V6 grouped barchart, (f) V6's apples-to-apples coverage (restricted to A4-reachable universe). | Composer |
| 4.3 | Draft `INTERNAL_V0_V6_ANALYSIS.md`: §1 goal/scope, §2 V0 anchor results, §3 V6 partial preview, §4 V6 fairness decomposition, §5 implications for V5 narrative, §6 open questions. **No conclusion section** — Ivan + Opus draft jointly after reviewing data. | Composer |
| 4.4 | Execute notebook → `INTERNAL_V0_V6_NOTEBOOK.html`. | Composer |

**Review checkpoint #4:** Opus + Ivan reviews narrative, plot accuracy, V6 caveats. Iterate.

#### Batch 4 implementation log (Composer, 2026-06-16)

| Task | Status | Notes |
|---|---|---|
| 4.1 `build_internal_notebook.py` | **DONE** | 8 cells, 5 plots → `plots_internal/` |
| 4.2 notebook cells | **DONE** | V0 anchor, cumulative+V6 lines, loc overlap, kind stacked, loc+CGC |
| 4.3 `INTERNAL_V0_V6_ANALYSIS.md` | **DONE** | §1–§5 draft; §6 deferred |
| 4.4 M1 CGC apples-to-apples | **DONE** | 104/483 (21.5%) in `internal_v6_apples_to_apples.csv` |
| 4.5 HTML | **DONE** | `INTERNAL_V0_V6_NOTEBOOK.html` (671KB, plots embedded) |

**Re-run pipeline after V6 10/10:**
```bash
cd /root/arguzz/a4/runs/iv_pos_7
bash analysis/sync_internal_dbs.sh
python3 analysis/build_internal_artifacts.py
python3 analysis/build_internal_notebook.py
jupyter nbconvert --execute --to html INTERNAL_V0_V6_NOTEBOOK.ipynb
```

---

### Batch 5+ — Iterate (open-ended, like R2)

- Review feedback addressed
- §6 conclusion drafted jointly after data review
- As additional V6 DBs land (~07:00 → ~11:00 CEST Tue), re-run `build_artifacts.py` to update internal CSVs; notebook re-executes. Final pass once 10/10 V6 land.
- Decision point: do we surface V6's strength to Pro in a future round? (Out of scope for this plan; just flag as a downstream question.)

---

## 4. Risks and watch-outs

| # | Risk | Mitigation |
|---|---|---|
| R1 | V6's wider kind set inflates raw coverage; misreading as "arguzz beats V5" without disentangling kind set | Batch 3 §3.4 + §3.5 — explicit fairness decomposition |
| R2 | V6 missing tables crash existing modules | Existing `try/except` catches; Batch 1 §1.4 verifies |
| R3 | V6 partial-data noise (n=2) makes paired tests meaningless | Suppress p-values when n<5; report raw values + mean diffs only |
| R4 | Re-running `build_artifacts.py` overwrites the R2-shipped `metrics_table.csv` | Compose to **separate file** `internal_metrics_table.csv`; don't touch R2 CSVs |
| R5 | `discovery_rate.py`'s hardcoded `KINDS` list excludes V6-only kinds | Extend or use dynamic kind enumeration in `kind_translation.csv` |
| R6 | V6's per-job in-flight DBs visible on disk but missing `.OK` markers — could be picked up if we sync results dirs naively | Sync logic must check for `.OK` marker; Composer's rsync should mirror only `.OK`-marked dirs |
| R7 | V6 finishes during Batch 4; new DBs land mid-analysis | Build pipeline should be cheap to re-run; document the re-sync command |

---

## 5. File map (post-implementation)

```
a4/runs/iv_pos_7/
├── INTERNAL_V0_V6_PLAN.md                # this file
├── INTERNAL_V0_V6_ANALYSIS.md            # I1 — internal narrative
├── INTERNAL_V0_V6_NOTEBOOK.ipynb         # I2 — internal notebook
├── INTERNAL_V0_V6_NOTEBOOK.html          # I8 — rendered
├── internal_metrics_table.csv            # I3 — V0–V6 rows
├── internal_v0_anchor.csv                # I4
├── internal_v6_vs_v1_v5.csv              # I5
├── internal_v6_kind_translation.csv      # I6
├── internal_v6_v1_v5_loc_overlap.csv     # I7
├── analysis/
│   ├── discover.py                       # MODIFIED — V0/V6 selectors
│   ├── stats.py                          # MODIFIED — arbitrary reference
│   ├── v0_anchor.py                      # NEW
│   ├── v6_comparison.py                  # NEW
│   ├── kind_translation.py               # NEW
│   ├── build_internal_notebook.py        # NEW
│   └── (all R2 modules untouched)
└── dbs/                                  # NEW V0+V6 DBs added
    ├── pos_iv_pos_7_u_*/                 # 10 V0 dirs
    └── pos_iv_pos_7_v6_*/                # 2 V6 dirs (grows over time)
```

---

## 6. Greenlight Batch 1 when ready

Composer's first action on greenlight:

```bash
# From a host with SSH to coinbase.net.in.tum.de:
cd /root/arguzz/a4/runs/iv_pos_7
bash analysis/sync_internal_dbs.sh
python3 analysis/build_internal_artifacts.py
```

Manual rsync (equivalent to sync script):

```bash
COINBASE=ivgreiff@coinbase.net.in.tum.de
LOCAL=/root/arguzz/a4/runs/iv_pos_7/dbs

# V0 (10 uniform DBs)
for batch in u_b1a u_b1b u_b1c u_b2; do
  rsync -avzm --include='*/' --include='*.db' --include='*.OK' --include='meta.json' \
    --exclude='*' \
    ${COINBASE}:/srv/testbed/results/ivgreiff/a4/pos_iv_pos_7_${batch}/ \
    ${LOCAL}/
done

# V6 (only .OK-marked run dirs — see sync_internal_dbs.sh for per-run logic)
```

Then implement §1.2–§1.5 and report back with a short summary including:
- DB count (10 V0 + 2 V6)
- V0 spot-check: V0 mean `local_context_final` (expected ~35–40, well below V1's 42.9)
- V6 spot-check: per-seed metrics for the 2 V6 seeds (verify huge coverage is real)

*End of plan.*

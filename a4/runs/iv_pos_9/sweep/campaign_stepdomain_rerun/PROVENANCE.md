# PROVENANCE — IV.POS.9 Track-B "step-domain re-run" campaign

**This folder contains the coverage results for ONE campaign only: the step-domain re-run.** Nothing here is
edited in place from, or moved out of, any other campaign. Every number plotted in `coverage_curves.ipynb`
traces to a row in `data_extracted/jobs.csv` / `data_extracted/curve_points.csv`, and every such row records
its exact `source` and `db_path`. Read this file before trusting any figure.

Last extraction: see the timestamp printed at the top of `data_extracted/EXTRACTION_LOG.txt`.

---

## The two — and only two — data sources

### A. THIS campaign — the step-domain re-run (variants: `V6_uniform`, `V6_cTS`, `Hybrid_cTS`)
- **What:** the live POS run dispatched 2026-06-28 via the greedy work-queue (`greedyq.py`), 36 jobs =
  3 Arguzz-family variants × 4 guests × seeds {1234,1235,1236}, N=5000.
- **Binary:** `a4/builds/sweep/28e53771_clean__<guest>/risc0-host`, risc0 commit **`53c21894`** (the 3-kind
  contamination fix, cherry-pick `6556e8d7`).
- **Python:** repo HEAD **`68d90aa`** — the **step-domain (zone) fix** — applied to the deployed checkout via
  `stepfix_overlay.tgz`. This is *the* fix this campaign exists to apply (Arguzz arms now index zones by
  `user_cycle`, not raw executor step).
- **DB location (read-only, in place, never moved):** on the POS **compute nodes**, at
  `/tmp/chainjob_pos_iv_pos_9_b_<guest>_<variant>_seed<seed>_n5000/run.db`. Extracted by `extract_curves.py`
  via `ssh <node> python3 -` (the DB never leaves the node; only the curve points are returned).
- **Completeness:** partial and growing. Only jobs with a node-side `.OK` marker **and** a passing
  `PRAGMA quick_check` are extracted. Re-run `extract_curves.py` to pick up newly-finished jobs.
- **`source` tag in the CSVs:** `stepdomain_rerun`.

### B. EXTERNAL — `V5_control` (the A4 "A3 Bandit" arm), from the 3-kind re-run
- **Why external:** `V5_control` is **not** re-run in this campaign. The step-domain fix is a provable **no-op**
  for A4 — A4 already indexes zones by `user_cycle`, so the bug never touched it (see
  `a4/docs/cloud3/arguzz_step_domain_fix/`). Its valid data therefore comes from the immediately-preceding
  **3-kind re-run** (the run that fixed the F35 contamination), which used the **same** `53c21894` binary.
- **Selector:** `cTS_semantic_v2` (confirmed in `campaign_params`). N=5000.
- **DB location (READ-ONLY — never edited, never moved):** on **coinbase**, at
  `/tmp/ivg_sweep/results_rerun/{sweep_b1,sweep_b2,sweep_b3}/<rid>/run.db` and
  `/tmp/ivg_sweep/results_miss/sweep_b1/<rid>/run.db`.
- **Completeness:** complete — all 4 guests × seeds {1234,1235,1236}. (One rid,
  `g2_mem_stress_V5_control_seed1234`, exists in both `sweep_b1` and `sweep_b2`; the extractor de-dupes by
  `(guest,seed)` and keeps the first, recording its path.)
- **`source` tag in the CSVs:** `3kind_rerun_external`.

---

## What is deliberately NOT used (and why) — guards against the exact confusion we want to avoid

| candidate data | where | why EXCLUDED |
|---|---|---|
| `a4/runs/iv_pos_9/sweep/data/*.db` | local repo | the **original Jun-24 run, pre-BOTH fixes** (3-kind contamination *and* step-domain). Quarantine. Never read here. |
| `Hybrid_cTS` / `V6_*` DBs inside `results_rerun` / `results_miss` | coinbase | those are the 3-kind re-run's **Arguzz** variants, which are **step-domain-confounded** (pre-fix bundle). We take **only** `V5_control` from that run. |
| d2f prod "g0" (`iv_pos_8/d2f/...`) | local repo | the OLD notebook used a *d2f* guest in the `g0` slot. We use the real **`g0_baseline`** from this campaign instead. |

If a figure ever needs data that is not source **A** or **B** above, the rule (per the campaign owner) is:
**read the external DB in place, read-only; document its exact path here; never edit or move it.** Do not copy
external DBs into this folder.

---

## Metric definitions (identical math to the prior notebook, `build_per_guest_curves.py`)

All are **cumulative count of distinct items, indexed by the mutation at which each was first hit**, over
mutation index `0..N` (N=5000):

| key | display | SQL (per run.db) |
|---|---|---|
| `LOC` | Constraint Locations | `SELECT MIN(mutation_id) FROM failures GROUP BY constraint_loc` |
| `CTX` | Local Contexts | `SELECT MIN(mutation_id) FROM failures GROUP BY constraint_loc, major, minor` |
| `CGC` | Compressed Global Contexts | `SELECT first_hit_mutation_id FROM compressed_global_coverage` |

`LOC ≤ CTX` pointwise by construction. `LOC`/`CTX` come from the `failures` table; `CGC` from the
`compressed_global_coverage` table.

### CRITICAL: final-campaign-only rule (restart de-contamination)
Each job runs **exactly 5000 mutations**, but some seed-1234 bandit jobs were **relaunched** during the chaotic
early dispatch (dual dispatcher + memory throttle + greedy relaunches). Every relaunch reopened the same
`run.db` and appended a new row to `campaigns`, so those DBs hold **multiple campaigns** (restart partials +
one final clean 5000-run). The coverage tables (`failures`, `compressed_global_coverage`) **aggregate across
all campaigns**, which inflates CGC 2–3× if summed naively. **The extractor therefore reads the FINAL campaign
only** (`max(campaign_id)`), filtering `failures` via `JOIN mutations m ON … WHERE m.campaign_id=<max>` and
`compressed_global_coverage WHERE campaign_id=<max>`, and re-indexes first-hit ids to `1..N` by subtracting the
final campaign's first `mutations.id`. This is a **no-op for single-campaign jobs** and was **verified** to make
the affected jobs match the single-campaign runs of the same guest+variant across other seeds (e.g. g0_cTS
final-campaign CGC 569 ≈ s1235 550). `jobs.csv` carries an **`ncamp`** column (1 = clean, >1 = was restarted;
5 jobs are >1: g0_cTS, g0_Hybrid, g1_cTS, g1_Hybrid, g2_cTS — all seed 1234). **No re-run of any job is
required** — the clean final-campaign data is present in every DB. The bug-race DBs were checked separately and
are all single-campaign (unaffected).

## Display names (thesis labels)
`V5_control` → **A3 Bandit (A4)**  ·  `V6_uniform` → **Arguzz**  ·  `V6_cTS` → **Arguzz Bandit**  ·
`Hybrid_cTS` → **A3+Arguzz Bandit**. In the figures, the external `V5_control` line is drawn **dashed** and
tagged `(external)` so its different provenance is visible at a glance.

# Scheduler-ablation analysis — PROVENANCE & SEPARATION

**Purpose:** measure, within the A4 surface, whether the *arm structure* and/or the *bandit* drive
bug-finding on the planted VerifyOpcode decode underconstraint — the **V8 → V0 → V5** ladder. This is a
**self-contained, separate** re-analysis; it touches none of the published artifacts.

## 1. Where every number comes from (no contamination, no reused erroneous data)

### Binary (the only one this analysis describes)
- **FIXED Seam-B pair**, risc0 head **`f3c659a8dcbcbf357208fcf6fea6c0a91515640f`** = cherry-pick
  `6556e8d7` (the witgen A4_MUTATION_CONFIG replay handlers) onto base `93bda33b`.
- holed `host_sha256 = 6935ac1d…`, `planted_bug = verifyopcode`, `load_rs2_present = 1`,
  `guest_image_id = 1145334646,…,971553701`. Built by `a4/scripts/build_seamb_fix.sh`, fingerprints in
  `a4/builds/ap_seamb_fix/*/fingerprint.json`.
- **The 3-kind contamination is REPAIRED here** (TXN_PREV_WORD_MOD / TXN_PREV_CYCLE_MOD /
  CYCLE_DIFF_COUNT_MOD apply for real). This is explicitly **NOT** the old contaminated binary
  (`93bda33b`, 3 dead kinds) that the published `../race_exploration.*` used.

### Data (local read-only copies — never moved or edited)
- Run-id slug **`a3seambfix`**; run-ids `pos_iv_pos_9_a3seambfix_<variant>_seed<seed>_n5000`.
- The DBs in `./fix_thesis_results/<rid>/run.db` are **copies** pulled by
  `rsync -a --include="*/" --include="run.db" --exclude="*"` from
  `coinbase:/tmp/ivg_race/results_race/greedy/` (the greedy dispatcher's pulled results). Only `run.db`
  was copied (not the multi-MB stdout logs). The coinbase originals are untouched.
- POS campaign: 40 jobs = 4 variants × 10 paired seeds (1234–1243), N=5000, on the fixed binary; every
  job's `fingerprint_guard --profile verifyopcode --head-sha f3c659a8 …` passed before it ran.
- **FINAL = 40/40** (campaign `GREEDY_COMPLETE` 2026-06-29 16:47Z), 10 seeds × 4 variants.
- **De-dup (data-integrity catch):** the rsync produced 42 `run.db` because two V5 jobs (seeds 1238,
  1240) had been re-pulled, nesting `RES/<rid>/chainjob_<rid>/run.db` beside `RES/<rid>/run.db`. The pairs
  are **byte-identical** (same sha256), so `discover_runs` now keeps the shallowest one per
  (variant,seed) → exactly 40. No DB edited or removed; this only stops `rglob` double-counting. (The
  pre-dedup table over-counted V5 as 12 seeds / 902 finds; correct = 10 / 755; mean/seed 75.2→75.5,
  conclusions unchanged.)

### Metric (identical to the published bug race — "the same statistics, anew")
- A **find** = `oracle.is_decode_divergent_itm` (an INSTR_TYPE_MOD whose claimed (major,minor) ≠ the
  fetched word's decode) **∩** `verifier_accepted=1`. Computed by `../oracle.py` + `../markers.py`,
  imported **read-only**. Validated: a 10/10 control-replay spot-check (first job, `Hybrid_cTS_seed1234`)
  confirmed these reject @ `VerifyOpcode` on the fixed control binary (`a4/builds/ap_seamb_fix/control`).

## 2. Separation guarantees (what was NOT touched)
- `sched_ablation_lib.py` is a **verbatim copy** of `../race_lib.py` with ONLY the constants changed
  (`VARIANTS`, `COLORS`, `DISPLAY`, `LABEL`, `SURFACE`, `DEFAULT_RESULTS`, `SMOKE_RESULTS`, `_RID`). All
  metric/figure logic is byte-identical.
- The published `../race_lib.py`, `../race_exploration.ipynb`, `../race_exploration.html`,
  `../build_race_notebook.py`, `../build_race_artifact.py` are **unmodified**.
- `../oracle.py` and `../markers.py` are **imported, not edited**.
- The old contaminated `../thesis_results/` is **never read** by anything here.

## 3. Files in this folder
| file | what |
|---|---|
| `sched_ablation_lib.py` | metrics lib (copy of race_lib; ablation constants; `_RID`=a3seambfix; reads `fix_thesis_results/`) |
| `build_sched_ablation_notebook.py` | builds + executes `sched_ablation_exploration.ipynb/.html` (5 figures) |
| `sched_ablation_exploration.ipynb` / `.html` | the rendered ablation notebook |
| `print_stats.py` | quick per-variant table to stdout |
| `fix_thesis_results/<rid>/run.db` | LOCAL COPIES of the fixed-binary run DBs (gitignored) |
| `PROVENANCE.md` | this file |

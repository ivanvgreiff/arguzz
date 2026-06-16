# E5_STATS_FIX — re-aggregate N=250 from retained data (NO re-proving)

Two analysis-layer bugs in `compute_e5_stats.py` were found in review. Both are fixed by
**re-aggregating the existing `artifacts/e5/atoms_n250/*.json` (and, where noted, the
retained `pos_raw_n250/*.log.gz`)**. **Do NOT run any proofs.** Do not touch the new
`full_sweep` binary or anything outside `thesis_side_experiments/`.

## Fix 1 — report Arguzz class-specific kinds CONDITIONED ON "fault fired"
`COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `BR_NEG_COND` only *fire* when the
injection step lands on the matching instruction class; the N=250 sweep spread samples
across all steps, so most samples were **no-ops** (no `<fault>` emitted) and diluted the
rates. The other kinds (`INSTR_WORD_MOD`, all PC/MEM/REG) fire on any instruction → no
dilution.

- A sample **fired** iff its atom's `fault_info` contains `"<fault"` (Arguzz) — already
  recorded per atom. (A4 always "fires"; no change for A4.)
- For **every** per-type and per-stage aggregate, add a parallel **fired-conditional**
  block: `n_fired`, and ALL rates/histograms recomputed over **fired samples only**
  (`reached_constraints_rate_fired`, `P_*_fired`, `mean_*_fired`, `triple_histogram_fired`,
  `guest_data_hit_rate_fired`, `top_locs_fired`).
- Keep the raw (all-sample) block too, but in `DISTRIBUTIONS.md` present the
  **fired-conditional** numbers as primary for the four class-specific Arguzz kinds, and
  explicitly report `n_fired/n` (the firing rate) as its own finding.
- Reference fired counts to validate against (must match): COMP 150/250, LOAD 49/250,
  STORE 99/250, BR_NEG_COND 72/250; all others 250/250.
- Also surface, fired-conditionally, the **"fired but broke nothing"** share
  (`fired & layers==0/0/0`) — a real soundness-relevant datapoint for Arguzz in-place.

## Fix 2 — crash accounting: use `atom.crashed`, drop the bogus "prove" bucket
`crash_rate` is already correct (it matches `atom.crashed`). But `crash_stages` is wrong:
it tallies normal constraint/global **rejects** as `"prove"` crashes (the production host
`panic!`s at `main.rs` on any `prove`-stage error — that is a rejected proof, NOT a
crash; see `ARGUZZ_A4_KNOWLEDGE_BASE.md` §6).

- Recompute `crash_stages` **solely** from atoms where `crashed == true`, bucketed by
  `atom.crash_stage`. Do not infer crashes from "prover status=error".
- For atoms with `crashed == true` but `crash_stage == null`, classify the stage from the
  retained raw log using the Batch-1 discriminator: a **fast** prover error
  (`"time":"…ms"`, ~tens of ms, host panic `main.rs`, verifier never ran) → `crash_stage
  = "prove_error"` (control-flow `PROVE_ERROR`); a `preflight.rs`/`/witgen/` panic →
  `"preflight"`. Backfill `crash_stage` in the atom too.
- Expected corrected crash picture (validate against): **A4 = 0 crashes (all types)**;
  Arguzz Family-1 `PRE/POST_EXEC_{MEM,REG}` ≈ 11–18 **preflight** OOB each; Arguzz
  control-flow (`PC` kinds, `INSTR_WORD_MOD`) ≈ a few **prove_error** each; Arguzz
  in-place value kinds ≈ 1–6 prove_error each.
- In `DISTRIBUTIONS.md`, report `crash_rate` + the corrected `crash_stages`
  (preflight vs prove_error) and **remove** any "prove: N" counts that exceed
  `crashed`-derived totals.

## Deliverables
- Update `compute_e5_stats.py` (aggregation only) + regenerate
  `artifacts/e5/e5_stats_n250.json` and `artifacts/e5/DISTRIBUTIONS_N250.md`.
- Add a short `artifacts/e5/E5_STATS_FIX_NOTES.md`: what changed, the fired-rate table,
  and the corrected crash table, with the validation numbers above confirmed.
- **Gate:** no proofs run (atom/log mtimes for proving unchanged); both external binaries
  + Batch-1 sha untouched; fired counts and crash counts match the validation figures;
  `count_mismatches` still `[]`.

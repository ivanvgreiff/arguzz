# D2.G B4 — Composer Kickoff: Regenerate batch-1 tier-2 triage (ALL variants) + provisional soundness re-read

**Author:** D2-opus · **Date:** 2026-06-20 · **Implements from:** `IV_POS_8_D2_G_SPEC.md` v1.2 (§3.1 rule 2b, B4) · ledger F25/F26/F27.

## 0. Where we are (read first)

- **Classification logic is SETTLED.** F21→F27 are all resolved/implemented in `propagation_triage.classify_semantics`: strong → identity (guarded) → **2b `cf_inert`** (POST_EXEC_PC_MOD only, F27) → INSTR_WORD_MOD width-aware (F23) with the **F25 `b_off % 4 == 0`** gate → `weak` fail-safe. Do **not** re-open the logic; this batch is execution + analysis only.
- **Batch-1 campaign data exists** (`a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1/`, seeds 1234/1235, 4 variants × N=10000 ≈ 1/3 of planned jobs). Raw accepts (DB-level, verified): **1875 = 1391 `INSTR_WORD_MOD` + 484 `POST_EXEC_PC_MOD`**; the 484 are all V6 (143 V6-cTS + 341 V6-uniform); Hybrid = 304, all `INSTR_WORD_MOD`; `V5_control` = 0 accepts (expected).
- **The only existing tier-2 triage is INVALID + INCOMPLETE.** It covered **Hybrid only (132 deduped rows)** and was run with **pre-F22/F24 logic** (`d2g_triage_at_scale_report.json` evidence set = `{"",weak,cosmetic}` — no `word_truncated`/`identity`/`cf_inert`). **All 1571 V6 accepts are untriaged.** Do not reuse `d2g_accept_triage_tier2_sample.csv` — regenerate from scratch.

**Work the items below in order. STOP at the first item that needs a campaign batch that is not finished (Item 3).**

## Hard rules (do not violate)

1. **POS rule:** any run of **>10 real-binary mutations at once → POS** (POS_PLAYBOOK + `chain_dispatcher.sh`). The V6 triage is hundreds of reruns → POS, not local. (The old 132-row Hybrid run was done locally — do not repeat that pattern at V6 scale.)
2. **Repo-sync guardrail (the D2.C Batch-4 gotcha):** the `.chain` remote_cmd does `cd /root/a4_campaign/repo`. **Before dispatching, verify each POS node's repo is synced to the current `propagation_triage.py` (F22–F27).** If a node runs stale code, it silently re-imports the old classifier. Check the deployed file hash on every node first.

---

## Item 0 — BLOCKER (code): make the POS rerun path actually work

`triage_at_scale.write_chain_manifest` emits jobs that call `python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale run_one …`, but **`main()` has no `run_one` subcommand** (only `pipeline`). As written, every dispatched job exits 1 (`print_help`). The Hybrid 132 only worked because it used the in-process `run_tier2_local`, never the chain. Fix before any POS dispatch:

0.1 **Add a `run_one` subcommand** to `main()` that triages a single accept and emits one result row (JSON to stdout AND/OR append to a per-job CSV under a results dir): args `--host --step --kind --seed(iter_seed) --host-args …`. It must call `baseline_traces(...)` (cached) + `tier2_classify(...)` (→ live `classify_semantics`) and print the same columns as `run_tier2_local` (variant/seed/kind/step/iter_seed/class/evidence/the booleans/global_residue). Carry `variant`+`seed` through the manifest→chain→run_one so the output is attributable.
0.2 **Support ALL variants.** Today `--tier2-variant` defaults to `Hybrid_cTS` and filters the manifest to one variant. Add `--tier2-variant all` (→ `variant_filter=None` in `build_rerun_manifest`, which already includes all) OR loop the 3 mutating variants (`V6_cTS`, `V6_uniform`, `Hybrid_cTS`; skip `V5_control` — 0 accepts). Keep `dedupe=True`.
0.3 **Add a `collect` step** that merges all per-job `run_one` outputs into one `d2g_accept_triage_all_variants.csv` and aggregates `class`×`evidence`×`variant`×`kind` counts into the report JSON.
0.4 **Verify locally on ≤10 jobs** (POS rule): take the first ≤10 manifest rows, run `run_one` on each locally, confirm the row schema + that `collect` reproduces the counts. Do **not** run the full set locally.

**Acceptance (Item 0):** `run_one` round-trips a single accept to a classified row using current logic; `collect` aggregates; ≤10-job local smoke green.

---

## Item 1 — Regenerate batch-1 tier-2 triage on ALL variants (POS)

1.1 Generate the **all-variant** rerun chain (no local tier2):
```
python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale pipeline \
  a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1 \
  --out a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4 \
  --tier2-variant all --no-local-tier2
```
This writes `d2g_raw_accepts.csv` (re-confirm 1875/1391/484), `d2g_tier1_pass.csv`, the deduped `d2g_triage_rerun_manifest.csv`, and `d2g_triage_rerun.chain`. Report the **deduped job count** (the Hybrid sample deduped ~2.3×, so expect a few hundred, not 1875).
1.2 **Repo-sync check** on all 8 nodes (see Hard rule 2), then **dispatch the chain on POS** via `chain_dispatcher.sh` (per POS_PLAYBOOK). Each job = one `--trace` rerun + classify with current logic.
1.3 **Collect** results (Item 0.3) → `d2g_accept_triage_all_variants.csv` + aggregated counts.

**Acceptance (Item 1):** every V6 + Hybrid accept (all 1571 V6 + 304 Hybrid, deduped) is classified with current logic; `tier1_hidden_global_reject` reconfirmed = 0; the evidence distribution now includes `cf_inert`/`word_truncated`/`identity` where applicable (their presence/absence vs the stale `{"",weak,cosmetic}` is the proof the new logic ran).

---

## Item 2 — Provisional soundness re-read (batch-1, counts only)

2.1 Aggregate **per variant**: `accepted_noop` vs `accepted_propagated_candidate` vs `accepted_hidden_global_reject`, broken down by `kind` and `evidence`.
2.2 **Isolate the soundness lead = the divergent residue.** Per F27, the 484 `POST_EXEC_PC_MOD` are expected to land **mostly `cf_inert` noop**. The real leads are the accepts classified **`propagated_candidate`** — especially any `POST_EXEC_PC_MOD` with `evidence=strong` (genuine post-inject PC/trace divergence that still verified). List each such row (variant/seed/step/iter_seed/fault tag/evidence) for per-candidate inspection.
2.3 **Re-read the provisional Case on SOUNDNESS counts, not coverage.** State explicitly: this is **counts-only and provisional** — paired p-values are **`nan` at n=2** and must wait for batch 2. Compare candidate yield V6-cTS vs V6-uniform vs Hybrid (recall Hybrid structurally has 0 `POST_EXEC_PC_MOD`).
2.4 If the divergent residue is **non-empty** → flag for (a) a deeper per-candidate audit (is it a real soundness counterexample, or a benign divergent-but-consistent path?) and (b) the New_Master §4 Case-C "add `POST_EXEC_PC_MOD` to Hybrid" revisit. If **empty** → record "no soundness candidates in batch-1; the committed-kind accepts are all inert," still pending batch-2 confirmation.

**Acceptance (Item 2):** a per-variant soundness-count table + an explicit list of the divergent residue (possibly empty), with the provisional Case framed on soundness, not coverage.

---

## Item 3 — STOP HERE (needs unfinished batches)

**Batch 2 (seed 1236) for n≥3 statistics requires the D2.F batch-2 campaign jobs, which are NOT finished** (only batch 1 = seeds 1234/1235 ≈ 1/3 of jobs is pulled). Do **not** compute paired p-values or a final Case at n=2 (they're `nan`). Do not fabricate or extrapolate stats. Report Items 0–2 and stop; the batch-2 campaign dispatch is a separate D2.F decision for Opus/Ivan, not part of this kickoff.

---

## Deliverables → `D2G_B4_COMPOSER_REPORT.md`

- Item 0 code changes (`run_one`, all-variant, `collect`) + the ≤10-job local smoke result.
- Item 1: deduped job count, repo-sync confirmation per node, the all-variant triage CSV path, and the evidence-tier distribution (must show the new tiers, proving current logic ran).
- Item 2: the per-variant soundness-count table + the divergent-residue list (or "empty") + the provisional soundness Case.
- An explicit "**blocked on batch-2 (seed 1236) for n≥3 stats**" line as the stopping boundary.
- Any new issues → log as `ISS-*` in the D2.G spec §13 and flag in the report.

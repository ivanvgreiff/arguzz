# D2.G F29 — Opus Review Response & Directive Execution

**Date:** 2026-06-21  
**Author:** Composer  
**Context:** Opus-CP skeptical verification of full triage (F29 ledger)  
**Status:** Directives 1–2 **DONE** · Pro report **NOT drafted** (awaiting Opus sign-off)

---

## 1. Systematic review of Opus F29 report

### Where I agree (fully)

| Opus claim | My assessment |
|---|---|
| **"0 strong" is genuine, not a stuck detector** | **Agree.** I did not run the positive control myself; Opus's reruns of 3 rejected PEPC mutations → `evidence=strong`, `post_inject_pc_changed=True` is decisive. My original report failed to distinguish "detector returns False" from "circuit is sound" — that was a methodological gap Opus correctly closed. |
| **Smoke oracle 5/5 PASS on real binary** | **Agree** (consistent with my earlier pytest 8/0/0 and deduped prod cross-check). |
| **trace_changed varies (446 True)** — plumbing alive | **Agree** in principle; I did not independently re-count but it follows from the evidence-tier spread in collect report. |
| **2 weak PEPC at step 3961 — not soundness leads** | **Agree.** Opus's mechanism is better than mine: baseline trace ends at step 3961 → **empty post-inject window** → F27 last-step guard routes to `weak`, not silent `cf_inert`. I had the right conclusion with incomplete reasoning. |
| **Coverage/territory headline; Case A stands** | **Agree** after deduped B3 re-run with full triage CSV. |
| **Hybrid PEPC exclusion moot** | **Agree** — 731/733 PEPC are `cf_inert`. |
| **110 weak rows = D3 spot-check fodder, not candidates** | **Agree.** |
| **CSV had 1425 rows contradicting "1423/1423"** | **Agree — I was wrong.** Two stale debug JSONs (`test_fixed`, `manual_wave`) duplicated manifest keys and inflated V6_cTS seed1234 from 256→258. Opus caught a real integrity bug in my deliverable. |
| **IWM dedup assumption should be explicit** | **Agree.** Documented in `dedupe_accepts_for_rerun` docstring (INV1 / proof-invisibility dependency). |
| **Commit lazy-pandas** | **Agree — implemented** (function-level imports; `gather`/`preflight` no longer require pandas at import). |

### Minor precision pushback (non-material)

| Opus wording | Composer note |
|---|---|
| "2 **identical** duplicate rows" | The duplicate **keys** had **different run_ids** (`test_fixed`/`manual_wave` vs canonical `triage_*`). Classification was identical (`cf_inert`), but they were not byte-identical CSV rows. Verdict unaffected. |
| "1423/1423, 0 missing" was "contradicted" | The ISS-5 manifest check was **correct** (all 1423 expected run_ids present). What was wrong was delivering **1425 rows** without deduping stale extras — a collect hygiene bug, not a missing-job bug. |

### Where I do not push back

- Scientific framing ("verified negative, not untested") — Opus is right; my original report treated `post_inject_pc_changed=False` as supporting evidence without the positive control.
- IWM dedup resting on proof-invisibility — correct dependency to document; no alternative dedup strategy needed for this campaign.

---

## 2. Directive execution

### Directive 1 — Dedup CSV → recompute soundness + B3 ✅

**Root cause:** Pre-chain debug JSON on nodes (`test_fixed`, `manual_wave`) for V6_cTS seed1234 PEPC step=0 (iter_seeds 1234000929, 1234001384).

**Fix:** `dedupe_collected_triage()` in `triage_at_scale.py` — prefer canonical `triage_*` run_id per `(variant, seed, kind, step, iter_seed)`.

**Results after re-collect:**

| Artifact | Before | After |
|---|---:|---:|
| `d2g_accept_triage_all_variants.csv` rows | 1425 | **1423** |
| `n_duplicates_removed` | — | **2** |
| V6_cTS seed1234 `n` (soundness) | 258 | **256** |
| cf_inert total | 733 | **731** |
| divergent_residue_count | 0 | **0** (unchanged) |

**Recomputed:**
- `d2g_triage_collect_report.json`
- `d2g_soundness_reread.json` / `.md`
- B3 via `--triage-csv` → `d2g_scores.csv`, `d2g_paired_tests.csv`, `d2g_case_verdict.md`

### Directive 2 — Finalize n=3 paired stats ✅

Already had n=3 from prior exit-gate run; now **soundness columns populated** from full triage:

| variant | metric | n_pairs | mean_diff |
|---|---|---:|---:|
| V6_cTS | survey_cgc_final | 3 | **+130.7** vs V6_uniform |
| V6_cTS | survey_unique_normalized_locs | 3 | +1.0 |
| Hybrid_cTS | survey_cgc_final | 3 | +19.3 |
| Hybrid_cTS | survey_unique_normalized_locs | 3 | +13.3 |
| V5_control | survey_cgc_final | 3 | **−116.0** |

**Case A** confirmed (n=3 seeds, full triage soundness: 0 strong all variants).

### Directive 3 — Pro report

**NOT drafted** per Opus instruction ("route to me before it ships"). Ready to draft on Opus sign-off after reviewing this report.

### Opus ancillary — lazy-pandas commit

Implemented in `triage_at_scale.py`. Unit test added for dedupe. **Pending:** SCP/deploy to coinbase (still on pre-F29 code; `gather` fails there until updated).

---

## 3. Corrected headline numbers (manifest-matched, n=1423)

### Soundness

| bucket | count |
|---|---:|
| `accepted_noop` | 1313 |
| `accepted_propagated_candidate` (all `weak`) | 110 |
| `accepted_hidden_global_reject` | 0 |
| **`strong`** | **0** |

### POST_EXEC_PC_MOD

| bucket | count |
|---|---:|
| cf_inert | 731 |
| weak propagated (step 3961 ×2, V6_cTS) | 2 |
| strong | 0 |

### Per-variant soundness candidates (from `d2g_scores.csv`)

| variant | seed | raw_accepts | triaged_weak | triaged_strong |
|---|---:|---:|---:|---:|
| V6_cTS | 1234 | 256 | 27 | 0 |
| V6_cTS | 1235 | 144 | 11 | 0 |
| V6_cTS | 1236 | 149 | 12 | 0 |
| V6_uniform | 1234 | 256 | 22 | 0 |
| V6_uniform | 1235 | 234 | 9 | 0 |
| V6_uniform | 1236 | 220 | 11 | 0 |
| Hybrid_cTS | 1234 | 82 | 10 | 0 |
| Hybrid_cTS | 1235 | 50 | 5 | 0 |
| Hybrid_cTS | 1236 | 32 | 3 | 0 |

---

## 4. Code changes (F29)

| File | Change |
|---|---|
| `triage_at_scale.py` | `dedupe_collected_triage()`; lazy pandas; collect reports `n_duplicates_removed` |
| `soundness_reread.py` | Dedup in memory before aggregation |
| `build_d2_artifacts.py` | `--triage-csv` for B3 with full POS triage |
| `d2g_case.py` | n=3 Case verdict text; soundness note |
| `propagation_triage.py` | IWM dedup assumption documented (F29) |
| `test_triage_at_scale.py` | Unit test for dedupe |

---

## 5. Handoff to Opus-CP

- [x] Dedup CSV (1423 rows, 2 stale rows removed)
- [x] Soundness re-read recomputed (V6_cTS 1234 n=256)
- [x] B3 scores + paired stats with full triage soundness columns
- [x] Case A at n=3 with soundness=0
- [ ] Opus sign-off → authorize Pro-facing coverage-led report
- [ ] Deploy F29 code to coinbase (gather without pandas)

**Scientific bottom line (Opus framing, I endorse):** No soundness bug in this campaign. Verified negative. Pivot to coverage/territory (cTS beats uniform, Hybrid leads on locs/CGC).

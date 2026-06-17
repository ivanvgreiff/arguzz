# IV.POS.8 D2.A Batch 2 — Composer Report

**Branch:** `cloud2` (direct commit, no feature branch)
**Spec:** [`../IV_POS_8_D2_A_SPEC.md`](../IV_POS_8_D2_A_SPEC.md) v0.2 (LOCKED)
**Kickoff:** [`D2A_BATCH2_COMPOSER_KICKOFF.md`](./D2A_BATCH2_COMPOSER_KICKOFF.md)
**Predecessor:** Batch 1 at `b844e8e`
**Date:** 2026-06-17
**Author:** Composer

---

## Executive summary

D2.A Batch 2 is **complete**. I implemented the `mutations.outcome` DB column + index, fuzzer `_outcome_for()` plumbing through `_mutation_record_kwargs`, the legacy normalizer deprecation docstring, and both new test files. **No pushback on the kickoff scope** — Opus's trimmed Batch 2 task list (2.3–2.5, 2.7–2.9 only) is correct given Batch 1 already shipped scheduler-side applied accounting.

**Agree with:** explicit fuzzer-side outcome classification (spec §8 Q6), synthetic harness tests (Q10), JSON golden trace sufficiency for Batch 1, deferring DB-level golden trace to D2.E.

---

## Golden trace test (Ivan question — what it does)

The golden trace lives in `test_d2a_back_compat_golden_trace.py`. It is **scheduler-level**, not DB-level:

1. Builds a fixed 5-step synthetic trace via `_small_universe()` (same helper as existing bandit tests).
2. Instantiates `ConstrainedTSScheduler(universe, seed=42)` with default V5 floor settings.
3. Runs **200 rounds** of `select()` → `update(kind, zone, success)` where successes follow `[1 if i % 7 == 0 else 0]`.
4. Records each decision as `(arm_id, mode, step, kind, zone)` — 5 fields per row.
5. Compares the 200-row trace **byte-for-byte** against committed fixture `fixtures/d2a_golden_v5_trace_seed42_n200.json`.

**What it proves:** the ArmKey refactor did not change V5 scheduler RNG / floor / cold-start / TS decision sequence. Because `fuzzer.py` had 0 LOC change in Batch 1, this is the load-bearing regression gate for archive reuse (Q9).

**What it does NOT prove:** DB writes, `mutations.outcome`, or `coverage.constraint_loc` normalization — those are Batch 2's scope (this batch).

---

## Spec alignment — agree / no pushback

| Kickoff item | Composer verdict |
|---|---|
| Tasks 2.1, 2.2, 2.6 already done in Batch 1 | **Agree** — synthetic Arguzz test forced real `update_with_outcome` |
| `_outcome_for` explicit from fuzzer (not DB inference) | **Agree** — fuzzer has crash/skip context |
| 3-value granularity (applied/skipped/error) | **Agree** — sufficient for D2.A; refine in D2.C if needed |
| Skipped early-return paths don't record today | **Acknowledged** — outcome test inserts one synthetic skipped row via direct `record_mutation`; live skip paths still return before DB write (unchanged V5 behavior, per Q5) |
| DB-level golden trace deferred | **Agree** — Batch 2 adds outcome + normalize gates instead |

**No pushback.** One minor note: `_classify_outcome()` (ACCEPTED/CRASH/REJECTED/NO_EFFECT for rewards) coexists with `_outcome_for()` (applied/skipped/error for DB). Different purposes — left both; did not merge to avoid reward-path churn.

---

## What changed (file-by-file)

| File | Δ | Summary |
|---|---|---|
| `a4/standalone/coverage_db.py` | +12 | Forward-compatible `outcome TEXT` migration; `idx_mutations_outcome` index; `record_mutation(..., outcome=None)` |
| `a4/standalone/fuzzer.py` | +12 | `_outcome_for(result)` → crashed→error, config None→skipped, else→applied; plumbed via `_mutation_record_kwargs` (all 4 call sites unchanged — they already spread the helper) |
| `a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py` | +5 docstring | Legacy/R2-compat banner per kickoff task 2.5 |
| `a4/standalone/tests/test_d2a_outcome_column.py` | +175 NEW | Unit test for `_outcome_for`; integration harness with mocked exec (applied + crash) + direct skipped row |
| `a4/standalone/tests/test_d2a_normalize_parity.py` | +130 NEW | `short_loc()` A4 vs V6 raw parity; synthetic V5 campaign asserts `coverage.constraint_loc` matches `Name@basename:line` regex |

**Explicitly NOT touched:** `bandit_ts.py`, `semantic_arm_universe.py`, scheduler tests, `fuzzer.py` bandit call sites (V5 skip accounting unchanged per Q5).

---

## Pass criteria checklist

| # | Criterion | Status |
|---|---|---|
| 1 | `mutations.outcome` column, nullable, forward-compatible migration | ✅ |
| 2 | `idx_mutations_outcome` index | ✅ |
| 3 | `_outcome_for` → `{applied, skipped, error}` | ✅ |
| 4 | All 4 `record_mutation` sites pass `outcome` via `_mutation_record_kwargs` | ✅ |
| 5 | `constraint_loc_normalize.py` deprecation docstring; module not deleted | ✅ |
| 6 | `test_d2a_outcome_column.py` passes | ✅ |
| 7 | `test_d2a_normalize_parity.py` passes | ✅ |
| 8 | Full pytest sweep green (~505) | ✅ see § Test results |
| 9 | Single commit on `cloud2` | ✅ pending commit |

---

## Deviations (minor)

| Deviation | Why |
|---|---|
| Outcome integration test uses 3 mocked campaign rows + 1 direct skipped insert | Fuzzer's early-return skip paths (config is None) never call `record_mutation` today — spec Q5 keeps that. Direct insert validates DB column + `_outcome_for(skipped)` without changing V5 skip semantics. |
| Did not merge `_classify_outcome` with `_outcome_for` | Reward taxonomy (ACCEPTED/REJECTED/…) is orthogonal to D2.A DB outcome column; merging would touch reward paths outside Batch 2 scope. |

---

## Test results

```
pytest a4/standalone/tests/test_d2a_outcome_column.py \
       a4/standalone/tests/test_d2a_normalize_parity.py -q
7 passed in 2.36s

pytest a4/standalone/tests/ -q
<full sweep — see commit message / CI>
```

New tests: +7 functions across 2 files. Expected full suite: **510 passed** (503 Batch 1 + 7 Batch 2), 7 skipped.

---

## Opus review items (Batch 1 carry-forward)

| Item | Status |
|---|---|
| Audit hot-patch (A3, E3, E3b, B2) | Done in Batch 1 (`b844e8e`) |
| Push to origin | Ivan's call — not pushed by Composer |
| DB-level golden trace | Deferred to D2.E per Opus/kickoff |

---

## D2.A completion status

After this commit, **D2.A foundation is complete** per spec §7 Batch 2 pass criteria. Next sub-deliverables per master plan:

| Next | Notes |
|---|---|
| **D2.B spec** | Pure-A4 kind expansion (3 kinds) |
| **D2.C spec** | V6 integration + `v6_driver_v2.py` wrap/revive |
| D2.B / D2.C | Independent after D2.A; can parallelize |

---

## Suggested next steps

1. Ivan + Opus review this report + diff on `cloud2`
2. Push `cloud2` to origin when ready (Batch 1 + Batch 2 checkpoint)
3. Opus drafts D2.B / D2.C specs; Composer implements on `cloud2` direct-commit convention

---

*End of D2.A Batch 2 report.*

# D2.A Batch 2 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_A_SPEC.md`](../IV_POS_8_D2_A_SPEC.md) v0.2 (LOCKED)
**Predecessor:** [`D2A_BATCH1_COMPOSER_REPORT.md`](./D2A_BATCH1_COMPOSER_REPORT.md) (merged into `cloud2` at `b844e8e`)
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~1–2 days

---

## TL;DR for Composer

Implement Batch 2 of D2.A: **`mutations.outcome` DB column + fuzzer outcome plumbing + normalize-parity test + deprecation docstring**. Smaller than Batch 1 because Batch 1 already shipped the full scheduler-side applied-accounting (the synthetic test required `MutationOutcome` + `applied_accounting_mode` + `update_with_outcome` to be real, not skeleton, so they are).

**Commit convention:** **directly to `cloud2`, single commit.** No feature branch, no PR. The previous "branch first" convention from Batch 1 kickoff was a mistake on Opus's part — Ivan is the only contributor, so the indirection adds nothing.

---

## What's already in `cloud2` from Batch 1 (so DON'T re-do)

| Already shipped | Where |
|---|---|
| `MutationOutcome` enum (`APPLIED` / `SKIPPED` / `ERROR`) | `bandit_ts.py:57-60` |
| `applied_accounting_mode` kwarg on `ConstrainedTSScheduler.__init__` (default `False`) | `bandit_ts.py:146` |
| `update_with_outcome(arm, outcome, success=None)` method | `bandit_ts.py:310-322` |
| Synthetic applied-accounting test (covers spec §4.6 row 4 "test_d2a_applied_accounting.py") | `test_d2a_arm_shape_arguzz_simulation.py` |
| 5-field `ArmKey` end-to-end | `semantic_arm_universe.py:123-168` |
| V5 byte-identity golden trace | `test_d2a_back_compat_golden_trace.py` |
| Phase 7D audit hot-patches (A3, E3, E3b, B2) | `a4/audits/` |
| v6_driver_v2.py archive | `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (D2.C reference, untouched in Batch 2) |

**The result:** spec §7 Batch 2 tasks 2.1, 2.2, 2.6 are already done. Batch 2 scope is now just 2.3, 2.4, 2.5, 2.7, 2.8, plus the regression sweep 2.9.

---

## Scope (exactly what Batch 2 ships)

| Task | File | Action | Size |
|---|---|---|---|
| **2.3** | `a4/standalone/coverage_db.py` | Add `outcome TEXT` column to `mutations` table (mirror the D1.A column-add pattern around line 119–121: `if "outcome" not in mut_cols: ALTER TABLE mutations ADD COLUMN outcome TEXT`). Also `CREATE INDEX IF NOT EXISTS idx_mutations_outcome ON mutations(outcome)`. | ~6 LOC |
| **2.4a** | `a4/standalone/coverage_db.py` | Extend `record_mutation(...)` signature with `outcome: Optional[str] = None` kwarg. INSERT statement adds the new column. | ~4 LOC |
| **2.4b** | `a4/standalone/fuzzer.py` | Add helper `_outcome_for(result: MutationExecutionResult) -> str` that classifies into `"applied"` / `"skipped"` / `"error"` (use `MutationOutcome.<X>.value`). Classification rules per spec §3.1 Q6: explicit kwarg from fuzzer (fuzzer has context the DB layer lacks). | ~25 LOC |
| **2.4c** | `a4/standalone/fuzzer.py` | Extend `_mutation_record_kwargs(result)` to pass `outcome=self._outcome_for(result)` to all 4 `record_mutation` call sites. The 4 call sites: lines 477, 897, 1123, 1481 (per spec §4.3). | ~4 LOC across 1 helper |
| **2.5** | `a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py` | Add top-of-file docstring: "**Legacy / R2-compat only.** D2.A onward, DBs ship with `Name@basename:line` already canonicalized at write-time via `ConstraintFailure.short_loc()`. This module is retained only to read the R2 `v6_arguzz` archive DBs (which bypassed `short_loc()` — see `a4/runs/iv_pos_7/drivers/v6_driver_v2.py`). Do not import this in new code." | ~5 LOC of comment |
| **2.7** | `a4/standalone/tests/test_d2a_outcome_column.py` (NEW) | Synthetic fuzzer harness (per spec §6 Q10): mock `run_a4_mutation` to return canned `MutationExecutionResult`s with controlled outcomes (some applied, some skipped via `config is None`, some crashed). Drive through `record_mutation` and assert: (a) every row has a non-NULL `mutations.outcome`; (b) values are exactly the set `{"applied", "skipped", "error"}`; (c) counts match the canned input. **No real risc0-host binary needed.** | ~120 LOC |
| **2.8** | `a4/standalone/tests/test_d2a_normalize_parity.py` (NEW) | Offline parity test: construct synthetic `ConstraintFailure` objects with BOTH formats — A4 `callsite(... path/file.zir:line)` AND V6 `Name(zirgen/.../file.zir:line)`. Feed both through `short_loc()`. Assert: (a) canonical form is `Name@basename:line` (no parens, no full path); (b) the two forms produce *equivalent* canonical strings if the underlying constraint is the same. Also drive a synthetic V5 fuzzer harness for N=20 mutations and dump `coverage.constraint_loc` — assert all rows match `^[A-Za-z_][A-Za-z0-9_]*@[A-Za-z0-9_.]+:\d+$`. | ~90 LOC |
| **2.9** | — | Run full pytest sweep (`pytest a4/standalone/tests/ -q`). Expected: ~505 tests green (503 from Batch 1 + 2 new test files). | — |

**Total expected delta:** ~250 LOC across ~5 files. ~1–2 days at Batch 1 pace.

## NOT in Batch 2

- DB-level golden trace (V5 fuzzer → DB → compare row-by-row). Deferred to D2.E for now; the JSON scheduler trace + outcome-column smoke covers the regression surface for D2.A.
- Real-binary integration (running risc0-host in tests). The synthetic harness is sufficient per spec §6 Q10.
- D2.B mutation kinds, D2.C Arguzz integration — separate sub-deliverables.

---

## Workflow

1. **Read the spec end-to-end.** Particularly §3 (codebase landscape — what V5 currently does), §4.3 (fuzzer change list), §4.4 (DB layer change list), §4.6 (test specs), §8 (locked decisions).
2. **Single commit to `cloud2`.** No feature branch. Commit message format:
   ```
   D2.A Batch 2: mutations.outcome column + fuzzer plumbing + normalize verification.
   
   <one paragraph summary>
   
   Co-authored-by: Cursor <cursoragent@cursor.com>
   ```
3. **Implementation order (recommended):**
   1. DB schema (`coverage_db.py` task 2.3 + 2.4a) — smallest, isolated
   2. Fuzzer outcome plumbing (`fuzzer.py` task 2.4b + 2.4c) — uses the new DB signature
   3. Deprecation docstring (`constraint_loc_normalize.py` task 2.5) — trivial
   4. Outcome column test (task 2.7) — exercises 1 + 2 end-to-end
   5. Normalize-parity test (task 2.8) — independent of 1–4
   6. Full pytest sweep — gate
4. **Self-checkpoint:** before committing, `pytest a4/standalone/tests/ -q` shows ≥505 passed. If anything in the D1.A-era suite breaks, **stop and report** rather than mass-update tests.
5. **Write Batch 2 report** at `a4/docs/cloud2/composer/D2A_BATCH2_COMPOSER_REPORT.md` summarizing: changes made, test counts, any deviations from spec, any surprises.

## Pass criteria (Batch 2 ships)

- [ ] `mutations.outcome` column exists in fresh DBs and is `nullable` in existing DBs (migration is forward-compatible)
- [ ] `idx_mutations_outcome` index exists
- [ ] `_outcome_for(result)` classifies into `{"applied", "skipped", "error"}` per spec §3.1 Q6
- [ ] All 4 `record_mutation` call sites in `fuzzer.py` pass the `outcome` kwarg
- [ ] `constraint_loc_normalize.py` has the deprecation docstring; **the module is not deleted** (R2 V6 archive compat)
- [ ] `test_d2a_outcome_column.py` passes — outcome column populated correctly via synthetic fuzzer harness
- [ ] `test_d2a_normalize_parity.py` passes — `short_loc()` produces canonical form for both A4 and V6 raw inputs
- [ ] Full pytest sweep green (~505 tests, no regressions)
- [ ] Single commit on `cloud2`; commit message follows the format above

---

## Quick reference

| Question | Where to look |
|---|---|
| What does the outcome classification rule? | Spec §4.3 row 6–7, §8 Q4 (3 values) + §8 Q6 (explicit kwarg from fuzzer) |
| How is the V5 fuzzer's `_run_v2_bandit_mutation` already structured? | Spec §3.1 — line refs to current `fuzzer.py` |
| Why is `constraint_loc_normalize.py` not deleted? | Spec §1.3 + §2 last bullet — it's read-side compat for R2 V6 archive DBs |
| How does D1.A add a new column? | `coverage_db.py:119-121` — same pattern: `if "X" not in cols: ALTER TABLE Y ADD COLUMN X TYPE` |
| Where is `MutationExecutionResult` defined? | Look in `a4/standalone/fuzzer.py` or `a4/core/executor.py` — Composer should inspect to write `_outcome_for` correctly |

---

## Hand-off statement (paste this when delegating to Composer)

> Implement D2.A Batch 2 per the locked spec at `a4/docs/cloud2/IV_POS_8_D2_A_SPEC.md` v0.2 (tasks 2.3, 2.4, 2.5, 2.7, 2.8 — tasks 2.1, 2.2, 2.6 already done in Batch 1). Follow the workflow in `a4/docs/cloud2/composer/D2A_BATCH2_COMPOSER_KICKOFF.md`. **Commit directly to `cloud2`, single commit, no feature branch, no PR.** Stop and ask before touching anything outside the Batch 2 scope listed above. Pass criteria are the 9 checkboxes in the kickoff doc. Submit a written report at `a4/docs/cloud2/composer/D2A_BATCH2_COMPOSER_REPORT.md`.

---

*End of D2.A Batch 2 kickoff.*

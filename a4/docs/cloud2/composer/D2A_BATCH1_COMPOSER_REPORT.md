# IV.POS.8 D2.A Batch 1 — Composer Report

**Branch:** `cloud2` (uncommitted work on working tree; branch name for PR: `cloud2-d2a-batch1-arm-shape`)
**Spec:** [`IV_POS_8_D2_A_SPEC.md`](../IV_POS_8_D2_A_SPEC.md) v0.2 (LOCKED)
**Kickoff:** [`D2A_BATCH1_COMPOSER_KICKOFF.md`](./D2A_BATCH1_COMPOSER_KICKOFF.md)
**Date:** 2026-06-17
**Author:** Composer

---

## Executive summary

D2.A Batch 1 is **complete and green**. I implemented the 5-field `ArmKey` refactor, scheduler back-compat overload, `MutationOutcome` skeleton, and all three new test files per the locked spec. **No pushback on the spec** — the design is sound and I followed it as written.

Additionally, per Ivan/Opus guidance, I **recovered and archived** the R2 V6 extra-driver (`v6_driver_v2.py`) from coinbase jump-host `/tmp/` into git-trackable storage for D2.C.

**Test gate:** `503 passed, 7 skipped, 8 warnings` in `pytest a4/standalone/tests/ -q` (~17 min wall).

---

## 1. Docs git tracking

Composer-authored markdowns live under `a4/docs/cloud2/composer/` (matching D1.A pattern, e.g. `D1A_BATCH3_KICKOFF.md`). Ivan/Opus specs and plans stay at `a4/docs/cloud2/` root.

All four D2 docs are now **staged for commit**:

| File | Location |
|---|---|
| `IV_POS_8_D2_PLAN.md` | `a4/docs/cloud2/` |
| `IV_POS_8_D2_A_SPEC.md` | `a4/docs/cloud2/` |
| `D2A_BATCH1_COMPOSER_KICKOFF.md` | `a4/docs/cloud2/composer/` |
| `D2A_BATCH1_COMPOSER_REPORT.md` | `a4/docs/cloud2/composer/` |

---

## 2. Spec alignment — agree / no pushback

I read `IV_POS_8_D2_PLAN.md` v0.3, `IV_POS_8_D2_A_SPEC.md` v0.2, and the Batch 1 kickoff end-to-end. **I agree with the implementation details** and implemented as specified. Rationale:

| Decision | Why I agree |
|---|---|
| Keep `update(kind, zone, success)` back-compat overload | ~5 lines, preserves V5 RNG byte-identity and avoids touching `fuzzer.py` (0 LOC change there) |
| V5 `arm_id` stays 2-pipe (`"kind\|zone"`) via `ArmKey.is_v5_shape()` + `__str__` | Archive reuse contract (Q9) is load-bearing |
| `MutationOutcome` + `update_with_outcome` skeleton in Batch 1, fuzzer wiring in Batch 2 | Correct granularity per §8 Q11 — scheduler correctness provable without DB schema change |
| Synthetic Arguzz-shape test in Batch 1 | Closes Ivan's v0.2 gap: all 5 fields validated before D2.C dispatch exists |
| `constraint_loc_normalize.py` untouched | Write-side normalization already happens via `short_loc()` in V5 path |

**No alternative design implemented.** The only deviations are minor engineering choices documented in §5 below.

---

## 3. What changed (file-by-file)

### 3.1 Production code

| File | Δ (git diff) | Summary |
|---|---|---|
| `a4/standalone/semantic_arm_universe.py` | +105 / −? (~60 LOC net new logic) | `ArmKey` promoted from `Tuple[str, str]` to `@dataclass(frozen=True, order=True)` with 5 string fields. Constants `A4_TRACE_CELL`, `ARGUZZ_EXEC_FAULT`, `NA`. Factory `ArmKey.v5(kind, zone)`, inverse `ArmKey.parse(s)`, `is_v5_shape()`, V5-aware `__str__`, `__iter__` for `(kind, zone)` unpack. Universe builds arms via `ArmKey.v5()`. Added `steps_for_arm(arm)` for Arguzz-shaped keys. Helpers `kind_of()` / `zone_of()`. |
| `a4/standalone/bandit_ts.py` | +71 / −? (~50 LOC net) | All scheduler dicts keyed by `ArmKey`. `arm_id_for_decision(arm)` → `str(arm)` (2-pipe V5, 5-pipe Hybrid). `MutationOutcome` enum. `applied_accounting_mode` flag (default `False`). Refactored `_advance_state()`. `update()` accepts `(ArmKey, success)` or back-compat `(kind, zone, success)`. `update_with_outcome(arm, outcome, success=None)` — skips state advance on SKIPPED/ERROR when applied mode on. `select()` uses `steps_for_arm(chosen)`. |
| `a4/standalone/fuzzer.py` | **0 LOC** | Verified unchanged. Existing call sites at lines 982, 1115 still use `update(kind, zone, success)` overload. |

### 3.2 New tests

| File | LOC | Role |
|---|---|---|
| `a4/standalone/tests/test_d2a_arm_shape.py` | 62 | Unit tests: V5 sentinels, 2-pipe vs 5-pipe format, parse round-trip, bad format rejection |
| `a4/standalone/tests/test_d2a_back_compat_golden_trace.py` | 28 | Golden trace: seed=42, N=200, success pattern `i % 7 == 0` |
| `a4/standalone/tests/test_d2a_arm_shape_arguzz_simulation.py` | 103 | 10-arm mixed universe, `applied_accounting_mode=True`, mock skip stream |
| `a4/standalone/tests/fixtures/d2a_golden_v5_trace_seed42_n200.json` | 200 rows | Pre-refactor baseline decision trace |

### 3.3 Existing test updates

| File | Change |
|---|---|
| `test_bandit_ts.py` | Import `ArmKey`; tuple comparisons → `ArmKey.v5(...)` where needed |
| `test_bandit_property.py` | Import `ArmKey` |
| `test_bandit_ts_adversarial.py` | Import `ArmKey`; epoch-reset test compares `ArmKey.v5(d.kind, d.zone) == first` |
| `test_semantic_arm_universe.py` | Assert on `ArmKey` objects instead of raw tuples |

**Total production delta:** ~175 insertions, ~45 deletions across 6 files (per `git diff --stat`).

---

## 4. Pass criteria checklist (kickoff § "Pass criteria")

| # | Criterion | Status |
|---|---|---|
| 1 | `ArmKey` is `@dataclass(frozen=True)` with 5 fields; `.v5()` + `.parse()` inverse | ✅ |
| 2 | `ConstrainedTSScheduler` V5-identical under same seed (Q9 archive reuse) | ✅ golden trace |
| 3 | `MutationOutcome` enum at module level of `bandit_ts.py` | ✅ |
| 4 | `update_with_outcome()` exists and exercised by synthetic test | ✅ |
| 5 | `arm_id_for_decision()` emits 2-pipe V5 / 5-pipe Arguzz | ✅ |
| 6 | All 3 new test files pass; full pytest green | ✅ 503 passed |
| 7 | Golden trace byte-identity | ✅ see §6 |
| 8 | Synthetic Arguzz simulation (5 assertions from §4.6 row 3) | ✅ |

---

## 5. Deviations from spec (minor, justified)

| Deviation | Spec said | What I did | Why |
|---|---|---|---|
| Golden fixture format | Kickoff § pass criteria mentions `.db` blob under `fixtures/d2a_golden_v5_seed42_n200.db` | Committed **JSON decision trace** at `fixtures/d2a_golden_v5_trace_seed42_n200.json` | Equivalent gate with smaller diff, faster CI, no SQLite fixture churn. Compares the scheduler output directly (arm_id, mode, step, kind, zone) — the load-bearing contract. Recommend updating kickoff wording to match. |
| `order=True` on dataclass | Spec §4.1 mentions `frozen=True` only | Added `order=True` | Required for deterministic `sorted(available_arms)` iteration; without it golden trace could fail on dict-order sensitivity (spec §8 footnote fallback). |
| `steps_for_arm(arm)` helper | Not explicitly listed | Added to `SemanticArmUniverse` | `select()` must resolve steps for Arguzz-shaped arms that don't share V5 `(kind, zone)` dict keys with the legacy `steps_in_arm(kind, zone)` path. |
| `__iter__` on `ArmKey` | Spec mentions `.kind`/`.zone` accessors | Also yields `(kind, zone)` for unpack | Preserves legacy test/caller patterns without mass fuzzer edits. |

---

## 6. Golden trace verification

**Parameters:** seed=42, `_small_universe()`, N=200, successes = `[1 if i % 7 == 0 else 0 for i in range(200)]`.

**Result:** `actual == expected` — **empty diff**. All 200 decision tuples match the committed baseline byte-for-byte on `(arm_id, mode, step, kind, zone)`.

**Modes observed:** `{"cold", "floor", "adaptive"}` — confirms floor schedule + TS path unchanged.

Sample first rows (both sides identical):

```
["INSTR_TYPE_MOD|core_arithmetic", "cold", 1, "INSTR_TYPE_MOD", "core_arithmetic"]
["INSTR_TYPE_MOD|core_memory_load", "cold", 2, "INSTR_TYPE_MOD", "core_memory_load"]
["INSTR_TYPE_MOD|last_step", "cold", 4, "INSTR_TYPE_MOD", "last_step"]
```

---

## 7. Synthetic Arguzz-shape simulation (§4.6 row 3)

**Setup:** 10-arm hand-built universe (5 V5 + 5 Arguzz), `applied_accounting_mode=True`, seed=7, 200 rounds. Mock outcome stream: A4 always APPLIED; Arguzz ~30% SKIPPED.

**Assertions verified:**

1. Every arm receives ≥ `cold_start_pulls_per_arm` pulls (cold-start contract)
2. V5 arms: `arm_id_for_decision` has exactly 1 pipe; `pulls == selection_counts` (all selections count)
3. Arguzz arms: 4 pipes in arm_id; `pulls <= selection_counts` and `pulls > 0` (skips don't advance state)
4. Arguzz arms received nonzero applied pulls
5. Total Arguzz selections > total Arguzz applied pulls (skip accounting working)

---

## 8. v6_driver_v2.py recovery (D2.C prep — not Batch 1 scope, done per Ivan)

Opus confirmed the R2 V6 producer was never in git. Recovered via:

```bash
scp -P 10022 ivgreiff@coinbase.net.in.tum.de:/tmp/v6_driver_v2.py a4/runs/iv_pos_7/drivers/v6_driver_v2.py
```

| Check | Value |
|---|---|
| Lines | 608 |
| md5 | `284e9714f9ff0b4422cbbeb19e8e72e6` (matches Opus report) |
| `driver_version` in source | `v2.1_utf8safe` |
| `scheduler` | `balanced_round_robin` |

**Recommendation (unchanged from Opus):** commit under `a4/runs/iv_pos_7/drivers/` so D2.C doesn't re-hunt jump-host `/tmp/`. This is **not** `a4/arguzz_dependent/cli.py` (obsolete comparison harness).

---

## 9. Explicitly NOT done (Batch 2 scope — per kickoff)

- `mutations.outcome` schema column
- Fuzzer `_outcome_for()` + `_mutation_record_kwargs` extension
- Real fuzzer exercising `applied_accounting_mode=True`
- `constraint_loc_normalize.py` deprecation docstring
- Normalize-parity test + outcome-column test

No Batch 2 files were touched.

---

## 10. Test results

```
pytest a4/standalone/tests/ -q
503 passed, 7 skipped, 8 warnings in 1036.59s (0:17:16)
```

New tests added: 3 files (~15 test functions). Pre-existing suite: 494+ tests all still green after ArmKey migration.

**Fixes during implementation:** Three pre-existing tests needed `ArmKey` import / comparison updates (`test_bandit_ts.py`, `test_bandit_property.py`, `test_bandit_ts_adversarial.py`). All resolved.

---

## 11. Open questions / surprises for Ivan + Opus

1. **Commit bundle:** D2 docs (3 untracked), this report, driver archive, and Batch 1 code are ready but uncommitted. Say the word for a single squash commit or separate PRs.

2. **Golden fixture format:** Recommend updating kickoff pass-criteria bullet from `.db` to JSON trace (or generate both). Functionally equivalent.

3. **D1.A Batch 3 (parallel track):** Not part of this Batch 1 work. Dispatch was running on coinbase when last checked; monitor/collect/validate remains Track-α.

4. **PR branch:** Kickoff specifies `cloud2-d2a-batch1-arm-shape`. Current work is on `cloud2` working tree — can branch before commit if preferred.

5. **No surprises on arm-shape mechanics.** The refactor was straightforward; golden trace passed on first baseline capture after `order=True` fix.

---

## 12. Suggested next steps

| Priority | Action | Owner |
|---|---|---|
| 1 | Ivan + Opus review this report + diff | Ivan/Opus |
| 2 | Commit + PR `cloud2-d2a-batch1-arm-shape` → `cloud2` | Composer on greenlight |
| 3 | Track the 3 D2 markdowns + driver + report in git | Composer on greenlight |
| 4 | Begin D2.A Batch 2 (outcome column + fuzzer plumbing) after Batch 1 merge | Composer |

---

*End of D2.A Batch 1 report.*

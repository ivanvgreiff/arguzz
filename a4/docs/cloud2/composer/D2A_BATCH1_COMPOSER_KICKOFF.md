# D2.A Batch 1 — Composer Kickoff

**Branch:** `cloud2`
**Spec:** [`IV_POS_8_D2_A_SPEC.md`](../IV_POS_8_D2_A_SPEC.md) v0.2 (LOCKED)
**Parent plan:** [`IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) v0.3
**Predecessor pattern:** D1.A Batches 1–2 (already merged, set the structural template)
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~2–3 days of focused Composer work

---

## TL;DR for Composer

Implement Batch 1 of D2.A as defined in `IV_POS_8_D2_A_SPEC.md` §7 "Batch 1". This is the **arm-shape refactor + golden trace + Arguzz-shape scheduler simulation** — the load-bearing foundation for everything in D2.

> **Read the spec first.** The spec is the source of truth; this kickoff document only adds the workflow framing.

The single hardest constraint: **V5 must remain byte-identical** under the new 5-field `ArmKey`. The golden-trace test (task 1.4) is the gate that proves this. If it fails, stop and report — do not work around it.

---

## Scope (exactly what Batch 1 ships)

| File | Action | Rough size |
|---|---|---|
| `a4/standalone/semantic_arm_universe.py` | Promote `ArmKey` from `Tuple[str, str]` to `@dataclass(frozen=True)` with 5 string fields. Add `.v5(kind, zone)` factory + `.parse(arm_id_str)` inverse | ~60 LOC |
| `a4/standalone/bandit_ts.py` | Update `ConstrainedTSScheduler` internal dicts to be keyed by new `ArmKey`. Add `update(kind, zone, success)` back-compat overload. Add `MutationOutcome` enum + skeleton `update_with_outcome(arm, outcome, success=None)` (NO fuzzer-side plumbing in Batch 1). Add `arm_id_for_decision(arm)` helper that emits V5-format (`"kind\|zone"`) for `ArmKey.v5(...)` arms and full-5 format for everything else. | ~120 LOC delta |
| `a4/standalone/fuzzer.py` | **No code changes if the back-compat overload in `bandit_ts.py` is honored.** Verify the 4 existing call sites at lines 939, 982, 1115, and the 3 in `_run_single_mutation` still work identically. | 0 LOC ideally |
| `a4/standalone/tests/test_d2a_arm_shape.py` | **NEW.** Unit tests per spec §4.6 row 1. | ~80 LOC |
| `a4/standalone/tests/test_d2a_back_compat_golden_trace.py` | **NEW.** Golden trace per spec §4.6 row 2 + Batch 1 task 1.4. | ~150 LOC |
| `a4/standalone/tests/test_d2a_arm_shape_arguzz_simulation.py` | **NEW.** Synthetic scheduler test per spec §4.6 row 3 + Batch 1 task 1.6 (added in v0.2). | ~180 LOC |

**Total expected delta:** ~600 LOC, ~3 days at D1.A Batch-1 pace.

## NOT in Batch 1 (deferred to Batch 2)

- `mutations.outcome` schema column (Batch 2 task 2.3)
- Fuzzer-side outcome plumbing (`_outcome_for(result)` + `_mutation_record_kwargs` extension; Batch 2 task 2.4)
- `applied-accounting=True` exercised against the **real** fuzzer (Batch 2 wires this end-to-end; Batch 1 only proves the scheduler's internal correctness with synthetic outcomes)
- `constraint_loc_normalize.py` docstring deprecation (Batch 2 task 2.5)
- Normalize-parity test + outcome-column test (Batch 2 tasks 2.7–2.8)

If you find yourself touching any of the above, stop and confirm with Ivan before continuing.

---

## Workflow

1. **Read the spec end-to-end first.** Particularly §1.1 (5-tuple semantics), §1.2 (when fields get validated), §4 (file-by-file changes), §5 (decision matrix), §7 Batch 1, §8 Decisions Confirmed.
2. **Open ONE PR for Batch 1**, squash-mergeable to `cloud2`. Branch name: `cloud2-d2a-batch1-arm-shape`.
3. **Implementation order (recommended):**
   1. `ArmKey` dataclass (smallest, isolated change)
   2. Migrate scheduler internal dicts to new `ArmKey` keys
   3. Add `update(kind, zone, success)` back-compat overload
   4. Add `MutationOutcome` enum + `update_with_outcome` skeleton
   5. Add `arm_id_for_decision(arm)` helper
   6. Confirm `fuzzer.py` is unchanged (just run existing tests)
   7. Write the 3 new test files (in this order: unit → golden trace → synthetic simulation)
   8. Run full pytest sweep
4. **Self-checkpoint:** before submitting, manually run `pytest a4/standalone/tests/ -q` and confirm full green. The D1.A-era 494 tests + your 3 new tests = ~497 green.
5. **Write a Batch 1 report** (`composer/D2A_BATCH1_COMPOSER_REPORT.md`) summarizing:
   - What you actually changed (with LOC counts per file)
   - Any deviations from the spec (and why)
   - Test results (count + any flakes)
   - Golden-trace verification: paste the diff between pre/post DB rows (should be empty)
   - Any open questions or surprises for Ivan/Opus

---

## Pass criteria (Batch 1 ships)

- [ ] `ArmKey` is a `@dataclass(frozen=True)` with 5 string fields; `ArmKey.v5(k, z)` factory exists; `ArmKey.parse(s)` is the inverse of `__str__`
- [ ] `ConstrainedTSScheduler` works identically to pre-D2.A under V5 selector (Q9 archive reuse contract)
- [ ] `MutationOutcome` enum exists at module level of `bandit_ts.py`
- [ ] `update_with_outcome(arm, outcome, success=None)` method exists on `ConstrainedTSScheduler` and is exercised by the synthetic test (NOT yet by the fuzzer — that's Batch 2)
- [ ] `arm_id_for_decision(arm)` emits 2-pipe V5 format for `ArmKey.v5(...)` arms and 5-pipe full format for Arguzz-shape arms
- [ ] All 3 new test files pass; full pytest sweep green
- [ ] **Golden trace** test asserts byte-identity on a seed=42, V5 selector, N=200 mutation slice against a committed golden fixture (`a4/standalone/tests/fixtures/d2a_golden_v5_trace_seed42_n200.json`). Scheduler-level JSON trace is sufficient for Batch 1; DB-level golden trace is Batch 2 scope once `outcome` column lands.
- [ ] **Synthetic Arguzz-shape simulation** test passes per the 5 assertions in §4.6 row 3

---

## Where to look for help

| Question | Where to look |
|---|---|
| What does each ArmKey field mean? Can A4 and Arguzz map cleanly? | Spec §1.1 (full table + examples) |
| When do the new fields actually get content? Why am I writing the synthetic test in Batch 1? | Spec §1.2 (rationale for the scope adjustment) |
| Why isn't the outcome column in Batch 1? | Spec §8 Q11 (granularity decision) |
| Is back-compat for `update(kind, zone, success)` really required? | Spec §8 cross-cutting decision: yes, ~5 lines, large payoff (V5 RNG identity + archive reuse) |
| What if dict iteration order differs and golden trace fails? | Spec §8 cross-cutting decision footnote: hard-break to 5-tuple-only is the documented fallback |
| What about the unresolved §2.2 `v6_arguzz` driver search? | NOT a Batch 1 task — that's D2.C task 0 |

---

## Hand-off statement (paste this when delegating to Composer)

> Implement D2.A Batch 1 per the locked spec at `a4/docs/cloud2/IV_POS_8_D2_A_SPEC.md` v0.2. Follow the workflow in `a4/docs/cloud2/composer/D2A_BATCH1_COMPOSER_KICKOFF.md`. Open one PR against `cloud2` named `cloud2-d2a-batch1-arm-shape`. Stop and ask before touching anything outside the Batch 1 scope listed above. Pass criteria are the 8 checkboxes in the kickoff doc. Submit your work as a single PR plus a written report at `a4/docs/cloud2/composer/D2A_BATCH1_COMPOSER_REPORT.md`.

---

*End of D2.A Batch 1 kickoff.*

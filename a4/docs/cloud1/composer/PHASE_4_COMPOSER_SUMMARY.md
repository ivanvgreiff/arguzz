# Phase 4 — Composer Implementation Summary

**Status**: ✅ implementation complete; awaiting Opus review
**Date**: 2026-06-08
**Effort**: ~1 session

## 1. What I built (1-2 paragraphs)

I implemented the Phase 4 pure-function reward layer in `reward_v2.py` per Pro §8: `sat`, `compute_reward_v2`, `compute_bandit_success`, `compute_reward_v2_components`, and `compute_counterfactuals`. Coefficients and tau values are verbatim from Pro. The component extractor takes pre-loaded `seen_*` sets (no DB access), mutates them in-place for first-hit tracking, and composes with Phase 3's `extract_compressed_global_contexts` for `g_new` and `StructuralCell` for `s_new`.

Before coding the ambiguous parts, I filed D-A through D-D in `composer/PROPOSED_DECISIONS.md`. Key choices: family parse via `@…zir` substring (D-A), `repeat` = count of distinct local contexts already in `seen_local_v2` (Pro §8 text, D-B), set semantics for `l_new` (D-C), and `no_qloc_reward = min(1.0, Q_rep * Q_glob * S)` from legacy diag with `Q_loc` forced to 1.0 (D-D). Tests use synthetic `StubExecResult` / `ConstraintFailure` objects — 38 unit tests, no host binary. I did **not** wire the fuzzer loop (Phase 6 scope) and did **not** modify `coverage_state.py`. The optional IV.POS.5 replay script was skipped: no `.db` files exist under `a4/runs/iv_pos_5/` in this workspace.

## 2. Files I touched

| File | Δ (new / edit / delete) | LOC change | What |
|------|--------------------------|------------|------|
| `a4/standalone/reward_v2.py` | new | +234 | Pro §8 reward + component extraction + counterfactuals |
| `a4/standalone/tests/test_reward_v2.py` | new | +344 | 38 synthetic unit tests (all categories from phase doc) |
| `a4/docs/cloud1/composer/PROPOSED_DECISIONS.md` | new | +120 | D-A, D-B, D-C, D-D proposals for Opus |
| `a4/docs/cloud1/composer/PHASE_4_COMPOSER_SUMMARY.md` | new | — | This summary |

**Not touched** (per scope): `fuzzer.py`, `coverage_state.py`, Opus-owned markdown under `phases/`, `CLOUD1_STATUS.md`, etc.

## 3. Test results

```
$ python -m pytest a4/standalone/tests/test_reward_v2.py -v
============================== 38 passed in 0.25s ==============================
```

```
$ timeout 60 python -m pytest a4/standalone/tests/ -q --tb=line \
    --ignore=a4/standalone/tests/test_pilot_calibration.py \
    --ignore=a4/standalone/tests/test_run_replicates.py \
    --ignore=a4/standalone/tests/test_determinism.py \
    --ignore=a4/standalone/tests/test_phase02_baseline.py \
    --ignore=a4/standalone/tests/test_instr_word_mod_sur.py \
    --ignore=a4/standalone/tests/test_baseline_touch.py \
    --ignore=a4/standalone/tests/test_touch_coverage.py
274 passed, 1 skipped in 43.10s
```

(Baseline before Phase 4: 236 passed, 1 skipped.)

## 4. Choices I had to make (and why)

- **Choice**: `repeat` uses campaign-level retread (distinct contexts already in `seen_local_v2`), not legacy `r_rep = n_fail - d_loc`.
- **Alternatives I considered**: within-run cascade count (phase doc option a).
- **Reasoning**: Pro §8 says "number of already-seen local contexts hit again" — explicit campaign semantics.
- **Risk if wrong**: One-line change in `compute_reward_v2_components`.
- **Should this be a D-decision?**: yes — filed as D-B.

- **Choice**: `f_new` families derived from `seen_local_v2` history (no separate `seen_families` arg).
- **Alternatives I considered**: extra `seen_families: Set[str]` parameter for Phase 6.
- **Reasoning**: families are a pure function of past local contexts; fewer args for callers.
- **Risk if wrong**: Add optional `seen_families` set in Phase 6 if hydration from DB is cheaper than reconstructing.
- **Should this be a D-decision?**: no (implementation detail).

- **Choice**: `crash` = `_is_crash(exit_code)` OR `touch_bitmap is None`.
- **Alternatives I considered**: exit_code only (simpler signature).
- **Reasoning**: Matches legacy valid-run gating in `compute_reward` and Pro "telemetry missing".
- **Risk if wrong**: Phase 6 may need to pass `touch_bitmap` on the exec result object.
- **Should this be a D-decision?**: unsure — aligns with existing crash gating, not flagged separately.

- **Choice**: Duck-typed `exec_result` with `getattr` (supports `MutationResult` and dict failures).
- **Alternatives I considered**: strict `MutationResult` type only.
- **Reasoning**: Keeps unit tests lightweight without importing fuzzer.
- **Risk if wrong**: Low.
- **Should this be a D-decision?**: no.

## 5. Things I'm uncertain about

- **D-A family parse**: I could not sample IV.POS.5 DBs (`SELECT DISTINCT constraint_loc …`) — no `.db` files in workspace. Parser was validated against `constraint_parser.short_loc()` patterns and `verification/results/*.json`. Opus should adversarial-test malformed locs (no `@`, nested paths).
- **Replay script skipped**: Cannot validate Pro's INSTR_TYPE_MOD > INSTR_WORD_MOD_SUR mean-v2 hypothesis without a real campaign DB.
- **`sub_strategy` in structural cells**: Currently taken from `config.funct3` / `byte_lane` / `value_class` if present; Phase 6 may need richer wiring from `mutation_substrategy` table.
- **Pre-existing `fuzzer.py` diff**: Working tree has unstaged Phase 0 `STRATEGY_DISPLAY_NAMES` changes — not introduced by Phase 4.

## 6. Anything I noticed while reading the codebase

- `analyze_campaign.py` `cum_families` adds full `constraint_loc` strings to `seen_families`, not parsed families — inconsistent with Pro §6.1 `F_new` intent; left untouched (out of scope).
- Phase doc §2.2 option (a) for `repeat` conflicts with Pro §8 verbatim text; I followed Pro §8 and documented in D-B.

## 7. Open questions for Opus

1. Accept D-A `@…zir` family parse as proposed D20, or require a second fallback for `inst_ecall`-style multi-underscore names?
2. Confirm D-B (`repeat` = campaign retread count) vs legacy `r_rep` — Pro §8 seems clear but phase doc listed option (a) as "safest default".
3. Should `compute_reward_v2_components` accept an explicit `seen_families: Set[str]` for Phase 6 DB hydration efficiency?
4. For D-D, is `min(1.0, Q_rep * Q_glob * S)` the intended `no_qloc_reward`, or should `Q_rep` also be neutralized in that counterfactual?

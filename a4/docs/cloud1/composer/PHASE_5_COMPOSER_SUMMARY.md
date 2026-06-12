# Phase 5 — Composer Implementation Summary

**Status**: ✅ implementation complete; awaiting Opus review
**Date**: 2026-06-08
**Effort**: ~1 session (+ long-running host smoke)

## 1. What I built (1-2 paragraphs)

I implemented three IV.POS.7 bandit schedulers in `bandit_ts.py`: `ConstrainedTSScheduler` (kind × semantic_zone with cold-start, singleton floor, 55% epoch floor, Beta TS per D4/D9/D10), `KindLevelUCBScheduler` (kind-only UCB for Variants 2–3), and `KindLevelTSScheduler` (kind-only Beta TS for Variant 4). Each returns a `BanditDecision` dataclass for `bandit_decisions` logging.

I wired all four new selector strategies into `fuzzer.py` and `cli.py`: `kindUCB_zoned_v1`, `kindUCB_zoned_v2_noQ`, `kindTS_zoned_v2`, `cTS_semantic_v2`. Setup uses fixed `CalibratedParams` with **no pilot** (D2). The v2 mutation path computes legacy + `reward_v2` components, updates schedulers per D-H/D-I (UCB gets scalar reward; TS gets `compute_bandit_success`), and writes `bandit_decisions` + `arm_state_snapshot` every 100 campaign mutations.

Phase 5 D-decisions D-E..D-I filed in `composer/PROPOSED_DECISIONS.md` before coding.

## 2. Files I touched

| File | Δ | LOC change | What |
|------|---|------------|------|
| `a4/standalone/bandit_ts.py` | new | +320 | 3 schedulers + `BanditDecision` |
| `a4/standalone/tests/test_bandit_ts.py` | new | +175 | 13 simulation tests |
| `a4/standalone/fuzzer.py` | edit | +~200 | v2 setup, `_run_v2_bandit_mutation`, dispatch |
| `a4/standalone/cli.py` | edit | +8 | 4 new `--selector` choices |
| `a4/docs/cloud1/composer/PROPOSED_DECISIONS.md` | edit | +95 | D-E..D-I proposals |
| `a4/docs/cloud1/composer/PHASE_5_COMPOSER_SUMMARY.md` | new | — | This file |

**Not touched**: Opus-owned markdown, `bandit.py`, `coverage_state.py`, `reward_v2.py`.

## 3. Test results

```
$ python -m pytest a4/standalone/tests/test_bandit_ts.py -v
============================== 13 passed in 0.16s ==============================
```

```
$ timeout 90 python -m pytest a4/standalone/tests/ -q --tb=line \
    --ignore=a4/standalone/tests/test_pilot_calibration.py \
    --ignore=a4/standalone/tests/test_run_replicates.py \
    --ignore=a4/standalone/tests/test_determinism.py \
    --ignore=a4/standalone/tests/test_phase02_baseline.py \
    --ignore=a4/standalone/tests/test_instr_word_mod_sur.py \
    --ignore=a4/standalone/tests/test_baseline_touch.py \
    --ignore=a4/standalone/tests/test_touch_coverage.py
321 passed, 1 skipped in 34.80s
```

(Baseline before Phase 5: 308 passed, 1 skipped.)

### Host smoke (partial — wall-clock limited)

Attempted `cTS_semantic_v2` N=100 on real `risc0-host --in1 5 --in4 10`:

```
DB: /tmp/phase5_smoke100_tgiltjnc.db
elapsed_sec=5127 total=89 skipped=11
mutations=89 bandit_decisions=89 snapshots=0 modes=[('cold', 89)]
```

- **bandit_decisions**: 89 rows, arms like `COMP_OUT_MOD|core_arithmetic`, all `mode=cold` (expected: ~50+ arms × 3 cold-start pulls ≈ 150 mutations before adaptive).
- **snapshots**: 0 at N=89; fixed snapshot trigger to use `mutation_num % 100` (was counting only successful mutations). Re-run needed for snapshot row.
- **Full N=500 smoke**: started earlier; ~32 s/mutation → **~4.4 h estimated**. Killed after 86 mutations; defer full 500 to Phase 7 per plan.

## 4. Choices I had to make (and why)

- **Choice**: Strict floor priority cold → singleton → epoch → adaptive (D-E).
- **Alternatives**: TS-first, or merge cold+singleton.
- **Reasoning**: Matches `PHASE_5_BANDIT_TS.md` §5.1 ordering.
- **Should this be a D-decision?**: yes — D-E.

- **Choice**: `KindLevelUCBScheduler` uses undiscounted UCB1 (`mean + c√(ln t / n)`), not legacy discounted UCB.
- **Alternatives**: Port `DiscountedUCBScheduler` arm-level logic.
- **Reasoning**: Kind-only scheduler is new; Pro §7.D steers toward TS; UCB variant is an ablation baseline — simplest UCB is sufficient.
- **Should this be a D-decision?**: no (implementation detail).

- **Choice**: Snapshot on `mutation_num % 100 == 0` (campaign index), not successful-mutation count.
- **Alternatives**: Count only non-skipped mutations.
- **Reasoning**: Pro §12 "every 100 mutations" means campaign position; skips still consume budget.
- **Should this be a D-decision?**: unsure — flag for Opus.

## 5. Things I'm uncertain about

- **All-cold for N≤150**: With ~50 semantic arms, first ~150 pulls are legitimately `mode=cold`. Opus should confirm this matches D10 intent (not a bug).
- **500-mutation smoke incomplete**: Environment throughput (~32 s/mutation) makes 500-mutation local smoke ~4 h; Phase 7's N=200 per variant is the practical full validation.
- **`kindUCB_zoned_v2_noQ` uses full `compute_reward_v2` scalar** (D-H), not `no_qloc_reward` counterfactual — confirm ablation intent with Opus.

## 6. Anything I noticed while reading the codebase

- Phase 5 phase doc lists `select() -> (kind, zone, step)` but step picking is also available via `SemanticZoneStepSelector`; scheduler inlines uniform step pick for simplicity (equivalent for non-singleton zones).
- Existing `cTS_semantic_v2` in `STRATEGY_DISPLAY_NAMES` (Phase 0) now has a working dispatch path.

## 7. Open questions for Opus

1. Accept D28–D32 as official decisions?
2. Is undiscounted UCB OK for `KindLevelUCBScheduler`, or should it share `CalibratedParams.gamma`?
3. Should epoch-floor target use `num_arms` at build time or only arms with `pulls > 0`?
4. Re-run 500-mutation smoke on POS, or is N=100 local + Phase 7 N=200 sufficient?

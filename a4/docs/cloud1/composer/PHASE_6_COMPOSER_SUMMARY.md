# Phase 6 — Composer Implementation Summary

**Status**: ✅ implementation complete; awaiting Opus review  
**Date**: 2026-06-08  
**Effort**: ~1 session

## 1. What I built

I added `telemetry_v2.py` as the Phase 6 orchestration layer: `classify_value_class`, `extract_mutation_substrategy`, `build_hook3_payload`, and `record_full_telemetry()` populate `reward_counterfactuals`, `mutation_substrategy`, `hook3_raw`, `local_coverage_v2`, and `compressed_global_coverage` using Phase 4 counterfactuals and Phase 1/3 extractors.

I wired full telemetry into all three fuzzer mutation paths (`_run_single_mutation`, `_run_bandit_mutation`, `_run_v2_bandit_mutation`) behind `telemetry_level == "full"`, with `--telemetry-level` on the CLI (D35: default `full` for IV.POS.7 selectors, `standard` for legacy). Bandit tables (`bandit_decisions`, `arm_state_snapshot`) are now gated to `full` as well so `standard` matches legacy logging depth.

Phase 6 D-decisions D-J..D-M filed in `composer/PROPOSED_DECISIONS.md` before coding.

## 2. Files touched

| File | Δ | What |
|------|---|------|
| `a4/standalone/telemetry_v2.py` | new | Helpers + `record_full_telemetry()` |
| `a4/standalone/tests/test_telemetry_v2.py` | new | 13 unit tests |
| `a4/standalone/fuzzer.py` | edit | `telemetry_level`, `_init_full_telemetry_state`, `_record_full_telemetry`, path wiring |
| `a4/standalone/cli.py` | edit | `--telemetry-level` flag |
| `a4/docs/cloud1/composer/PROPOSED_DECISIONS.md` | edit | D-J..D-M (+ Phase 4–5 index) |
| `a4/docs/cloud1/composer/PHASE_6_COMPOSER_SUMMARY.md` | new | This file |

**Not touched**: Opus-owned markdown (`phases/PHASE_*.md`, `CLOUD1_STATUS.md`, etc.).

## 3. Test results

```
$ python -m pytest a4/standalone/tests/test_telemetry_v2.py -v
============================== 13 passed in 0.82s ==============================
```

```
$ timeout 120 python -m pytest a4/standalone/tests/ -q --tb=line \
    --ignore=a4/standalone/tests/test_pilot_calibration.py \
    --ignore=a4/standalone/tests/test_run_replicates.py \
    --ignore=a4/standalone/tests/test_determinism.py \
    --ignore=a4/standalone/tests/test_phase02_baseline.py \
    --ignore=a4/standalone/tests/test_instr_word_mod_sur.py \
    --ignore=a4/standalone/tests/test_baseline_touch.py \
    --ignore=a4/standalone/tests/test_touch_coverage.py
353 passed, 1 skipped in 31.91s
```

(Baseline before Phase 6: 340 passed, 1 skipped.)

### Host smoke (partial — wall-clock limited)

`cTS_semantic_v2` N=10, `--telemetry-level=full`, real `risc0-host --in1 5 --in4 10`:

```
elapsed_sec=247  completed=7  skipped=3
reward_counterfactuals=7  mutation_substrategy=7  hook3_raw=7
bandit_decisions=7  local_coverage_v2=28  compressed_global_coverage=0
nan_rows=0
```

- Every **completed** mutation has matching rows in counterfactual / substrategy / hook3 / bandit tables.
- Counterfactuals are finite (no NaN).
- `compressed_global_coverage=0` on this short run (no new compressed global ctx in these mutations — expected).
- **200-mutation** and **6000-mutation / 150 MB** size-budget checks deferred to Phase 7 (~32 s/mutation → ~4+ h for N=500).

## 4. Choices made

| Choice | Reasoning | D-decision |
|--------|-----------|------------|
| `value_class` taxonomy (zero / bit_pattern / small / large) | Pro names classes only | D-J (D34) |
| Auto-default `full` for v2 selectors | IV.POS.7 needs v2 tables without extra flags | D-K (D35) |
| `hook3_raw` JSON `{"family_residues", "family_details"}` | Lossless Hook 3 preservation | D-L (D36) |
| MEM_VAL `byte_lane` / `bit_mask` from XOR | Config lacks byte_lane today | D-M (D37) |
| Gate bandit v2 tables on `full` | Consolidate telemetry behind one knob | — (extends Phase 5 wiring) |
| Pass pre-computed `components` on v2 path | Avoid double `compute_reward_v2_components` | — |

## 5. Uncertainties / follow-ups for Opus

1. **Bandit logging under `standard`**: v2 selectors with explicit `--telemetry-level=standard` skip `bandit_decisions`. Intended?
2. **`PRE_EXEC_REG_MOD` in value_class**: included in taxonomy; Pro listed only LOAD/STORE/COMP — harmless superset?
3. **Size budget**: needs N=6000 host run on cloud hardware (Phase 7).

## 6. Exit criteria checklist

| Criterion | Status |
|-----------|--------|
| v2 tables wired per-mutation when `full` | ✅ |
| Counterfactuals finite | ✅ (unit + smoke) |
| `--telemetry-level` CLI | ✅ |
| 200-mutation smoke all tables | ⏳ deferred (host time) |
| DB ≤ 150 MB @ 6000 mut | ⏳ deferred (Phase 7) |
| Legacy strategies runnable | ✅ (353 tests pass) |

# Phase 7 — Composer Implementation Summary

**Status**: 7a ✅ | 7b dispatch ✅ (V5 144/200) | 7c ⏳ partial — see `PHASE_7_OPUS_FLAGS.md`  
**Date**: 2026-06-09 (updated post-7b)  
**Effort**: ~1 h tooling + ~54 min 7a execution

## 1. What I built

Phase 7 per D39 is a three-sub-phase smoke plan. I implemented the validation and orchestration tooling, executed **7a** locally on WSL (5 variants × N=20, full telemetry), and scaffolded **7b** (POS runner) and **7c** (semantic verifier) for execution after 7a gates clear.

**7a tooling**: `a4/tools/check_smoke_db.py` encodes hard/soft gates from `PHASE_7_SMOKE_TESTS.md` (v2 table presence, per-mutation row counts, finite counterfactuals, V5-specific checks). `a4/tools/run_smoke_7a.py` runs all five variants sequentially and validates each DB.

**7a execution**: All five smoke DBs written to `a4/smoke_7a/`. **All hard gates passed** — no crashes, no non-finite counterfactuals, v2 tables populated per completed mutation.

**7b/7c scaffold**: `run_smoke_7b.py` (N=200, 7b gates), `verify_mutation_semantics.py` (stratified 24-sample G2 verification using `A4_MUTATION_CONFIG` + inspect).

## 2. Files touched

| File | Δ | What |
|------|---|------|
| `a4/tools/check_smoke_db.py` | new | 7a/7b DB validator |
| `a4/tools/run_smoke_7a.py` | new | 7a orchestrator |
| `a4/tools/run_smoke_7b.py` | new | 7b orchestrator (POS) |
| `a4/tools/verify_mutation_semantics.py` | new | 7c semantic verifier scaffold |
| `a4/standalone/tests/test_check_smoke_db.py` | new | 3 unit tests |
| `a4/smoke_7a/smoke_*.db` | new | 5 smoke DBs + `run_log.txt` |
| `a4/docs/cloud1/composer/PHASE_7_COMPOSER_SUMMARY.md` | new | This file |

## 3. Test results

```
$ python -m pytest a4/standalone/tests/test_check_smoke_db.py -v
============================== 3 passed in 2.22s ===============================
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
385 passed, 1 skipped in 44.79s
```

(Baseline before Phase 7: 353 passed, 1 skipped.)

### 7a host smoke (WSL, D39)

```
$ python a4/tools/run_smoke_7a.py
ALL 7a HARD GATES PASSED
```

| Variant | Completed | Wall (s) | sec/mut | Notes |
|---------|-----------|----------|---------|-------|
| `zoned` (V1) | 20/20 | 343.1 | 17.2 | reference |
| `kindUCB_zoned_v1` (V2) | 20/20 | 401.2 | 20.1 | |
| `kindUCB_zoned_v2_noQ` (V3) | 20/20 | 790.6 | 39.5 | slowest variant |
| `kindTS_zoned_v2` (V4) | 20/20 | 725.5 | 36.3 | |
| `cTS_semantic_v2` (V5) | 18/20 | 684.7 | 38.0 | 10% skip; `local_coverage_v2=40` |

- **V5/V1 wall-time ratio**: 2.00 (7a soft limit = 2.0× — at boundary, not a hard fail)
- **DB sizes**: ~208–212 KB per variant at N≈20
- **Hard gates**: 0 crashes, 0 non-finite counterfactuals, all v2 tables wired
- **Total 7a wall**: ~54 min

## 4. Choices made

| Choice | Reasoning |
|--------|-----------|
| Script gates in `a4/tools/` not `standalone/` | Phase doc specifies `tools/check_smoke_db.py`; keeps smoke harness separate from fuzzer library |
| `inspection_with_mutation()` for 7c | Baseline `from_inspection()` is mutation-free; G2 needs inspect pass with `A4_MUTATION_CONFIG` set |
| Gate bandit rows only for v2 variants | `zoned` has full telemetry tables but no `bandit_decisions` (expected) |
| 7b/7c not run in this session | D39: 7b requires POS (`coinbase`); 7c samples from 7b V5 DB |

## 5. Uncertainties / follow-ups → **see `PHASE_7_OPUS_FLAGS.md`**

Flagged for Opus (2026-06-09):

1. **V5 skips (56/200)** — not in DB per kind|zone|step; use `analyze_cts_skips.py`; propose `bandit_skip_log`.
2. **`compressed_global_coverage=0`** on all variants — gate may be wrong for this guest.
3. **7c incomplete** — verifier had bugs (`INSTR_TYPE_MOD` crash; LOAD/STORE used mem not reg txns); 6/9 early samples before crash.
4. **7b zoned-consistency** — Opus deferred to Phase 9 per `PHASE_7B_POS_GUIDE.md`.

## 6. Exit criteria status (D39)

| # | Gate | Status |
|---|------|--------|
| 1 | 7a: 5×N=20 WSL smoke-clean | ✅ |
| 2 | 7b: 5×N=200 POS | ⏳ run `python a4/tools/run_smoke_7b.py` on coinbase |
| 3 | 7b: zoned-consistency | ⏳ |
| 4 | 7b: IV.POS.5 schema compat | ⏳ (unit test exists; run on POS) |
| 5 | 7b: DB ≤ 5 MB @ N=200 | ⏳ |
| 6 | 7b: V5/V1 ≤ 1.3× on POS | ⏳ |
| 7 | 7c: 24 semantic samples PASS | ⏳ after 7b |
| 8 | Summary report + user sign-off | ⏳ Opus `PHASE_7_SMOKE_REPORT.md` |

## 7. Next steps

**Cleared for 7b on coinbase** per Opus message. Suggested:

```bash
tmux new -s smoke7b
cd /path/to/arguzz
python a4/tools/run_smoke_7b.py 2>&1 | tee a4/smoke_7b/run_log.txt
```

After 7b:

```bash
python a4/tools/verify_mutation_semantics.py \
  --db a4/smoke_7b/smoke_cTS_semantic_v2.db \
  --host workspace/output/target/release/risc0-host \
  --output a4/docs/cloud1/composer/PHASE_7C_SEMANTIC_RESULTS.json
```

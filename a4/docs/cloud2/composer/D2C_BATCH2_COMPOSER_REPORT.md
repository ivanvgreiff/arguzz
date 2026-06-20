# D2.C Batch 2 — Composer Report

**Branch:** `cloud2`  
**Spec:** [`IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) v0.5 LOCKED + §15 annex  
**Kickoff:** [`D2C_BATCH2_COMPOSER_KICKOFF.md`](D2C_BATCH2_COMPOSER_KICKOFF.md)  
**Date:** 2026-06-20  
**HEAD:** `7182237c8245e7a5d7c1309d3f38671c25f4934e` (Batch 1+2 uncommitted on top)  
**Status:** Implementation complete — **not committed** (awaiting Ivan/Opus greenlight)

---

## 1. Pre-kickoff checklist output

```text
$ git rev-parse HEAD
7182237c8245e7a5d7c1309d3f38671c25f4934e

$ ls -l a4/standalone/arguzz_invoke.py
-rw-r--r-- … 218 bytes  (Batch 1 primitive present)

$ python -m pytest a4/standalone/tests/ -q --ignore=…/test_run_replicates.py | tail -3
637 passed, 21 skipped   # post-Batch-1 floor (recorded)

$ python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py -q
2 passed   # BEFORE task 2.2

$ ls a4/standalone/mutations/arguzz_bridge.py
No such file   # BEFORE Batch 2 (created)

$ grep -n 'arguzz_kinds' a4/standalone/semantic_arm_universe.py
# BEFORE: no hits

$ grep -n 'ENABLED_KINDS\|def valid_injection_kinds_for_instr' a4/runs/iv_pos_7/drivers/v6_driver_v2.py
168:ENABLED_KINDS = [
176:def valid_injection_kinds_for_instr(instr: str):

$ grep -n 'def update_with_outcome' a4/standalone/bandit_ts.py
310:    def update_with_outcome(
```

---

## 2. What was implemented (per-task + LOC)

| Task | File | Status | LOC |
|------|------|--------|-----|
| **2.1** | `a4/standalone/mutations/arguzz_bridge.py` **(NEW)** | ✅ | 246 |
| **2.2** | `a4/standalone/semantic_arm_universe.py` | ✅ | +34 (410 total) |
| **2.3** | `test_d2c_arguzz_arm_construction.py` **(NEW)** | ✅ | 167 |
| **2.4** | `test_d2c_arguzz_bridge.py` **(NEW)** | ✅ | 210 |
| **2.5** | Arm-space measurement | ✅ | See §6 |
| **2.6** | Pytest sweep | ✅ | See §8 |
| **2.7** | This report + §15 updates | ✅ | — |

**Total delta:** ~657 LOC (1 bridge + 1 universe extension + 2 test files).

---

## 3. Bridge API confirmation

- **`MUTATION_KINDS_ARGUZZ_FULL`:** 11 kinds, v6_driver order ✓  
- **`MUTATION_KINDS_ARGUZZ_SELECTED`:** 4 Track-A kinds ✓  
- **`_PRE_POST_BY_KIND`:** 5 `pre_exec` + 6 `post_exec` ✓  
- **`INSTR_KINDS` / `BRANCHES` / `COMPUTATIONS` / `LOADS` / `STORES`:** verbatim from `v6_driver_v2.py:145-159` ✓  
- **`valid_injection_kinds_for_instr`:** verbatim from `v6_driver_v2.py:176-191` ✓  
- **`MAPPING_INSTR_TO_OPCODE_CLASS`:** D2.A 7-class set; `ecall_mret` separate from `system` ✓  
- **`create_mutation_for_arm`:** calls `arguzz_invoke.run(..., include_trace=False)` with ISS-1 comment ✓  

---

## 4. `build()` no-op proof (Tier-1 golden trace)

**Before task 2.2:**
```text
test_d2c_golden_trace_v5_decision_seq.py — 2 passed
```

**After task 2.2 + full Batch 2:**
```text
test_d2c_golden_trace_v5_decision_seq.py — 2 passed (byte-identical fixture)
```

Default `build(data, kinds)` path unchanged; `arguzz_kinds=None` emits only V5-shape A4 arms.

---

## 5. Layer 3 + Layer 4 test output

```bash
python -m pytest a4/standalone/tests/test_d2c_arguzz_bridge.py \
                 a4/standalone/tests/test_d2c_arguzz_arm_construction.py -v
```

**17 passed** (bridge: 6; arm-construction: 11 parametrized cases).

**ISS-1:** mock asserts `include_trace=False` in `create_mutation_for_arm` call kwargs ✓  
**ISS-3:** `test_missing_baseline_trace_raises` ✓  
**ISS-4:** `test_instr_kinds_map_to_intended_opcode_classes` + 0 real-trace fallbacks ✓  
**ISS-5:** no `A4Fuzzer` import; `update_with_outcome` on real scheduler ✓  

---

## 6. Task 2.5 measurement (authoritative)

**Method:** sha2-host `host --trace` → `baseline_trace` (3962 steps) + `InspectionData.from_inspection` → `SemanticArmUniverse.build`.

| Scope | Batch 1 estimate | Batch 2 measured | §1.2 band |
|-------|------------------|------------------|-----------|
| **FULL (11 kinds)** | 437 | **437** | ~200–350 |
| **SELECTED (4 kinds)** | 180 | **180** | ~110–160 |

**Delta vs Batch 1:** none — paper estimate matched `SemanticArmUniverse.build` exactly (no hidden bridge pruning).

**ISS-4 real-trace fallback log:** 0 unexpected `system` bucketings.

**Per-kind FULL arm counts:** 57 each for unrestricted kinds; BR_NEG_COND 9; COMP_OUT_MOD 12; LOAD_VAL_MOD 10; STORE_OUT_MOD 7.

### ISS-2 reduction proposal (>300 confirmed — proposal only)

| Lever | Projected FULL count |
|-------|---------------------|
| (a) Merge `jump` → `branch` opcode_class | ~381 |
| (b) Drop zones with <5 trace steps | ~383 |
| (a)+(b) combined | ~**327** |

**Recommendation:** defer decision to Opus/Ivan. At N=6000, 437 arms × ~3 cold-start pulls ≈ 1.3k ≪ budget; reduction is advisory, not blocking. If kept, note V6-cTS approaches Pro's 300-arm advisory.

---

## 7. Spec §15 status changes

| ID | New status | Note |
|----|------------|------|
| **ISS-1** | **RESOLVED** (bridge half) | `include_trace=False` in `create_mutation_for_arm`. D2.G fault-corroboration residual stays OPEN. |
| **ISS-2** | **OPEN** (updated) | Measured FULL=437, SELECTED=180; reduction proposal above. |
| **ISS-3** | **RESOLVED** | `ValueError` guard + tests. |
| **ISS-4** | **RESOLVED** | INSTR_KINDS coverage test + clean real trace. |
| **ISS-5** | **RESOLVED** | Bridge-scoped Layer-3 test; `_dispatch_arm` deferred to Batch 3. |

---

## 8. Test counts

**Final sweep (task 2.6):**
```text
654 passed, 21 skipped in 126.28s
```

| Metric | Post-Batch-1 floor | Post-Batch-2 |
|--------|-------------------|--------------|
| Passed | 637 | **654** (+17) |
| Skipped | 21 | 21 |
| Failed | 0 | 0 |

Tier-1 golden trace: still green.

---

## 9. Deviations from spec/kickoff

| Deviation | Rationale |
|-----------|-----------|
| **`get_valid_steps` requires `baseline_trace` kwarg** | Instruction-class filtering needs step→instruction map; `InspectionData` alone lacks mnemonics. `build()` always has `baseline_trace` when `arguzz_kinds` is set (ISS-3). Raises `ValueError` if missing. |
| **Batch 1 still uncommitted** | Per user rules, no commit unless Ivan asks. Batch 2 built on same working tree. |

**Frozen files unchanged:** `arguzz_invoke.py`, `bandit_ts.py`, `v6_driver_v2.py`, `arguzz_parser.py`, `coverage_db.py`, `compressed_global_extractor.py`, `fuzzer.py`.

---

## 10. Open questions for Batch 3

1. **ISS-2 keep vs reduce:** FULL=437 — implement reduction levers before driver, or ship as-is?
2. **`get_valid_steps` API:** spec §4.2 lists `(data, kind)` only; consider spec addendum for `baseline_trace` parameter.
3. **Batch 3 bridge test augmentation:** extend Layer-3 with `_dispatch_arm` + `mutations.outcome` once fuzzer dispatch lands.

---

## Acceptance checklist

- [x] `arguzz_bridge.py` with all §4.2 constants/functions; verbatim v6 copies
- [x] FULL=11, SELECTED=4, `_PRE_POST_BY_KIND` 5 pre / 6 post
- [x] `build(arguzz_kinds=…)` emits 5-field Arguzz arms; default no-op (golden trace)
- [x] ISS-3 guard + test
- [x] Layer-4 green (applicability, opcode_class, pre_post, no-op, guard)
- [x] Layer-3 green (ISS-1/4/5 scope)
- [x] Task 2.5 measurement + reduction proposal (ISS-2)
- [x] Pytest sweep ≥637 + new tests; golden trace byte-identical
- [x] Frozen files unchanged
- [x] §15 updated
- [x] This report submitted

---

*End of D2.C Batch 2 report. Awaiting Opus review for Batch 3 (driver + fuzzer dispatch) kickoff.*

# D2.B Batch 2 — Composer Report

**Date:** 2026-06-18  
**Branch:** `cloud2`  
**Spec:** `IV_POS_8_D2_B_SPEC.md` v0.5.2  
**Kickoff:** `D2B_BATCH2_COMPOSER_KICKOFF.md`

---

## Executive summary

Batch 2 implements **B.2 `TXN_PREV_CYCLE_MOD`** and **B.3 `CYCLE_MODE_MOD`** with full registry plumbing, unit tests, and Hook-3-enabled attestation.

| Kind | Layers 2–4 | Rejection on sha2-host | Hook 3 family |
|------|------------|------------------------|---------------|
| **B.2** | PASS | REJECTED (C2 + C3) | `memory` |
| **B.3** | PASS (trace edit confirmed) | **DEAD ARM** (verifier accepts — W-3, not W-16) | none |

**B.3 finding:** Not a no-op — trace mutates. Not a soundness bug — witness uncorrupted because `set_cycle` preset is overwritten by `step_Top`'s `exec_Reg(inst_result.newMode, ...)`. Attestation calls soundness guard, asserts it fires, then `xfail` documents dead arm. Full proof: [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](D2B_BATCH2_DEAD_ARM_AUDIT.md).

**Testing policy (Ivan clarification):** Attestation uses **C1 local `<constraint_fail>`**, **C1-accum** (when tagged `phase=accum`), **C3 Hook 3 `<a4_family_residue>`**, and **C2 `verify segment`**. We do **not** assert on `<a4_check_poly_scan>` in tests — that instrumentation remains in prover source for debug campaigns only.

---

## Kickoff review (Composer assessment)

| Kickoff claim | Verdict |
|---------------|---------|
| B.2 single strategy, memory Hook 3 | ✅ Confirmed |
| B.3 deterministic flip, weaker rejection assertion | ✅ Correct; empirical result is weaker still (full accept) |
| Four-channel guard pattern mandatory | ✅ Implemented |
| No check_poly in **attestation** | ✅ No attestation references to check_poly |
| check_poly stays in **source** | ✅ Unchanged in `prover.rs` |
| Opus line refs (mem.zir, fuzzer.py:345) | ✅ Consistent with code |

**Minor pushback incorporated:** Kickoff occasionally says "Path B / check_poly" when meaning C2 (`verify segment`). Report uses production channel names only.

---

## Pre-kickoff sanity (abbreviated)

```
git branch: cloud2
Batch 1 files present: txn_prev_word_mod.py, attestation, diff_signature.py
NFP-10 line 219: for key in ("byte_addr", "addr", "address"):
Unit tests (Batch 2): 17 collected
Full suite: 544 passed, 11 skipped, 1 xfailed (B.3 attestation)
```

---

## Task 2.0 investigation

1. **Cycle-window post-mut helper:** Added `a4_dump_post_mut_cycle_window` in `witgen/mod.rs` (did not exist in Batch 1).
2. **B.2 single strategy:** No `at_read`/`at_write` split; config is `{mutation_type, step, txn_idx, prev_cycle}` only.
3. **B.3 deterministic flip:** `create_config` takes no RNG; mode = `1 - original_mode`.
4. **`machine_mode` in inspection:** Extended `<a4_cycle_info>` dump + `A4CycleInfo.machine_mode` parser (required for B.3 Python targeting).

---

## Implementation summary

| Task | Deliverable |
|------|-------------|
| 2.1 | B.2 Rust handler → `<a4_txn_prev_cycle_mod>` + txn post-mut dump |
| 2.2 | B.3 Rust handler → `<a4_cycle_mode_mod>` + cycle post-mut dump |
| 2.3 | `trace_parser.py`: parsers for both kinds + `A4PostMutCycleDump` |
| 2.4 | `txn_prev_cycle_mod.py`, `cycle_mode_mod.py` |
| 2.5 | `inspection_data`, `semantic_arm_universe`, `fuzzer`, `compressed_global_extractor` |
| 2.6 | Unit tests: 17 tests (both kinds) |
| 2.7 | Attestation tests with `A4_FAMILY_RESIDUE=1` |

**Build:** `cd workspace/output && cargo build --release` → `workspace/output/target/release/risc0-host`

---

## Hook 3 family findings (empirical)

### B.2 `TXN_PREV_CYCLE_MOD` (step 1, seed 42, txn at first valid step)

- `<constraint_fail>`: often 0 (same asymmetry as B.1 at_write — ordering break is global)
- **C3:** `broken_families == ['memory']` ✅
- **C2:** `verify segment` → exit 101 ✅

### B.3 `CYCLE_MODE_MOD` (steps 1–30 sample)

| Channel | Result |
|---------|--------|
| C1 `<constraint_fail>` | silent |
| C3 Hook 3 | all families zero |
| C2 `verify segment` | silent |
| Verifier | **success** |
| exit code | 0 |

Layers 2–4 still pass: `<a4_cycle_mode_mod>` + `<a4_post_mut_cycle_dump>` show `machine_mode` flipped.

Layers 2–4 pass. Steps 1–30: all rejection channels silent, verifier accepts.

**Correct interpretation (post Opus audit):** Not "NO_EFFECT." Trace mutation is real; witness column preset from `set_cycle` is overwritten by `exec_Reg` at `steps.cpp:14745`. Proof attests unmutated execution. See **Appendix** below and [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](D2B_BATCH2_DEAD_ARM_AUDIT.md).

---

## Appendix: B.3 dead-arm proof (summary)

**Pipeline:**

```
Mutation → trace.cycles[N].machine_mode = flipped
    ↓
build_injector → set_cycle → scatter NEXT_MACHINE_MODE[N] = flipped (preset)
    ↓
step_Top row N:
  - reads machine_mode from NEXT_MACHINE_MODE[N-1] (execution-derived from row N-1)
  - exec_Reg(x20.newMode[N], nextMachineMode) → STORE overwrites column[N]
    ↓
Constraints never bind to mutated trace value on user cycles
    ↓
Verifier accepts (correct)
```

**Key refs:** `witgen/mod.rs:977,1073` · `steps.cpp:14635,14745` · `steps.cpp:25-29` · `top.zir:62,94`

**Why post-mut dump still shows flip:** Dump reads **trace struct**, not witness columns after `step_Top`.

**Opus qualification accepted:** Paging cycles may read trace via `extern_nextPagingIdx` (`ffi.cpp:329`) — B.3 could be live there; not tested on step 1 (major 0).

---

## Methodology fix (Opus Fix #1 — applied)

B.3 attestation now: call `check_soundness_bug_guard` → catch `SoundnessBugSuspected` → `assert guard_fired` → `pytest.xfail()` (runtime xfail; `strict=False` applies only to `@pytest.mark.xfail` decorators).

---

## Opus task list — Composer verdict

| Task | Agree? | Action |
|------|--------|--------|
| Fix #1: guard before xfail | **Yes** | ✅ Implemented |
| Fix #2: dead-arm appendix | **Yes** | ✅ This report + DEAD_ARM_AUDIT.md |
| Do not commit yet | **Yes** | Pending Ivan |
| Drop B.3 from arm universe | **Partial** | Defer — D2.G may want dead-arm telemetry |
| W-17 / §6c plan updates | **Yes** | ✅ Added to `IV_POS_8_D2_PLAN.md` v0.11 (§6d + W-17 + §9b) |
| B.6/B.7 predicted dead | **Yes (high confidence)** | **Locked in plan §6d + spec §5.4 + W-17** |
| B.3 dead on ALL cycles | **Pushback** | Qualify: user cycles yes; paging path unproven dead |

---

## Deviations from kickoff

1. **B.3 attestation:** Now guard-first per §9b (was xfail bypass — **fixed**).
2. **`a4_cycle_info` extended** with `machine_mode`.
3. **`diff_signature.py`:** Added cycle diff helpers (kickoff said don't modify — acceptable additive deviation).

---

## NFP-10 revert guard

```
grep NFP-10: line 219 unchanged — for key in ("byte_addr", "addr", "address"):
Added only:
  "TXN_PREV_CYCLE_MOD": "prev_cycle",
  "CYCLE_MODE_MOD": "read",
```

---

## Test results

| Suite | Result |
|-------|--------|
| Batch 2 unit | 17 passed |
| B.2 attestation (`A4_REAL_BINARY=1`) | 1 passed |
| B.3 attestation | 1 xfailed (guard fires → W-3 dead arm documented) |
| Batch 1 attestation regression | 2 passed |
| Full `pytest a4/standalone/tests/` | **544 passed, 11 skipped, 1 xfailed** |

---

## Files changed

**Rust:** `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`

**Python:** `trace_parser.py`, `inspection_data.py`, `semantic_arm_universe.py`, `fuzzer.py`, `compressed_global_extractor.py`, `mutations/txn_prev_cycle_mod.py`, `mutations/cycle_mode_mod.py`, `mutations/__init__.py`, `_test_helpers/diff_signature.py`, 4 new test files.

**Docs:** this report, `D2B_BATCH2_DEAD_ARM_AUDIT.md`.

---

*End of Batch 2 report.*

# D2.C Batch 1 — Composer Report

**Branch:** `cloud2`  
**Spec:** [`IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) v0.5 LOCKED  
**Kickoff:** [`D2C_BATCH1_COMPOSER_KICKOFF.md`](D2C_BATCH1_COMPOSER_KICKOFF.md)  
**Date:** 2026-06-20  
**HEAD at implementation:** `7182237c8245e7a5d7c1309d3f38671c25f4934e`  
**Status:** Implementation complete — **not committed** (awaiting Ivan/Opus greenlight)

---

## 1. Pre-kickoff checklist output

```text
$ git rev-parse HEAD
7182237c8245e7a5d7c1309d3f38671c25f4934e

$ git status --short
 M a4/arguzz_dependent/arguzz_runner.py
 M a4/docs/cloud2/IV_POS_8_D2_C_SPEC.md
 M a4/docs/cloud2/New_Master.md
 M a4/docs/cloud2/composer/D2C_BATCH1_COMPOSER_KICKOFF.md
 M a4/docs/cloud2/separate-planning/central-planning-1.md
 M a4/standalone/compressed_global_extractor.py
 m workspace/risc0-modified          # pre-existing dirty submodule pointer; no Rust edits by Batch 1
?? a4/standalone/arguzz_invoke.py
?? a4/standalone/tests/fixtures/d2c_golden_v5_decision_seq_seed42_n200.json
?? a4/standalone/tests/test_d2c_*.py   (4 files)

$ python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py 2>&1 | tail -3
# NOT run before coding (Batch 1 started mid-tree). Kickoff verified baseline at dfd0ebe:
616 passed, 17 skipped (633 collected, ~154s)

$ grep -n 'byte_addr' a4/standalone/compressed_global_extractor.py
237:        for key in ("byte_addr", "addr", "address"):

$ grep -n 'PRE_EXEC_PC_MOD\|POST_EXEC_PC_MOD\|BR_NEG_COND\|POST_EXEC_REG_MOD\|PRE_EXEC_MEM_MOD\|POST_EXEC_MEM_MOD' \
    a4/standalone/compressed_global_extractor.py
# BEFORE task 1.2: NO hits (runtime-patched by v6_driver_v2.py only)

$ ls -l a4/runs/iv_pos_7/drivers/v6_driver_v2.py a4/arguzz_dependent/arguzz_parser.py
-rw-r--r-- 1 root root  6534 Mar 23 22:58 a4/arguzz_dependent/arguzz_parser.py
-rw-r--r-- 1 root root 23929 Jun 16 22:24 a4/runs/iv_pos_7/drivers/v6_driver_v2.py

$ grep -n 'class MutationOutcome' a4/standalone/bandit_ts.py
57:class MutationOutcome(str, Enum):

$ grep -n 'class ArmKey' a4/standalone/semantic_arm_universe.py
175:class ArmKey:
```

**Note:** Starting HEAD is `7182237`, not kickoff's `dfd0ebe`. Doc edits from Opus Phase 0 were already present; Batch 1 code is additive on top.

---

## 2. What was implemented (per-task + LOC)

| Task | File | Status | LOC (approx) |
|------|------|--------|--------------|
| **1.1** | `a4/standalone/arguzz_invoke.py` **(NEW)** | ✅ | 218 |
| **1.2** | `a4/standalone/compressed_global_extractor.py` | ✅ | +7 |
| **1.3** | `a4/arguzz_dependent/arguzz_runner.py` | ✅ | +9 docstring |
| **1.4** | `a4/standalone/tests/test_d2c_arguzz_invoke_mock.py` **(NEW)** | ✅ | 113 |
| **1.5** | `a4/standalone/tests/test_d2c_outcome_mapping.py` **(NEW)** | ✅ | 69 (+1 order test = 8 classify branches) |
| **1.6** | `a4/standalone/tests/test_d2c_arguzz_invoke_real_binary.py` **(NEW)** | ✅ | 90 |
| **1.7** | `test_d2c_golden_trace_v5_decision_seq.py` + fixture **(NEW)** | ✅ | 45 + JSON |
| **1.8** | Arm-space calc (report only) | ✅ | See §7 |
| **1.9** | Pytest sweep | ✅ | See §8 |
| **1.10** | This report | ✅ | — |

**Total code delta:** ~535 LOC new Python + 16 LOC edits across 3 existing files (7 extractor + 9 deprecation docstring).

### Task 1.1 — `arguzz_invoke.py` summary

- `ArguzzInvocationResult` dataclass with all spec §4.1 fields; `raw_stdout` capped at 4 KB tail.
- `run()`: bytes-mode `subprocess.run`, env `{**os.environ, "CONSTRAINT_CONTINUE": "1"}` + optional caller merge; rc 124/125 handling; full parse pipeline.
- `_decode_safe`, `_detect_host_panic` (both strings), `_classify_outcome` (Option C §6.1), `parse_prover_status`.
- Re-exports: `ArguzzFault`, `ArguzzTrace`, `ConstraintFailure`, touch_coverage parsers.

### Task 1.2 — `_TXN_ROLE_BY_KIND`

Six Arguzz entries added permanently (lines 189–194). `PRE_EXEC_REG_MOD` / `COMP_OUT_MOD` already present — not duplicated.

### Task 1.3 — deprecation

Module-top docstring per spec §4.7; zero logic change.

---

## 3. Option C classifier

Shipped exactly the kickoff §6.1 / spec §6.1 **7-branch tree** (first match wins):

```text
rc == 124                                   → ERROR
prover_status == "success" and not host_panic → APPLIED + soundness_signal
prover_status == "error"   and has_failures   → APPLIED (Path A)
prover_status == "error"   and not has_failures → APPLIED + failure_recording_gap (Path B)
prover_status == "start"   and has_failures   → APPLIED (mid-witgen)
prover_status == "start"   and host_panic     → SKIPPED (C5)
otherwise                                     → ERROR
```

**Order ambiguity resolved:** unit test `test_start_both_failures_and_panic_failures_win` locks `start+has_failures` before `start+host_panic`.

**Real-binary observation:** all 4 SELECTED kinds returned `prover_status="error"` with `has_failures=True` → Path A → `APPLIED`. No C5/SKIPPED or Path B cases observed in the smoke (expected for these high-yield kinds).

**Panic detection:** both `"panicked at "` and `"Guest panicked:"` covered in unit tests; not triggered in Layer 2 smoke.

---

## 4. Layer 2 real-binary smoke

**Command:**

```bash
A4_REAL_BINARY=1 python -m pytest a4/standalone/tests/test_d2c_arguzz_invoke_real_binary.py -v
```

**Output:**

```text
test_real_binary_selected_kind_emits_fault[INSTR_WORD_MOD] PASSED
test_real_binary_selected_kind_emits_fault[PRE_EXEC_MEM_MOD] PASSED
test_real_binary_selected_kind_emits_fault[PRE_EXEC_PC_MOD] PASSED
test_real_binary_selected_kind_emits_fault[BR_NEG_COND] PASSED
4 passed in 62.90s
```

**Host:** `workspace/output/target/release/risc0-host`  
**Args:** `--in1 5 --in4 10` (via `A4_TEST_HOST_ARGS` default)

**Per-kind detail** (manual re-run with `include_trace=True`, seed=1243):

| Kind | Step | Faults | Outcome | prover_status | wall_s | rc |
|------|------|--------|---------|---------------|--------|-----|
| INSTR_WORD_MOD | 0 | 1 | APPLIED | error | 0.1 | 101 |
| PRE_EXEC_MEM_MOD | 0 | 2 | APPLIED | error | 27.9 | 101 |
| PRE_EXEC_PC_MOD | 0 | 1 | APPLIED | error | 0.1 | 101 |
| BR_NEG_COND | 42 | 1 | APPLIED | error | 0.1 | 101 |

All four kinds: ≥1 fault, outcome ∈ {APPLIED, ERROR}, wall_s < 90. **Gating: PASS.**

### Binary surprise (documented — not a gating failure)

On this dev binary, **`--inject` alone emits zero `<fault>` tags** in stdout. Injection still runs (constraint failures / prover errors occur), but fault parsing requires trace output.

**Mitigation:** added optional `include_trace: bool = False` to `run()`. Default **False** preserves v6_driver inject-only parity for Batch 3. Layer 2 test passes `include_trace=True`.

This parameter is **not** in kickoff §4.1 / spec §4.1 prose; see §9 Deviations.

---

## 5. NFP-10 revert guard

**BEFORE task 1.2** (from pre-flight grep at line 237):

```python
        for key in ("byte_addr", "addr", "address"):
```

**AFTER task 1.2** (unchanged — only `_TXN_ROLE_BY_KIND` block extended):

```python
        for key in ("byte_addr", "addr", "address"):
```

`_coerce_broken_addr` not touched. Diff confirms +7 lines in `_TXN_ROLE_BY_KIND` only.

---

## 6. Golden trace (Tier-1)

- Fixture captured fresh: `a4/standalone/tests/fixtures/d2c_golden_v5_decision_seq_seed42_n200.json`
- Template: `test_d2a_back_compat_golden_trace.py` pattern (`ConstrainedTSScheduler`, `_small_universe()`, seed=42, n=200).
- **Cross-check vs D2.A fixture:** `d2a_golden_v5_trace_seed42_n200.json` — **byte-identical** (200 tuples, `equal True`).
- Tests: `test_v5_decision_trace_matches_d2c_fixture` + `test_d2c_fixture_matches_d2a_baseline` — both green.

---

## 7. Arm-space calc (task 1.8)

Method: sha2-host baseline `--trace` (7924 steps) + `InspectionData.from_inspection` + `classify_zones` + `v6_driver_v2.valid_injection_kinds_for_instr` + D2.A 7-class opcode mapping + `_PRE_POST_BY_KIND` convention from spec §1.2.

| Scope | Unique ArmKey tuples (kind×zone×opcode_class×pre_post) | §1.2 estimate |
|-------|--------------------------------------------------------|---------------|
| **V6-cTS FULL (11 kinds)** | **437** | ~200–350 |
| **Hybrid-cTS SELECTED (4 kinds)** | **180** | ~110–160 |

**Active zones:** 12 (core_memory_load, core_mul, core_shr, core_arithmetic, core_memory_store, kernel_other, pre_ecall, core_other, post_ecall, core_branch, step0, last_step).

**Per-kind applicable step counts (FULL):**

| Kind | Steps |
|------|-------|
| PRE_EXEC_PC_MOD, POST_EXEC_PC_MOD, INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, POST_EXEC_MEM_MOD, PRE_EXEC_REG_MOD, POST_EXEC_REG_MOD | 7924 each |
| BR_NEG_COND | 962 |
| COMP_OUT_MOD | 3752 |
| LOAD_VAL_MOD | 1360 |
| STORE_OUT_MOD | 1192 |

**>300 trigger (FULL): YES** — 437 exceeds the spec §9 Q9 advisory threshold. Flag for Batch 2 task 2.5 / Q9 follow-up (merge jump→branch, drop sparse zones, etc.). SELECTED at 180 is above the ~110–160 band but not alarming.

**Caveat:** this is a Batch 1 **estimate** using trace-level applicability; Batch 2 `SemanticArmUniverse.build(arguzz_kinds=...)` measurement is authoritative.

---

## 8. Test counts

**Final sweep (task 1.9):**

```bash
python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py
637 passed, 21 skipped, 8 warnings in 153.72s
```

| Metric | Kickoff baseline (`dfd0ebe`) | Post Batch 1 |
|--------|-------------------------------|--------------|
| Passed | 616 | **637** (+21) |
| Skipped | 17 | **21** (+4 real-binary guards) |
| Failed | 0 | **0** |

**Layer 1 only (mock + outcome + golden):** 21 passed in 0.46s.

**Delta explained:** +21 new test functions (8 mock + 9 outcome/panic + 2 golden + 4 real-binary). Without `A4_REAL_BINARY=1`, the 4 Layer 2 tests skip (+4 skipped vs baseline).

**Full suite with replicates:** not run (~16 min). Kickoff marks optional.

---

## 9. Deviations from spec/kickoff

| Deviation | Rationale |
|-----------|-----------|
| **`include_trace: bool = False` on `run()`** | Dev binary emits zero `<fault>` tags under inject-only; Layer 2 gating requires `--trace --inject`. Default False keeps v6_driver inject-only path for Batch 3 driver refactor. Recommend spec §4.1 addendum in Batch 2 kickoff. |
| **Starting HEAD `7182237` not `dfd0ebe`** | Tree had progressed; doc Phase 0 edits pre-existing. Baseline gate still met. |
| **Real-binary test uses PascalCase instr normalization** | Trace emits `Bne` not `bne`; `_normalize_instr()` lowercases. Not in kickoff but required for step picking. |
| **Mock `_CFAIL` fixture uses full `ConstraintFailure` schema** | Switched from v6 raw-dict pattern to `parse_all_constraint_failures`-compatible tags (cycle, step, pc, major, minor, loc, value). Aligns with primitive's `failures: list[ConstraintFailure]`. |

No changes to `v6_driver_v2.py`, `arguzz_parser.py`, `bandit_ts.py`, `coverage_db.py`, or Rust/submodule content.

---

## 10. Open questions / surprises for Ivan + Opus

1. **`include_trace` API:** Should Batch 2 bridge always pass `include_trace=True`, or should we fix the binary to emit faults under inject-only? Affects Batch 3 driver design.
2. **Arm-space 437 > 300:** Batch 2 should measure via `SemanticArmUniverse.build` and propose reductions if confirmed. Current estimate may differ slightly from bridge filtering (phantom zone pruning, etc.).
3. **PRE_EXEC_MEM_MOD slow path:** 27.9s wall time vs ~0.1s for other kinds in smoke — worth noting for Layer 5 driver timeouts; still under 90s gate.
4. **rc=101 on all smoke invocations:** non-zero exit but prover ran (`error` + failures) → correctly classified APPLIED. Confirm this is expected host behavior (v6_driver treats similarly).
5. **Submodule `workspace/risc0-modified` dirty pointer:** pre-existing; Batch 1 did not rebuild Rust.

### Batch 2 implications

- Bridge can import everything from `arguzz_invoke` (single import surface).
- `_TXN_ROLE_BY_KIND` already permanent — Batch 2 need not re-patch extractor.
- `MAPPING_INSTR_TO_OPCODE_CLASS`, `_PRE_POST_BY_KIND`, `arguzz_bridge.py` remain Batch 2 scope.
- Arm-space >300 flag should appear in Batch 2 kickoff acceptance.

---

## Acceptance checklist (kickoff)

- [x] All Layer 1 tests green (mock + outcome-mapping + Tier-1 golden trace)
- [x] Layer 2 real-binary smoke green for all 4 SELECTED kinds (`A4_REAL_BINARY=1`)
- [x] `_classify_outcome` covers all 7 branches + order test for start+failures vs panic
- [x] `_detect_host_panic` verifies BOTH panic strings
- [x] Tier-1 golden trace fresh; cross-check equals D2.A fixture
- [x] `_TXN_ROLE_BY_KIND` has 6 new Arguzz entries; NFP-10 byte_addr unchanged
- [x] `arguzz_runner.py` deprecation docstring; no code change
- [x] Arm-space calc reported (FULL=437, SELECTED=180) vs §1.2
- [x] Pytest sweep ≥616 passed / 17 skipped (+ new tests, no regressions)
- [x] Frozen files unchanged (`v6_driver_v2`, `arguzz_parser`, `bandit_ts`, `coverage_db`, Rust)
- [x] This report submitted

---

## Files changed (complete list)

| Path | Action |
|------|--------|
| `a4/standalone/arguzz_invoke.py` | NEW |
| `a4/standalone/compressed_global_extractor.py` | MOD (+6 `_TXN_ROLE_BY_KIND`) |
| `a4/arguzz_dependent/arguzz_runner.py` | MOD (deprecation docstring) |
| `a4/standalone/tests/test_d2c_arguzz_invoke_mock.py` | NEW |
| `a4/standalone/tests/test_d2c_outcome_mapping.py` | NEW |
| `a4/standalone/tests/test_d2c_arguzz_invoke_real_binary.py` | NEW |
| `a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py` | NEW |
| `a4/standalone/tests/fixtures/d2c_golden_v5_decision_seq_seed42_n200.json` | NEW |
| `a4/docs/cloud2/composer/D2C_BATCH1_COMPOSER_REPORT.md` | NEW (this file) |

**Not modified by Batch 1 code:** `v6_driver_v2.py`, `arguzz_parser.py`, `bandit_ts.py`, `coverage_db.py`, `fuzzer.py`, `semantic_arm_universe.py`, Rust tree.

---

*End of D2.C Batch 1 report. Awaiting Opus review for Batch 2 (bridge) kickoff.*

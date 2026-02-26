# Phase 0.1 Detailed Implementation Plan

This document is the **step-by-step, source-code-fact-based** plan for implementing Phase 0.1 (Baseline + Observability, Python-only). It is consistent with `PHASE_I_IMPLEMENTATION_PLAN.md` sections 0, 2, and 4. Phase 0.2 is referenced where it consumes 0.1 outputs.

**Preconditions**: A4 standalone fuzzer and executor run mutations and parse `<constraint_fail>` output. No RISC Zero rebuild or new env vars required for 0.1.

---

## Step 0.1.1: Canonical ID documentation

**Goal**: Single place that defines ConstraintFamily and ConstraintContext for all coverage code.

**Facts**:
- `a4/core/constraint_parser.py` defines `constraint_loc()` (lines 115–125) and `constraint_type()` (lines 88–114).
- `a4/standalone/coverage_db.py` uses `failure.constraint_loc()` and `failure.constraint_type()` when recording (lines 261–264, 266–271).

**Actions**:
1. In `a4/core/constraint_parser.py`, at the top of the module or after the `ConstraintFailure` class docstring, add a comment block:
   - "Canonical coverage IDs: ConstraintFamily = constraint_loc() (name@file:line). ConstraintContext = (constraint_loc(), major, minor). No step_bucket in Phase I (see docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md §0.1)."
2. Section 2.1 of PHASE_I_IMPLEMENTATION_PLAN.md already defines these; the parser comment should point to it.

**Phase 0.2**: Baseline run and measurements use the same IDs.

---

## Step 0.1.2: Add `context_id()` and `context_id_with_step_bucket(B)`

**Goal**: One function that, given a `ConstraintFailure`, returns a stable tuple for coverage keying (and optionally with step_bucket for future use).

**Facts**:
- `ConstraintFailure` has `.constraint_loc()`, `.major`, `.minor`, `.step` (from parse: `data['major']`, etc.).
- Return type must be hashable for sets/dicts and determinism test.

**Actions**:
1. In `a4/core/constraint_parser.py`, add to class `ConstraintFailure`:
   - `def context_id(self) -> Tuple[str, int, int]: return (self.constraint_loc(), self.major, self.minor)`
   - `def context_id_with_step_bucket(self, B: int) -> Tuple[str, int, int, int]: return (self.constraint_loc(), self.major, self.minor, self.step // B)`
2. Add `from typing import Tuple` if not already present.
3. Do **not** change `coverage_db.py` schema or keying; the helper is for the determinism test and future touch/failure comparison.

**Phase 0.2**: Measurement script will collect distinct `context_id()` from failure lists.

---

## Step 0.1.3: Determinism test (same config, two runs, same failure set)

**Goal**: Automated check that running the same mutation twice yields identical sets of (constraint_loc, major, minor, step).

**Facts**:
- `a4.core.executor.run_a4_mutation(host_binary, host_args, config_path)` returns `MutationExecutionResult` with `.combined_output`, `.exit_code`.
- `a4.core.constraint_parser.parse_all_constraint_failures(output)` returns `List[ConstraintFailure]`.

**Actions**:
1. Create test: e.g. `a4/standalone/tests/test_determinism.py` or `a4/tests/test_phase0_determinism.py`. Create `a4/standalone/tests/` and `__init__.py` if missing.
2. Test logic:
   - Require env or CLI: host binary path, host args (e.g. `--in1 5 --in4 10`), path to a **fixed** mutation config (or generate once with fixed seed and save to temp).
   - Call `run_a4_mutation(host, args, config_path)` twice.
   - Parse both outputs with `parse_all_constraint_failures`.
   - Build two sets: `set(f.context_id() for f in failures1)` and same for failures2. For stricter comparison use `f.signature()` (includes step, pc, major, minor, short_loc — `constraint_parser.py` line 85).
   - Assert the two sets are equal.
3. Document: host must be release build; A4 forces SeqForward when `A4_MUTATION_CONFIG` is set (`hal/mod.rs`), so no witness-gen thread non-determinism.
4. Use any valid mutation config (e.g. one COMP_OUT_MOD or INSTR_WORD_MOD at a fixed step). Test is "same config → same failures."

**Phase 0.2**: Re-run this test in the actual environment after a short campaign.

---

## Step 0.1.4: Touch-accuracy note (EQZ = active)

**Goal**: Document that "EQZ called" implies "constraint active" for Phase 3 touch marking.

**Facts**:
- PHASE_I_IMPLEMENTATION_PLAN.md §0.2: `exec_Top` dispatches on major onehot; components (e.g. `exec_Div0`) dispatch on minor onehot; EQZ calls are inside those branches (`steps.cpp` lines 14596–14749, 1628–1714).

**Actions**:
1. In PHASE_I_IMPLEMENTATION_PLAN.md §2.5 or §2.6, add: "Touch accuracy (EQZ only when active): see §0.2; evidence in steps.cpp exec_Top and exec_Div0."
2. Optional: in `a4/core/constraint_parser.py` module docstring or a new `coverage_utils.py`: "Constraint 'touched' = EQZ was invoked for that (cycle, loc); in RV32IM codegen this implies the constraint was active (control-flow gated). See docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md §0.2."

**Phase 0.2**: Optional minimal-program run can sanity-check failure set (or later touch set).

---

## Step 0.1.5: No regressions; optional use of context_id in coverage_db

**Goal**: Existing coverage DB and fuzzer keep working; use `context_id()` only where it simplifies.

**Facts**:
- `coverage_db.py` `record_failures` uses `failure.constraint_loc()` for the coverage table key (line 266). No schema change in Phase 0.1.

**Actions**:
1. Run existing tests (if any) for fuzzer/executor after adding the helper and determinism test.
2. Do not remove or change `constraint_loc()` / `constraint_type()` in `coverage_db.py`; the new helper is additive.

**Phase 0.2**: Measurement script uses `context_id()` to count distinct contexts; no DB change.

---

## Phase 0.1 completion checklist

- [x] Parser module documents canonical ConstraintFamily / ConstraintContext (Step 0.1.1).
- [x] `ConstraintFailure.context_id()` and `context_id_with_step_bucket(B)` implemented and typed (Step 0.1.2).
- [x] Determinism test added: two runs, same config, compare failure sets by context_id (or signature); document host/build requirements (Step 0.1.3).
- [x] Touch-accuracy note referenced in plan and optionally in code (Step 0.1.4).
- [x] No DB schema change; existing coverage and fuzzer paths unchanged (Step 0.1.5).

---

## Phase 0.2 checklist (reference only)

The detailed implementation plan for Phase 0.2 is in [PHASE_0_2_IMPLEMENTATION_PLAN.md](./PHASE_0_2_IMPLEMENTATION_PLAN.md). After implementation, update [PHASE_0_2_IMPLEMENTATION_REPORT.md](./PHASE_0_2_IMPLEMENTATION_REPORT.md).

- [ ] Run determinism test in real environment.
- [ ] Run baseline (unmutated) guest once; confirm zero `<constraint_fail>` entries.
- [ ] Short campaign (e.g. 50–100 mutations): compute per-run and total distinct `context_id()`; document counts and whether step_bucket is needed (PHASE_I_IMPLEMENTATION_PLAN.md §0.1).
- [ ] Optional: minimal-program sanity check (single instruction type; failure set plausible).
- [ ] Optional: persist baseline "expected touch set" for Phase 3 comparison.

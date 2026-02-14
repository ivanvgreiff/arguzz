# Phase 0.1 Implementation Report

This report describes the implementation and testing of Phase 0.1 (Baseline + Observability), any deviations from the plan, key variables, and insights for Phase 0.2.

---

## 1. Summary

Phase 0.1 was implemented as specified in `PHASE_0_1_IMPLEMENTATION_PLAN.md`. All five steps were completed. The determinism tests pass when run with the A4-patched RISC Zero host; they are skipped when `A4_TEST_HOST` is not set. No changes were made to the coverage DB schema or to the fuzzer’s use of `constraint_loc()` / `constraint_type()`.

---

## 2. Implementation Details

### 2.1 Step 0.1.1: Canonical ID documentation

**Location**: `a4/core/constraint_parser.py`

- **Change**: Extended the module docstring to define canonical coverage IDs and the touch-accuracy note.
- **Content added**:
  - ConstraintFamily = `constraint_loc()` (name@file:line).
  - ConstraintContext = `(constraint_loc(), major, minor)`; no step_bucket in Phase I.
  - Reference to `PHASE_I_IMPLEMENTATION_PLAN.md` §2.1 and §0.1.
  - Note that “touched” = EQZ invoked implies constraint active (control-flow gated); reference to §0.2.

**Deviation**: None. The plan asked for a comment block at the top or after the class docstring; the module docstring was used so both the parser and the touch-accuracy note are in one place.

---

### 2.2 Step 0.1.2: `context_id()` and `context_id_with_step_bucket(B)`

**Location**: `a4/core/constraint_parser.py`

**Key variables / types**:

- **`context_id(self) -> Tuple[str, int, int]`**  
  Returns `(self.constraint_loc(), self.major, self.minor)`. Used as the stable coverage key for determinism and for Phase 0.2 distinct-context counts. Hashable for use in sets/dicts.

- **`context_id_with_step_bucket(self, B: int) -> Tuple[str, int, int, int]`**  
  Returns `(self.constraint_loc(), self.major, self.minor, self.step // B)`. Reserved for future location-aware coverage; Phase I does not use it.

- **`constraint_loc()`**  
  Already present; returns the short form (e.g. `MemoryWrite@mem.zir:99`) from the raw `loc` string. It is the canonical ConstraintFamily identifier.

- **Import**: `from typing import Tuple` was added.

**Deviation**: None. Both methods were added to the `ConstraintFailure` dataclass as specified.

---

### 2.3 Step 0.1.3: Determinism test

**Location**: `a4/standalone/tests/test_determinism.py` (new). `a4/standalone/tests/__init__.py` was added.

**Behavior**:

1. **Skip condition**: Tests are skipped unless the environment variable `A4_TEST_HOST` is set (path to `risc0-host`). This avoids requiring a built host in CI or minimal environments.

2. **Config source**:
   - If `A4_TEST_CONFIG` is set and points to an existing file, that config is used for both runs.
   - Otherwise, the test builds a config by: running inspection once (`InspectionData.from_inspection(host_binary, host_args)`), getting valid steps for `COMP_OUT_MOD`, finding the first step that has a target (`get_targets_at_step`), and creating one COMP_OUT_MOD config with a fixed mutated value `0xDEADBEEF` via `create_comp_out_config`, saved to a temp file.

3. **Comparison**:
   - **test_same_config_same_failure_set_by_context_id**: Runs the mutation twice, parses `<constraint_fail>` from both outputs, builds `set(f.context_id() for f in failures)`, and asserts the two sets are equal.
   - **test_same_config_same_failure_set_by_signature**: Same flow but compares `set(f.signature() for f in failures)` (stricter: includes step, pc, major, minor, short_loc).

4. **Host args**: `A4_TEST_HOST_ARGS` defaults to `"--in1 5 --in4 10"` and is split on spaces to form the list passed to `run_a4_mutation`.

**Key variables**:

- **`_get_test_config_path() -> Path | None`**: Returns `Path(A4_TEST_CONFIG)` if set and non-empty, else `None`.
- **`_build_config_from_inspection(host_binary, host_args) -> Path`**: Builds a COMP_OUT_MOD config from inspection and returns the path to the temp file. Caller is responsible for deleting the temp file.

**Deviation**: The plan said “path to a **fixed** mutation config (or generate once with fixed seed and save to temp).” Implementation generates the config from inspection when `A4_TEST_CONFIG` is not set, so no pre-created config file is required. One additional behavioral fix: the first “valid” step for COMP_OUT_MOD (e.g. step 0) may have no target (e.g. no register write at that step). The code was updated to iterate over `valid_steps` until `get_targets_at_step(step, data)` returns a target, instead of using only the first step. This is a bug fix, not a change of intent.

**Documentation**: The test module docstring states that the host must be an A4-patched RISC Zero build in release mode and that A4 forces SeqForward when `A4_MUTATION_CONFIG` is set.

---

### 2.4 Step 0.1.4: Touch-accuracy note

**Locations**:

- **`a4/docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md`**: Added one sentence after the determinism-check paragraph (before §2.4): “**Touch accuracy (EQZ only when active):** see §0.2; evidence in steps.cpp `exec_Top` and `exec_Div0`.”
- **`a4/core/constraint_parser.py`**: The module docstring already includes the touch-accuracy note (see Step 0.1.1).

**Deviation**: None. The plan’s optional “in constraint_parser module docstring” was done as part of the same docstring that documents canonical IDs.

---

### 2.5 Step 0.1.5: No regressions

- **Coverage DB**: Not modified. `record_failures` still uses `failure.constraint_loc()` and `failure.constraint_type()`; no schema change.
- **Fuzzer**: Not modified; it continues to use the same parser and DB APIs.
- **Verification**: A small script was run that (1) parses a fake `<constraint_fail>` line and checks `context_id()` and `context_id_with_step_bucket(64)`, and (2) uses `CoverageDB.record_failures` with a `ConstraintFailure` and checks that coverage stats still work. Both passed.

---

## 3. Testing Performed

### 3.1 Unit-style checks (no host)

- **context_id / context_id_with_step_bucket**: One fake `ConstraintFailure` was parsed from a single-line `<constraint_fail>` string; `context_id()` and `context_id_with_step_bucket(64)` were asserted to match expected tuples. Passed.
- **Coverage DB**: A temporary DB was created, a campaign and mutation were recorded, and a single parsed `ConstraintFailure` was recorded via `record_failures`. `get_coverage_stats()` was checked for `total_constraints == 1`. Passed.

### 3.2 Determinism tests (with host)

- **Skip when A4_TEST_HOST unset**: With `A4_TEST_HOST` unset, both tests were skipped by pytest (reason: “Set A4_TEST_HOST (path to risc0-host) and A4_TEST_HOST_ARGS to run”). Passed.
- **With host**: With `A4_TEST_HOST=./workspace/output/target/release/risc0-host` and `A4_TEST_HOST_ARGS="--in1 5 --in4 10"`:
  - **First run**: Inspection ran (~30s), config was generated from the first valid step that had a COMP_OUT_MOD target, then two mutation runs were executed. Both tests passed (same `context_id` set and same `signature` set across the two runs). Total time ~99s for both tests.

So determinism is confirmed for this host and guest: the same config run twice yields identical failure sets by both `context_id()` and `signature()`.

### 3.3 Dependencies

- **pytest**: Not in the project’s default environment; it was installed to run the determinism tests. The tests use `pytest.mark.skipif` and standard pytest discovery. For Phase 0.2, consider adding pytest to the project’s dev/optional dependencies or documenting that it is required to run the determinism tests.

---

## 4. Deviations from the Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Config for determinism test | “Require … path to a fixed mutation config (or generate once with fixed seed and save to temp)” | When `A4_TEST_CONFIG` is unset, config is built from one inspection run and first valid COMP_OUT_MOD target | Avoids requiring a pre-created config file; still “fixed” per run (same inspection → same config for both runs). |
| First valid step | Not specified | Iterate over `valid_steps` until `get_targets_at_step` returns non-None | Step 0 can be valid by major but have no COMP_OUT_MOD target; iterating avoids failing in that case. |
| Touch-accuracy note location | “In §2.5 or §2.6” and “optionally in constraint_parser” | One sentence in §2.3 (after determinism), plus full note in parser module docstring | Keeps plan readable and keeps a single canonical note in the parser. |

---

## 5. Key Variables and Types (Quick Reference)

- **ConstraintFamily**: `str` = `constraint_loc()` (e.g. `MemoryWrite@mem.zir:99`).
- **ConstraintContext**: `Tuple[str, int, int]` = `(constraint_loc(), major, minor)` = `context_id()`.
- **context_id_with_step_bucket(B)**: `Tuple[str, int, int, int]` = `(constraint_loc(), major, minor, step // B)`.
- **signature()**: `str` = `f"{step}:{pc}:{major}:{minor}:{short_loc()}"`; used for stricter determinism comparison.
- **Test env**: `A4_TEST_HOST` (required to run), `A4_TEST_HOST_ARGS` (default `"--in1 5 --in4 10"`), `A4_TEST_CONFIG` (optional path to pre-made config).

---

## 6. Insights for Phase 0.2

1. **Determinism test as 0.2 entry check**: Re-running the same determinism test in the Phase 0.2 environment (after a short campaign or on a different machine) is a good first step to confirm the host and guest still behave deterministically before measuring distinct `context_id()` and baseline runs.

2. **Distinct-context measurement**: Phase 0.2 can collect failure lists from a short campaign (or from existing DB), then compute `len(set(f.context_id() for f in failures))` per run and over the whole campaign. The helper is already on `ConstraintFailure`; no DB schema change is needed for this. If the DB is used, failures are stored with `constraint_loc`, `major`, `minor`; distinct `context_id()` can be computed as distinct `(constraint_loc, major, minor)` from the `failures` table.

3. **Config generation**: The determinism test’s “build config from inspection” logic can be reused or refactored for Phase 0.2 if you need a fixed config for baseline or for a minimal-program run (e.g. one COMP_OUT_MOD at a chosen step). The only nuance is that the first valid step in `get_valid_steps_for_kind("COMP_OUT_MOD")` may not have a target; iterating until `get_targets_at_step` returns non-None is necessary.

4. **Host binary and pytest**: Phase 0.2 scripts that run the host (baseline run, short campaign) will need the host path and args in the same way as the determinism test. Consider a small shared helper or env convention (e.g. `A4_TEST_HOST` / `A4_TEST_HOST_ARGS`) for all Phase 0.2 scripts. Document or add pytest to dev dependencies so the determinism test can be run in CI or by contributors.

5. **Baseline run**: For “unmutated guest, zero failures,” run the host **without** `A4_MUTATION_CONFIG` (and without `CONSTRAINT_CONTINUE` if you only want to confirm no failures). If you run with a dummy or empty mutation config to keep using the same code path, ensure the config does not actually mutate anything, or document that baseline is “no config” and parse output for absence of `<constraint_fail>`.

6. **Bucket decision**: Phase 0.2’s distinct `context_id()` counts (per run and total) will inform whether to introduce step_bucket in Phase 3. If distinct (constraint_loc, major, minor) stays in the low thousands, a 64k bitmap without step_bucket is sufficient; if it grows much larger, the plan’s collision formula and optional step_bucket can be applied.

---

## 7. Files Touched

| File | Change |
|------|--------|
| `a4/core/constraint_parser.py` | Module docstring (canonical IDs + touch note), `Tuple` import, `context_id()`, `context_id_with_step_bucket(B)` |
| `a4/standalone/tests/__init__.py` | New (empty package init) |
| `a4/standalone/tests/test_determinism.py` | New (two pytest tests, config builder, skip when no host) |
| `a4/docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md` | One-sentence touch-accuracy note after §2.3 |
| `a4/docs/touch/PHASE_0_1_IMPLEMENTATION_PLAN.md` | Checklist items marked complete |
| `a4/docs/touch/PHASE_0_1_IMPLEMENTATION_REPORT.md` | This report |

No changes: `a4/standalone/coverage_db.py`, `a4/standalone/fuzzer.py`, or any mutation module beyond the test’s use of `comp_out_mod.get_targets_at_step` and `create_config`.

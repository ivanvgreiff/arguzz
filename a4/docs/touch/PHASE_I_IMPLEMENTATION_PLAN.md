# Phase I Implementation Plan: Constraint-Failure-Guided Coverage (Phases 0 + 3)

This document is a **fact-based, source-code-grounded** implementation plan for **Phase I**, which combines **Phase 0** (Baseline + Observability) and **Phase 3** (Touch Coverage v2 / per-constraint touched) from Pro_Report_2.md. Phase 1 (touch coverage v1 via easy selectors) is skipped in favor of implementing the more effective per-constraint touch coverage (v2) directly.

**Scope**: Establish stable constraint identifiers, confirm determinism, and implement instrumentation that marks **every constraint evaluation** (touched) during witness generation, then consume this in Python for coverage-guided fuzzing. Phase II (coverage-guided scheduling, corpus, bandits) will follow later.

**Rule**: No guesses. All statements are tied to file paths and code facts; where confidence is not 100%, the gap is stated explicitly.

---

## 1. Source-of-Truth Summary (Facts Only)

### 1.1 Where Constraint Checking Happens

| Fact | Location |
|------|----------|
| All RV32IM constraint checks go through the same macro | `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` line 209: `#define EQZ(val, loc) eqz(ctx, val, loc)` |
| The `eqz` function is the single choke point for both failure reporting and (to be added) touch marking | `witgen.h` lines 178–197: `inline void eqz(ExecContext& ctx, Val a, const char* loc)` |
| `ExecContext` provides cycle index; step, pc, major, minor come from preflight | `witgen.h` lines 104–109: `ExecContext(PreflightTrace& preflight, LookupTables& tables, size_t cycle)`; lines 181–184 use `ctx.preflight.cycles[ctx.cycle].userCycle`, `.pc`, `.major`, `.minor` |
| Witness generation runs per-cycle via `stepExec` → `step_Top` | `ffi.cpp` lines 252–258: `void stepExec(...)` creates `ExecContext` and calls `step_Top(ctx, &data, &global)`; lines 311–314 (SeqForward) loop over `cycle` and call `stepExec` |
| When A4 is active, mode is always SeqForward | `hal/mod.rs` lines 148–150: `let mode = if std::env::var_os("A4_MUTATION_CONFIG").is_some() { StepMode::SeqForward } else { ... }` |
| So during A4 mutation runs there is a single thread for witness gen; no parallel merge of coverage is required | Derived from above |

### 1.2 Constraint Identity (loc String)

| Fact | Location |
|------|----------|
| Each EQZ call site passes a literal `loc` string | e.g. `steps.cpp` line 51: `EQZ((arg0 - x2._super), "Reg(<preamble>:6)");`; line 977: `EQZ(x3.low2._super, "DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)");` |
| Two patterns observed in steps.cpp | (1) `"Name(zirgen/.../file.zir:line)"` (2) `"loc(callsite( Name ( path :line:col) at ...))"` |
| Python normalizes these to a stable short form | `a4/core/constraint_parser.py` lines 48–76: `short_loc()` produces e.g. `DecodeInst@inst.zir:29`; lines 79–85: `signature()` includes step, pc, major, minor, short_loc; lines 88–114: `constraint_type()` (name only) and `constraint_loc()` (short_loc) |

### 1.3 Current Failure Reporting and Parsing

| Fact | Location |
|------|----------|
| Failure line format | `witgen.h` line 185: `printf("<constraint_fail>{\"cycle\":%zu, \"step\":%u, \"pc\":%u, \"major\":%u, \"minor\":%u, \"loc\":\"%s\", \"value\":%u}</constraint_fail>\n", ...)` |
| Parsing in Python | `a4/core/constraint_parser.py` lines 27–45: `ConstraintFailure.parse()`; fields: cycle, step, pc, major, minor, loc, value |
| Coverage DB stores failures by constraint_loc (file:line) | `a4/standalone/coverage_db.py` lines 126–138: `failures` table has constraint_type, constraint_loc; lines 131–138: `coverage` table keyed by constraint_loc |

### 1.4 A3 / Post-Witness DATA Matrix (Context Only)

| Fact | Location |
|------|----------|
| Constraint checking (EQZ) happens during witness build, not after | `a3/README.md` and flow: stepExec → EQZ; A3 mutates after witness build in `mod.rs` lines 217–295, so EQZ has already run |
| A3 inspect dumps row/cycle/block_type per row | `hal/mod.rs` lines 171–215: A3_INSPECT prints `<a3_row_info>` with row, step, pc, major, minor, block_type |
| DATA matrix layout (column meanings) is block-type dependent and was explored empirically in A3; not needed for Phase I touch coverage, which hooks at EQZ time | `a3/README.md` “Column Layout (Block Type Dependent)” |

### 1.5 Gaps (Not Assumed)

- **Lane**: Pro_Report_1/2 mention lane (e.g. “(x21)”). In `steps.cpp`, loc strings do not consistently include a “(xN)” lane suffix in the form reported in the user’s examples. **Unresolved**: whether “(x21)” is added by display code or exists in some loc strings. Phase I will not rely on lane; context = (family, major, minor [, step_bucket]).
- **CUDA path**: Touch coverage in this plan targets the **C++ CPU witgen** path only (`ffi.cpp` → `stepExec` → `witgen.h` eqz). The CUDA kernel has its own `eqz` in `kernels/cuda/witgen.h`; A4 forces sequential CPU mode when `A4_MUTATION_CONFIG` is set, so CPU path is the one used. If a future build uses CUDA for witgen in A4 mode, a separate instrumentation pass would be needed (not in Phase I scope).
- **Exact number of EQZ sites**: `steps.cpp` has many EQZ calls; the report “36 unique constraints” is from a campaign and may reflect constraint_loc granularity. No attempt here to enumerate all sites; instrumentation is at the single `eqz()` implementation in `witgen.h`.

---

## 2. Phase 0: Baseline + Observability

**Goal**: Stable `ConstraintFamily` and `ConstraintContext` IDs, and confirmed determinism so that “same mutation twice → same failures and same metadata.”

### 2.1 Stable ConstraintFamily ID (Already Present)

- **Definition**: `ConstraintFamily := (constraint_name, zir_file, zir_line)`.
- **Facts**: Python already exposes this as `constraint_loc()` (e.g. `MemoryWrite@mem.zir:99`) and `constraint_type()` (name only). Stored in DB as `constraint_loc` and `constraint_type` (`coverage_db.py`).
- **Action**: Formalize in code/docs that the **canonical** family ID for coverage is `constraint_loc()` (name + file + line). Use this consistently in Phase 3 bitmap keys so that Python and C++ agree on the same string format for “loc” (see 3.2).

### 2.2 Stable ConstraintContext ID

- **Definition**: `ConstraintContext := (ConstraintFamily, major, minor)` with optional `step_bucket = step // B` (e.g. B=64).
- **Facts**: `ConstraintFailure` already has major, minor, step (`constraint_parser.py`). No step_bucket in current schema.
- **Actions**:
  1. Add a small helper (e.g. in `constraint_parser.py` or a new `coverage_utils.py`): given a `ConstraintFailure`, compute `context_id = (constraint_loc(), major, minor)` and optionally `(constraint_loc(), major, minor, step // B)`.
  2. Use this same tuple for (a) Python-side failure coverage keying and (b) the C++ touch bitmap key (after normalizing loc to the same string form; see 3.2). No schema change required for Phase 0 if we only add the helper; DB can stay keyed by constraint_loc for “violated” coverage.

### 2.3 Determinism Check

- **Requirement**: Running the same mutation (same config file, same host binary, same host args) twice must yield the same set of failure records (same constraint_loc, major, minor, step, etc.) and, after Phase 3, the same touch set.
- **Facts**: Step selection and value generation can use a fixed seed (`fuzzer.py` / `--seed`). Executor runs host with `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE` (`executor.py` lines 159–161). No evidence of non-determinism in the parser or DB.
- **Actions**:
  1. Add a small test or script: run the same mutation config twice, parse both outputs, compare sets of `(constraint_loc(), major, minor, step)` (and optionally cycle). Fail if they differ.
  2. Document that RISC Zero host must be built in release mode and that no ASLR or thread-scheduling-dependent behavior should affect witness order; A4 already forces SeqForward.

### 2.4 Deliverables (Phase 0)

- [ ] Document canonical ConstraintFamily = `constraint_loc()` and ConstraintContext = `(constraint_loc(), major, minor)` (+ optional step_bucket) in code comments or a4/docs.
- [ ] Add `context_id()` (and optionally `context_id_with_step_bucket(B)`) on `ConstraintFailure` or in a shared util used by coverage_db and future touch logic.
- [ ] Add determinism test: two runs, same config → same failure set.
- [ ] (Optional) Run baseline (unmutated) guest once with failure parsing; confirm zero failures and record which constraints would be “touched” for that run once Phase 3 is in place (baseline touch set).

---

## 3. Phase 3: Touch Coverage v2 (Per-Constraint Touched)

**Goal**: Instrument the constraint evaluation path so that **every** time an EQZ is executed (whether the constraint passes or fails), we record that the corresponding (context) was “touched.” Emit a compact coverage representation from C++ and consume it in Python.

### 3.1 Semantics of “Touched”

- In this codebase, **reaching** the `eqz(ctx, val, loc)` call for a given cycle means the generated step code for that cycle executed that constraint check. Control flow in `steps.cpp` is already gated by major/minor and instruction logic, so we do not need to check a separate selector: **if eqz is called, the constraint is active for this (cycle, loc)**. Thus “touched” = “eqz was invoked with this (loc, major, minor, step).”
- **Implementation**: At the very beginning of `eqz()` in `witgen.h`, before `if (a.asUInt32())`, call a new function that updates a touch-coverage structure keyed by a stable (loc, major, minor, step_bucket) or (loc, major, minor). See 3.2–3.4.

### 3.2 C++: Normalized “loc” for Bitmap Key

- **Requirement**: The key used in the C++ bitmap must match what Python will use so that Python can merge touch coverage with the same ConstraintContext as failures.
- **Facts**: C++ has the raw `loc` string (e.g. `"DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)"`). Python’s `short_loc()` normalizes to `DecodeInst@inst.zir:29` via regexes in `constraint_parser.py` (lines 56–76).
- **Options**: (A) Implement the same normalization in C++ (duplicate regex/logic). (B) Have C++ emit raw `loc` and have Python normalize when parsing touch coverage. (C) Have C++ emit a precomputed “family” string from a small helper that mirrors Python’s short_loc.
- **Recommendation**: (B) for Phase I: C++ sends raw `loc` (and cycle, step, pc, major, minor) in the touch event; Python normalizes with existing `ConstraintFailure`-style logic (or a shared normalizer) and then builds context_id. That avoids C++ string/regex complexity and keeps a single source of truth for “constraint_loc” in Python. If performance of many string emissions becomes an issue, we can later add a C++-side normalization or a compact numeric ID table.

### 3.3 C++: Touch Coverage Storage and Emission

**Location**: All changes in `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/`.

1. **Touch accumulator**
   - Add a global (or static) structure used only when `A4_COVERAGE_TOUCH` (or similar) env var is set. Because A4 forces SeqForward, a single global is safe.
   - Structure: AFL-style bitmap. For example, `uint8_t cov_touch[MAP_SIZE]` with `MAP_SIZE = 65536`. For each touch, compute:
     - `key = (loc_str, major, minor, step_bucket)` with step_bucket = step / B (e.g. B=64). Use a simple hash (e.g. FNV-1a or djb2) over the concatenation of these, then `idx = hash % MAP_SIZE`, then `cov_touch[idx] = min(255, cov_touch[idx] + 1)` (saturating).
   - **Fact**: `eqz` is called from generated code with `ctx` and `loc`. So we have access to `ctx.preflight.cycles[ctx.cycle].userCycle`, `.pc`, `.major`, `.minor` and `loc`. Step and major/minor are enough for context; step_bucket = step / B reduces cardinality.

2. **When to record**
   - In `witgen.h`, at the start of `inline void eqz(ExecContext& ctx, Val a, const char* loc)`:
     - If `getenv("A4_COVERAGE_TOUCH")` is set, call `a4_touch_mark(ctx, loc)` (implemented in a new file or in `ffi.cpp` to avoid pulling env/stdio into header). Pass at least: cycle, step, pc, major, minor, loc (pointer).
   - Do **not** mark in the ExtVal overload; that one calls the Val overload per element, so marking once per Val is enough (otherwise we’d double-count).

3. **When to emit**
   - After the witgen loop in `risc0_circuit_rv32im_cpu_witgen` (`ffi.cpp`): when `A4_COVERAGE_TOUCH` is set and mode was SeqForward, after the `for (size_t cycle = 0; cycle < lastCycle; cycle++) { stepExec(...); }` loop, call a function that:
     - Serializes `cov_touch[0..MAP_SIZE-1]` to a single line, e.g. base64 or comma-separated bytes, and prints `<a4_touch_coverage>...</a4_touch_coverage>` (or similar tag) to stdout.
     - Clears the bitmap for the next run (if the process is reused).
   - **Fact**: In SeqForward we return only after the loop completes (or after an exception). So one emission per witgen invocation.

4. **Optional: emit raw touch list for debugging**
   - Alternatively or in addition, for a “verbose” mode, append each (loc, step, major, minor) to a list and at the end print a JSON array inside the tag. That would allow Python to build an exact set for debugging; for normal runs the bitmap is enough for scheduling.

### 3.4 Python: Parse Touch Coverage and Merge

- **New parser**: In `a4/core/` (e.g. `touch_coverage_parser.py` or extend `constraint_parser.py`), add:
  - Parse `<a4_touch_coverage>...</a4_touch_coverage>` from combined stdout/stderr.
  - Decode the bitmap (base64 or whatever format was chosen).
  - No need to “invert” the bitmap to a set of context IDs for the basic merge: we only need to compare two bitmaps (e.g. global union vs current run) to compute “new” bits. So: maintain a global `cov_touch_global` (numpy array or list of length MAP_SIZE); for the current run bitmap `run_touch`, compute `new_bits = (run_touch > 0) & (cov_touch_global == 0)`, then update `cov_touch_global = max(cov_touch_global, run_touch)` (element-wise max or union).
- **Context for scheduling (Phase II)**: When we later implement corpus and rarity, we may need to map bitmap indices back to approximate (constraint_loc, major, minor, step_bucket). That is not required for Phase I; Phase I only needs to (a) emit touch bitmap from C++, (b) parse it in Python, (c) merge into global and detect “new” coverage for a run.

### 3.5 Executor and Fuzzer Integration

- **Executor**: When running a mutation, set `A4_COVERAGE_TOUCH=1` in the env (same way as `CONSTRAINT_CONTINUE` and `A4_MUTATION_CONFIG`) so that the host emits touch coverage. No change to how stdout/stderr are captured.
- **Fuzzer / DB**: In the same place where `parse_all_constraint_failures(output)` is called, also run the touch-coverage parser on `output`. Store the run’s touch bitmap (or “new touch count”) and optionally the merged global bitmap. For Phase I, “new touch bits” can be the reward signal (count of indices where run had touch and global did not); actual use in scheduling is Phase II.

### 3.6 Constants and Configuration

- **MAP_SIZE**: 65536 (or 2^16) is a reasonable default; document in one place (C++ and Python).
- **B (step bucket size)**: 64 or 128; make it a named constant in C++ and Python so they match. If we omit step_bucket from the key to reduce complexity in Phase I, we can add it later; then the key is just (loc, major, minor) and the bitmap will merge touches across steps for the same context.
- **Hash function**: Pick one (e.g. FNV-1a) and implement the same in C++ and (if ever needed) in Python for inverse mapping.

### 3.7 Exact Code Anchors (for implementers)

- **eqz() entry point**  
  File: `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h`  
  Current code at lines 178–180:
  ```cpp
  inline void eqz(ExecContext& ctx, Val a, const char* loc) {
    if (a.asUInt32()) {
  ```
  Insert the touch-mark call immediately after the opening `{`, before `if (a.asUInt32())`, so that every invocation (pass or fail) is counted once.

- **Emission point**  
  File: `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp`  
  SeqForward branch at lines 311–315:
  ```cpp
    case kStepModeSeqForward:
      for (size_t cycle = 0; cycle < lastCycle; cycle++) {
        stepExec(*buffers, *preflight, tables, cycle);
      }
      break;
  ```
  After the `for` loop (before `break;`), add: if `A4_COVERAGE_TOUCH` is set, call the function that serializes the global touch bitmap to stdout and clears it.

### 3.8 Deliverables (Phase 3)

- [ ] **C++**: In `witgen.h`, at entry of `eqz(ExecContext& ctx, Val a, const char* loc)`, call `a4_touch_mark(ctx, loc)` when `A4_COVERAGE_TOUCH` is set.
- [ ] **C++**: Implement `a4_touch_mark` and bitmap (e.g. in `ffi.cpp` or `coverage.cpp`); hash(loc, major, minor, step_bucket) % MAP_SIZE, saturating increment.
- [ ] **C++**: After the SeqForward witgen loop in `risc0_circuit_rv32im_cpu_witgen`, if `A4_COVERAGE_TOUCH` is set, serialize bitmap to stdout as `<a4_touch_coverage>...</a4_touch_coverage>` and clear bitmap.
- [ ] **Python**: Parser for `<a4_touch_coverage>`; merge into global bitmap; compute “new touch bits” for the run.
- [ ] **Python**: Executor sets `A4_COVERAGE_TOUCH=1` when running mutations (or under a flag).
- [ ] **Python**: Fuzzer/DB record “new touch count” per run; optionally persist global bitmap (e.g. in DB or a file) for restarts.
- [ ] **Docs**: Update a4/docs/standalone (and touch/) to describe A4_COVERAGE_TOUCH, bitmap format, and Phase I scope.

---

## 4. Implementation Order (Incremental)

1. **Phase 0.1** – ConstraintContext helper and determinism test (Python only).
2. **Phase 0.2** – Document ConstraintFamily/ConstraintContext and run baseline (unmutated) once; confirm zero failures.
3. **Phase 3.1** – C++: touch accumulator + `a4_touch_mark` + call from `eqz`; no emission yet. Verify with a debug print that touches are being recorded (e.g. count per run).
4. **Phase 3.2** – C++: emission after SeqForward loop; Python: parse and merge; executor sets env.
5. **Phase 3.3** – Fuzzer/DB: record new touch count per run; optional persistence.
6. **Phase 3.4** – Documentation and constants (MAP_SIZE, B, hash) in one place; add tests that same mutation yields same touch bitmap (determinism for touch).

---

## 5. Files to Touch (Summary)

| Area | Files |
|------|--------|
| C++ touch marking and bitmap | `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` (eqz entry), new or existing `ffi.cpp` (a4_touch_mark, bitmap, emission after loop) |
| Python constraint context | `a4/core/constraint_parser.py` or new `a4/core/coverage_utils.py` (context_id helpers) |
| Python touch parsing and merge | New `a4/core/touch_coverage_parser.py` (or under constraint_parser); merge logic |
| Executor env | `a4/core/executor.py` (add A4_COVERAGE_TOUCH when running mutation) |
| Fuzzer / DB | `a4/standalone/fuzzer.py`, `a4/standalone/coverage_db.py` (record new touch count; optional schema for global bitmap) |
| Docs | `a4/docs/standalone/README.md`, `a4/docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md` (this file) |
| Tests | New test or script for determinism (failures + touch) |

---

## 6. What Phase I Does Not Include

- **Phase 1 (touch v1 via selectors)**: Skipped; we go straight to per-constraint touch (v2).
- **Phase 2 (scheduling, corpus, bandits)**: Deferred to Phase II; Phase I only collects touch coverage and “new touch” count.
- **Coherence scoring, cascade control**: Pro_Report_2 Phase 4; not in Phase I.
- **Lane in context**: Omitted until we have a clear, stable source for lane (e.g. from loc or from trace).
- **CUDA witgen**: Not instrumented; A4 uses CPU SeqForward.

---

## 7. Agreement on Touch v1 vs v2

You asked whether touch coverage v1 is just a weaker version of v2. **Yes.** Pro_Report_2 describes:
- **v1**: “Easy selectors” (major/minor, mem read/write flags) to get component-level touch without per-constraint gating.
- **v2**: Per-constraint touched by instrumenting the constraint evaluation (eqz) so that every (context) that was actually evaluated is marked.

Because we have a single choke point (`eqz` in witgen.h) and the same run already gives us (cycle, step, pc, major, minor, loc), implementing v2 is a small step: mark on every `eqz` call. That gives strictly more information than v1 (we see exactly which constraint families and contexts were evaluated, not just which major/minor). So implementing v2 directly is the right choice and makes v1 redundant for our pipeline.

---

*End of Phase I Implementation Plan. All assertions above are tied to the cited files and line ranges; any change in the repo should be reflected by re-checking those locations.*

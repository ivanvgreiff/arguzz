# Phase II.0 Detailed Implementation Plan: Baseline Touch Snapshot

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.0** (Baseline Touch Snapshot). It is the first sub-phase of Phase II and is consistent with [PHASE_II_MASTER_IMPLEMENTATION_PLAN.md](./PHASE_II_MASTER_IMPLEMENTATION_PLAN.md) §5 (Phase II.0).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites

### 1.1 What Phase I delivered that Phase II.0 uses

| Artifact | Location | Used for |
|----------|----------|----------|
| `run_baseline(host_binary, host_args) -> str` | `a4/core/executor.py` lines 139–153 | Running the host without mutation |
| `parse_touch_bitmap(output) -> Optional[bytes]` | `a4/core/touch_coverage.py` lines 32–50 | Extracting touch bitmap from host output |
| `distinct_touched(bitmap) -> int` | `a4/core/touch_coverage.py` lines 99–101 | Counting non-zero entries |
| `total_touches(bitmap) -> int` | `a4/core/touch_coverage.py` lines 103–105 | Summing all entries |
| `A4_COVERAGE_TOUCH=1` in env triggers C++ bitmap emission | `ffi.cpp` SeqForward block | C++ side: emit `<a4_touch_coverage>` tag |
| Phase 0.2 confirmed: baseline (unmutated) run produces zero `<constraint_fail>` lines | Phase 0.2 report §Step 0.2.2 | Confidence that baseline runs cleanly |

### 1.2 What Phase II.0 does NOT do (left to later sub-phases)

- **II.1**: Arm universe construction (step bucketing, arm enumeration).
- **II.1.5**: Pilot calibration (parameter estimation from random mutations).
- **II.2–II.6**: Reward, bandit, integration, tuning, persistence.

Phase II.0 only captures the baseline touch bitmap and records it for diagnostic use.

---

## 2. Source-of-Truth Facts

### 2.1 How `run_baseline` works

| Fact | Location |
|------|----------|
| `run_baseline` runs the host with `env=dict(os.environ)` — no `A4_MUTATION_CONFIG`, no `CONSTRAINT_CONTINUE` | `executor.py` lines 146–151 |
| It does **not** set `A4_COVERAGE_TOUCH` | `executor.py` line 151: `env=dict(os.environ)` inherits whatever is in the shell environment |
| Returns combined stdout+stderr as a string | `executor.py` line 153: `return result.stdout + result.stderr` |

**Key issue**: `run_baseline` does not currently set `A4_COVERAGE_TOUCH=1`. For Phase II.0, we need the baseline run to emit the touch bitmap. There are two options:

- **(A)** Modify `run_baseline` to accept an optional `extra_env` dict and merge it in. This is the cleaner approach — it keeps `run_baseline` flexible without hardcoding touch coverage.
- **(B)** Set `A4_COVERAGE_TOUCH=1` in the shell environment before calling `run_baseline`. This works but is fragile (depends on caller remembering to set it).

**Decision**: Option (A). Add an optional `extra_env: Optional[Dict[str, str]] = None` parameter to `run_baseline`. When provided, merge it into the env dict. This is a small, backwards-compatible change (existing callers pass no `extra_env` and behavior is unchanged).

### 2.2 What `parse_touch_bitmap` expects

| Fact | Location |
|------|----------|
| Searches for `<a4_touch_coverage>BASE64</a4_touch_coverage>` in the output string | `touch_coverage.py` lines 41–50 |
| Returns `bytes` of length 65536, or `None` if not found / decode fails | Same |

### 2.3 What the baseline run should produce

- **Zero `<constraint_fail>` lines**: Confirmed in Phase 0.2.
- **One `<a4_touch_coverage>` line**: When `A4_COVERAGE_TOUCH=1` is set, the C++ SeqForward block emits the bitmap after the witgen loop. This happens for *all* runs (mutated or unmutated) as long as the env var is set.
- **One `<a4_touch_debug>` line**: Similarly emitted (Phase 3.1 debug summary).
- **Non-zero bitmap**: The baseline (unmutated) run still executes all ~32768 cycles of witness generation, which evaluates EQZ at every cycle for active constraints. So the bitmap will have non-zero entries (the "base touch set" — which constraints are evaluated in normal, unmutated execution).

**Confidence note**: I have not directly run `run_baseline` with `A4_COVERAGE_TOUCH=1` to verify the bitmap is emitted. However: (1) the C++ code checks `std::getenv("A4_COVERAGE_TOUCH")` at runtime, not at build time; (2) the env var is checked in `a4_touch_mark` (called from every `eqz`) and in the SeqForward block (for emission); (3) the baseline run goes through the same `risc0_circuit_rv32im_cpu_witgen` → SeqForward → `stepExec` → `step_Top` → `eqz` path as a mutation run. So the bitmap should be emitted. This will be verified during implementation.

---

## 3. Step-by-Step Implementation Plan

### Step II.0.1: Extend `run_baseline` with optional `extra_env`

**Goal**: Allow `run_baseline` to accept additional environment variables (like `A4_COVERAGE_TOUCH=1`) without hardcoding them.

**Facts**:
- `run_baseline` at `executor.py` lines 139–153 builds `env=dict(os.environ)`.
- No other callers pass extra env (the only call site is `test_phase02_baseline.py` line 30).

**Actions**:

1. In `run_baseline`, add parameter `extra_env: Optional[Dict[str, str]] = None`.
2. When building the env, merge: `env = dict(os.environ); if extra_env: env.update(extra_env)`.
3. Existing callers pass no `extra_env` and are unaffected.
4. Add `Dict` to the typing imports if not already present.

**Deliverable**: `run_baseline` accepts optional `extra_env`.

---

### Step II.0.2: Create baseline touch snapshot function

**Goal**: A function that runs the baseline with touch enabled and returns the parsed bitmap plus summary statistics.

**Actions**:

1. Create `a4/standalone/baseline_touch.py` (new module) with:

   - `capture_baseline_touch(host_binary: str, host_args: List[str]) -> BaselineTouch` where `BaselineTouch` is a dataclass:
     ```python
     @dataclass
     class BaselineTouch:
         bitmap: bytes                    # 65536-byte touch bitmap
         distinct_buckets: int            # number of non-zero entries
         total_touches: int               # sum of all entries
         touched_indices: List[int]       # sorted list of non-zero indices
     ```
   - The function calls `run_baseline(host_binary, host_args, extra_env={"A4_COVERAGE_TOUCH": "1"})`, then `parse_touch_bitmap(output)`, then computes the summary fields.
   - Raises `RuntimeError` if the bitmap is `None` (parsing failed or tag not found).

2. Optionally add `save_baseline(baseline: BaselineTouch, path: Path)` and `load_baseline(path: Path) -> BaselineTouch` for persistence to a JSON file (indices + stats) and/or raw bytes. This is useful so the baseline doesn't need to be re-run for every campaign.

**Why a separate module**: Baseline touch capture is a one-time setup step, conceptually distinct from the fuzzer's campaign loop. Keeping it in its own module avoids adding Phase II logic to `fuzzer.py` prematurely. Phase II.4 (campaign integration) will call this module at campaign start.

**Deliverable**: `baseline_touch.py` with `capture_baseline_touch` and optional persistence.

---

### Step II.0.3: Add test for baseline touch

**Goal**: Verify that the baseline produces a non-None touch bitmap with plausible statistics.

**Actions**:

1. Create `a4/standalone/tests/test_baseline_touch.py` with:
   - `test_baseline_produces_touch_bitmap`: Skipped unless `A4_TEST_HOST` set. Calls `capture_baseline_touch(host, args)`. Asserts:
     - `baseline.bitmap is not None`
     - `len(baseline.bitmap) == 65536`
     - `baseline.distinct_buckets > 0` (at least some constraints are evaluated)
     - `baseline.distinct_buckets < 65536` (not every bucket — that would indicate a bug)
     - `baseline.total_touches > 0`
   - Optionally: assert `baseline.distinct_buckets` is in a plausible range (e.g., 1000–5000 based on Phase 3.2's measurement of ~1599 for a mutated run; the baseline should be similar since the program executes the same cycles).

**Deliverable**: Test that validates baseline touch emission.

---

### Step II.0.4: Run the test and record results

**Goal**: Execute the baseline touch test and document the snapshot statistics.

**Actions**:

1. Build the host if not already built (it should already be built from Phase 3.2/3.3 testing).
2. Run: `A4_TEST_HOST=./workspace/output/target/release/risc0-host A4_TEST_HOST_ARGS="--in1 5 --in4 10" python -m pytest a4/standalone/tests/test_baseline_touch.py -v`.
3. Record in the implementation report:
   - `distinct_buckets` (expected: ~1599 based on Phase 3.2 measurement)
   - `total_touches` (expected: ~192676)
   - Whether the baseline bitmap matches a mutated run's bitmap (they should be very similar since the same program/inputs are used; the mutation changes values but not which major/minor branches execute)

**Deliverable**: Baseline statistics documented. These become the reference point for Phase II diagnostic comparisons.

---

## 4. Files to Touch (Phase II.0 only)

| File | Change |
|------|--------|
| `a4/core/executor.py` | Add `extra_env` parameter to `run_baseline`. |
| `a4/standalone/baseline_touch.py` | **New**: `BaselineTouch` dataclass, `capture_baseline_touch`, optional persistence. |
| `a4/standalone/tests/test_baseline_touch.py` | **New**: Test that baseline produces valid touch bitmap. |
| `a4/docs/touch/Phase II/PHASE_II_0_IMPLEMENTATION_PLAN.md` | This plan. |

No changes to: `ffi.cpp`, `witgen.h`, `touch_coverage.py`, `fuzzer.py`, `constraint_parser.py`, `coverage_db.py`, `step_selector.py`, `bandit.py` (doesn't exist yet).

---

## 5. Alignment with Master Plan

| Master plan reference | Phase II.0 coverage | Notes |
|----------------------|---------------------|-------|
| §5 Phase II.0: "Run baseline with touch enabled; record baseline touched indices and distinct count" | Steps II.0.1–II.0.4 | As specified. |
| §5 Phase II.0: "baseline coverage snapshot and campaign state init code" | `BaselineTouch` dataclass + `capture_baseline_touch` | As specified. |
| §5 Phase II.0: "NOT used in the reward function (reward compares against campaign global, not baseline)" | Correct. The baseline is diagnostic only. Phase II.2 CoverageState initializes from zeros, not from baseline. | As specified. |
| §0.3: "Use existing `global_bitmap[i] > 0` as seen test" | Not affected by II.0. Global bitmap is managed by the fuzzer, not by baseline capture. | Consistent. |

### Deviations from master plan

1. **`run_baseline` modification**: The master plan says "Optional: allow `run_baseline` to accept env override for `A4_COVERAGE_TOUCH`." Phase II.0 implements this as a generic `extra_env` parameter, not specific to `A4_COVERAGE_TOUCH`. **Reason**: More flexible; can be reused for other env vars in the future. The master plan lists this as optional; Phase II.0 treats it as required because without it, there is no clean way to get the baseline touch bitmap.

2. **Separate `baseline_touch.py` module**: The master plan does not specify a module name. Phase II.0 creates a new `a4/standalone/baseline_touch.py`. **Reason**: Keeps baseline capture logic separate from the fuzzer campaign loop. Phase II.4 will import from this module when integrating.

No other deviations.

---

## 6. Key Variables and Functions

### 6.1 `run_baseline(host_binary, host_args, extra_env=None) -> str`

- **What**: Runs the host without mutation. Now accepts optional extra environment variables.
- **Why extended**: To set `A4_COVERAGE_TOUCH=1` without modifying the function's core behavior (no mutation config, no CONSTRAINT_CONTINUE).

### 6.2 `BaselineTouch` (dataclass)

- **`bitmap: bytes`** — The raw 65536-byte touch bitmap from the unmutated run.
- **`distinct_buckets: int`** — Number of non-zero entries (distinct constraint contexts touched).
- **`total_touches: int`** — Sum of all entries (total EQZ calls across all cycles).
- **`touched_indices: List[int]`** — Sorted list of indices where `bitmap[i] > 0`. This is the explicit "baseline touch set" — the set of bitmap buckets that are touched during normal (unmutated) execution.

### 6.3 `capture_baseline_touch(host_binary, host_args) -> BaselineTouch`

- **What**: Runs the baseline with touch enabled, parses the bitmap, computes summary stats, returns the `BaselineTouch` snapshot.
- **Why a function**: Encapsulates the full baseline capture workflow. Can be called at campaign start (Phase II.4) or independently for diagnostics.

---

## 7. Phase II.0 Completion Checklist

- [ ] Step II.0.1: `run_baseline` extended with `extra_env` parameter.
- [ ] Step II.0.2: `baseline_touch.py` with `BaselineTouch` and `capture_baseline_touch`.
- [ ] Step II.0.3: `test_baseline_touch.py` with plausibility test.
- [ ] Step II.0.4: Test run; baseline statistics documented in report.
- [ ] No changes to C++, fuzzer, or DB.

---

## 8. Dependencies for Phase II.1 (reminders)

Phase II.1 (Arm Universe Construction) needs `InspectionData` to compute `S_k` for each mutation kind and derive `T`, `B_count`, `B`. It does not depend on the baseline touch snapshot. However, Phase II.0 and II.1 can run in sequence and be combined into a single implementation round if desired (the master plan notes: "Sub-phases II.0 and II.1 are small and can be combined into a single subplan").

---

## 9. For Anyone New: What Phase II.0 Is and Why

### What

Phase II.0 captures the **baseline touch set** — the set of constraint contexts that the zkVM evaluates during a normal, unmutated witness generation run. It does this by running the host binary without any mutation but with touch coverage instrumentation enabled (`A4_COVERAGE_TOUCH=1`), which causes the C++ code to record every `eqz` call into a 65536-byte bitmap and emit it in the host's output.

### Why

The baseline touch set is the "ground truth" of what the program exercises without any fuzzer intervention. It serves three purposes:

1. **Diagnostic reference**: When a mutated run produces a different touch bitmap, we can compare it to the baseline to understand what changed. If a mutation caused the program to touch constraint contexts that the baseline never touches, that's particularly interesting.
2. **Sanity check**: The baseline should have ~1599 distinct buckets (from Phase 3.2 measurements). If we see a wildly different number, something is wrong with the instrumentation or the build.
3. **Future Phase II use**: Phase II.2 (reward function) does not use the baseline directly — the reward compares each run against the campaign's growing global bitmap, not against the baseline. But the baseline is valuable for offline analysis and for Phase II.5 (A/B experiments) where we want to understand whether the bandit scheduler is discovering contexts *beyond* what the baseline already covers.

### How Phase II.0 differs from other phases

| Phase | What it does | Nature |
|-------|-------------|--------|
| **Phase I (all)** | Built the touch instrumentation pipeline (C++ → Python → fuzzer) | Infrastructure |
| **II.0** (this) | Captures one unmutated run's touch data as a reference point | **Measurement / setup** |
| **II.1** | Builds the arm universe (bucketed action space for the bandit) | Data structure construction |
| **II.1.5** | Runs pilot mutations to calibrate reward parameters | Calibration |
| **II.2–II.6** | Reward function, bandit, integration, tuning, persistence | Core scheduling system |

Phase II.0 is the simplest sub-phase: one function, one test, one measurement. It is deliberately small to provide a clean starting point before the more complex sub-phases that follow.

---

## 10. New and Withheld Sections

**Sections retained from Phase I plans**: Prerequisites, source-of-truth facts, step-by-step plan, files to touch, alignment/deviations, key variables, completion checklist, for-anyone-new.

**New sections**: §8 (Dependencies for next sub-phase) — same as Phase I plans §7/§9 pattern.

**Sections withheld**: None.

---

*End of Phase II.0 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*

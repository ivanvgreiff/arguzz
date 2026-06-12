# Phase II.1 Detailed Implementation Plan: Arm Universe Construction

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.1** (Arm Universe Construction). It is consistent with [PHASE_II_MASTER_IMPLEMENTATION_PLAN.md](./PHASE_II_MASTER_IMPLEMENTATION_PLAN.md) section 5 (Phase II.1) and section 2.2 (DERIVED parameters).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites from Phase II.0

### 1.1 What Phase II.0 delivered

- `run_baseline` extended with `extra_env` (executor.py).
- `BaselineTouch` snapshot: 1599 distinct buckets, 192676 total touches.
- Rust `mod.rs` fix: `A4_COVERAGE_TOUCH` forces SeqForward.
- Host binary up to date; no rebuild needed.

### 1.2 Phase II.0 insights relevant to II.1

- **T computation**: Phase II.0 report section 5.3 says "T should be computed from actual `get_valid_steps_for_kind(k)` union for all 8 kinds, not assumed from the 3930 total steps."
- **Host/inspection data**: The default guest (`--in1 5 --in4 10`) has `total_steps = 3930` (from `InspectionData.total_steps`, computed as `max(c.step for c in cycles) + 1`). This is the ceiling; `T` will be `<= 3930` depending on whether the last step is valid for at least one mutation kind.

### 1.3 What Phase II.1 does NOT do

- **II.1.5**: Pilot calibration (parameter estimation from random mutations).
- **II.2**: CoverageState + reward.
- **II.3**: Bandit.
- **II.4**: Campaign loop integration.

Phase II.1 only builds the arm universe data structure. It does not run mutations or change the campaign loop.

---

## 2. Source-of-Truth Facts

### 2.1 Mutation kinds

From `fuzzer.py` lines 117-126:
```
MUTATION_KINDS = [
    "COMP_OUT_MOD",       # major 0-4 (compute instructions)
    "LOAD_VAL_MOD",       # major 5 (MEM0 / load)
    "STORE_OUT_MOD",      # major 6 (MEM1 / store)
    "PRE_EXEC_REG_MOD",   # major 0-6 (any instruction)
    "INSTR_TYPE_MOD",     # major 0-6 (any instruction)
    "MEM_VAL_MOD",        # steps with memory transactions
    "INSTR_WORD_MOD_FULL", # major 0-6 or 8
    "INSTR_WORD_MOD_SUR",  # major 0-6 or 8
]
```
K = 8 mutation kinds.

### 2.2 Valid steps per kind

From `inspection_data.py` lines 147-215, `get_valid_steps_for_kind(k)` returns a sorted list of unique step numbers. The valid-step criteria per kind are:

| Kind | Valid when | Major range |
|------|-----------|-------------|
| COMP_OUT_MOD | cycle.major in (0,1,2,3,4) | compute instructions |
| LOAD_VAL_MOD | cycle.major == 5 | loads |
| STORE_OUT_MOD | cycle.major == 6 | stores |
| PRE_EXEC_REG_MOD | cycle.major <= 6 | all instructions |
| INSTR_TYPE_MOD | cycle.major <= 6 | all instructions |
| MEM_VAL_MOD | step has memory txns | any step with mem txns |
| INSTR_WORD_MOD_FULL | cycle.major <= 6 or == 8 | instructions + ECALL |
| INSTR_WORD_MOD_SUR | cycle.major <= 6 or == 8 | instructions + ECALL |

Note: Some kinds share the same step sets (PRE_EXEC_REG_MOD and INSTR_TYPE_MOD both accept major 0-6). This means those kinds will have identical S_k sets and identical arm-bucket populations. The bandit will learn to differentiate them by reward, not by step availability.

### 2.3 InspectionData.total_steps

From `inspection_data.py` line 86: `self.total_steps = max(c.step for c in self.cycles) + 1`. For the default guest, `total_steps = 3930`.

### 2.4 Parameter formulas (from master plan section 2.2)

- **T**: `1 + max(union of S_k for all k)`. In practice, since `get_valid_steps_for_kind` already returns unique sorted steps, T is `1 + max(max(S_k) for k in MUTATION_KINDS)`.
- **B_count**: `pow2_clamp(floor(N / (K * n_target)), B_min, B_max)` where `n_target=3`, `K=8`, `B_min=16`, `B_max=128`.
- **B**: `ceil(T / B_count)`.
- **num_arms**: Count of `(k, b)` pairs where `S_{k,b}` is non-empty.
- **n_min**: `1 if N >= num_arms else 0`.

---

## 3. Step-by-Step Implementation Plan

### Step II.1.1: Create `arm_universe.py` module

**Goal**: A module that computes the arm universe from `InspectionData` and campaign budget N.

**Actions**:

1. Create `a4/standalone/arm_universe.py` with:

   - `pow2_clamp(x, lo, hi) -> int`: Round x down to nearest power of 2, clamp to [lo, hi]. If x < lo, return lo. If x > hi, return hi. Otherwise, return the largest power of 2 <= x.

   - `ArmUniverse` class:
     - Constructor: `__init__(self, data: InspectionData, budget: int, mutation_kinds: List[str])`
     - Computes: `S_k` for each kind, `T`, `B_count`, `B`, enumerates arms.
     - Stores:
       - `self.T: int` -- step horizon
       - `self.B_count: int` -- number of step buckets
       - `self.B: int` -- steps per bucket
       - `self.arms: Dict[Tuple[str, int], List[int]]` -- mapping `(kind, bucket) -> sorted list of valid steps in that bucket`
       - `self.available_arms: List[Tuple[str, int]]` -- list of arms with non-empty step lists
       - `self.num_arms: int` -- len(available_arms)
       - `self.n_min: int` -- forced exploration minimum
       - `self.steps_per_kind: Dict[str, List[int]]` -- S_k per kind (for diagnostics)

   - `summary(self) -> str`: Human-readable summary of the arm universe (T, B_count, B, num_arms, arms per kind, etc.).

**Key implementation detail**: Bucket assignment for step `s` is `b(s) = s // B` (integer division, NOT `s // B_count`). This maps steps 0..B-1 to bucket 0, steps B..2B-1 to bucket 1, etc.

**Why a separate module**: The arm universe is a data structure computed once per campaign from inspection + budget. It is consumed by the bandit (Phase II.3) and the campaign loop (Phase II.4). Keeping it in its own module avoids cluttering `fuzzer.py` and makes it independently testable.

**Deliverable**: `arm_universe.py` with `ArmUniverse` class.

---

### Step II.1.2: Compute DERIVED parameters for default guest + budget

**Goal**: For the default guest program (`--in1 5 --in4 10`), compute and report the concrete values of T, B_count, B, num_arms for a few representative budgets (N=500, N=1000, N=5000).

**Actions**:

1. Write a small script or test that:
   - Runs `InspectionData.from_inspection(host, args)`.
   - Constructs `ArmUniverse(data, N, MUTATION_KINDS)` for N in [500, 1000, 5000].
   - Prints: T, B_count, B, num_arms, n_min, and a summary of arms per kind.

2. This is a diagnostic/verification step, not a permanent feature. The values go into the report.

**Why this matters**: The master plan's confidence gap (section 9 item 1) says "I have not directly verified max(union of S_k) for all 8 kinds." This step resolves that gap.

**Deliverable**: Concrete T, B_count, B, num_arms values documented in the report.

---

### Step II.1.3: Add unit tests

**Goal**: Verify arm universe construction logic without requiring the host binary.

**Actions**:

1. Create `a4/standalone/tests/test_arm_universe.py` with:

   - `test_pow2_clamp`: Verify edge cases (x=1 -> 1; x=41 -> 32; x=200 clamped to 128; x=5 clamped up to 16).
   - `test_arm_universe_synthetic`: Create a fake InspectionData with known cycles, construct ArmUniverse, verify T, B_count, B, arm count, and step-bucket assignment.
   - `test_empty_kinds_handled`: A kind with no valid steps produces no arms for that kind.
   - `test_bucket_assignment`: Verify that step s maps to bucket s // B consistently.

**Deliverable**: Unit tests for arm universe logic.

---

### Step II.1.4: Integration test with real inspection data

**Goal**: Construct the arm universe from real inspection data and verify plausibility.

**Actions**:

1. In `test_arm_universe.py`, add a host-dependent test:
   - `test_arm_universe_real_inspection` (skipped unless A4_TEST_HOST set).
   - Run inspection, construct ArmUniverse with N=1000.
   - Assert: T > 0, B_count in [16, 128], num_arms > 0 and < K * B_count.
   - Print summary for documentation.

**Deliverable**: Integration test confirms real arm universe is plausible.

---

## 4. Files to Touch (Phase II.1 only)

| File | Change |
|------|--------|
| `a4/standalone/arm_universe.py` | **New**: pow2_clamp, ArmUniverse class. |
| `a4/standalone/tests/test_arm_universe.py` | **New**: Unit tests + integration test. |
| `a4/docs/touch/Phase II/PHASE_II_1_IMPLEMENTATION_PLAN.md` | This plan. |

No changes to: executor.py, fuzzer.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs, coverage_db.py, step_selector.py, bandit.py (doesn't exist yet).

---

## 5. Alignment with Master Plan

| Master plan reference | Phase II.1 coverage | Notes |
|----------------------|---------------------|-------|
| Section 5, Phase II.1: "compute S_k, T, B_count, B, enumerate arms" | Steps II.1.1-II.1.2 | As specified. |
| Section 5, Phase II.1: "ArmUniverse data structure mapping (kind, bucket) -> list_of_valid_steps" | ArmUniverse class | As specified. |
| Section 2.2 items 12-15: DERIVED parameter formulas | Implemented in ArmUniverse constructor | As specified. |
| Confidence gap (section 9 item 1): "I have not directly verified max(union of S_k)" | Resolved by Step II.1.2 | Computes T from actual inspection data. |

### Deviations from master plan

1. **`pow2_clamp` behavior**: The master plan says "round to power of two" for B_count. The plan does not specify whether to round up or down. Phase II.1 rounds **down** (largest power of 2 <= x). Reason: rounding down gives fewer buckets (larger B), which means fewer arms and more samples per arm -- better for bandit learning with limited budget. If x < B_min, clamp to B_min.

2. **T definition**: The master plan says `T = 1 + max(union of S_k)`. In practice, `InspectionData.total_steps` is already `1 + max(all steps)`, which is >= T. Phase II.1 computes T from the actual union of S_k to be precise, not from `total_steps`. They may differ if the very last step is not valid for any mutation kind (e.g., it's a CONTROL cycle with major=7). The difference, if any, would be small (a few steps).

No other deviations.

---

## 6. Key Variables and Functions

### 6.1 `pow2_clamp(x, lo, hi) -> int`

Rounds x down to the nearest power of 2, then clamps to [lo, hi]. Used for B_count computation. Example: pow2_clamp(41, 16, 128) = 32.

### 6.2 `ArmUniverse`

- **T**: Step horizon. `1 + max step across all valid steps for all kinds`. Determines the range [0, T-1] that step buckets partition.
- **B_count**: Number of step buckets. Derived from budget N: `pow2_clamp(N // (K * 3), 16, 128)`.
- **B**: Steps per bucket. `ceil(T / B_count)`. Each bucket covers steps [b*B, (b+1)*B - 1].
- **arms**: Dict mapping `(kind, bucket_index) -> [step1, step2, ...]`. Only non-empty entries exist.
- **available_arms**: Flat list of `(kind, bucket_index)` keys with non-empty step lists.
- **num_arms**: `len(available_arms)`. Typically K * B_count minus the empty arm-buckets.
- **n_min**: Forced exploration minimum. `1 if N >= num_arms else 0`.
- **steps_per_kind**: `Dict[str, List[int]]` mapping kind -> S_k. For diagnostics.

### 6.3 Bucket assignment

For step s: `bucket = s // B`. This is deterministic and consistent. Steps 0..B-1 are bucket 0, steps B..2B-1 are bucket 1, etc.

---

## 7. Phase II.1 Completion Checklist

- [ ] Step II.1.1: `arm_universe.py` with `pow2_clamp` and `ArmUniverse`.
- [ ] Step II.1.2: Concrete T, B_count, B, num_arms computed for default guest.
- [ ] Step II.1.3: Unit tests for arm universe logic.
- [ ] Step II.1.4: Integration test with real inspection data.
- [ ] No changes to C++, Rust, executor, fuzzer, or DB.

---

## 8. Dependencies for Phase II.1.5 (reminders)

Phase II.1.5 (Pilot Calibration) needs:
- The arm universe (for random sampling of valid arms/steps during pilot).
- Campaign budget N (to compute N_pilot).
- Existing `ZonedStepSelector` or a simple random selector for pilot runs.

Phase II.1.5 will run N_pilot mutations and calibrate tau_new, tau_fail_count, K_rare from pilot statistics.

---

## 9. For Anyone New: What Phase II.1 Is and Why

### What

Phase II.1 builds the **arm universe** -- the set of all possible actions the coverage-guided scheduler (bandit) can choose from. Each "arm" is a pair `(mutation_kind, step_bucket)`:

- **mutation_kind**: One of 8 types of mutations the fuzzer can apply (e.g., change a computation output, change an instruction type, change a memory value, etc.).
- **step_bucket**: A range of instruction steps in the program. Instead of treating every individual step as a separate choice (which would be ~3930 options), we group consecutive steps into buckets (e.g., 32 buckets of ~123 steps each).

Combining 8 kinds with 32 buckets gives ~256 possible arms. Not all are valid (some mutation kinds can't be applied at some step ranges), so the actual number is smaller.

### Why

The bandit scheduler (Phase II.3) needs a finite, well-sized action space to learn from. If the space is too large (8 kinds x 3930 steps = ~31,000 options), the bandit can't explore enough arms to learn which are productive. If it's too small (just 8 kinds), it can't learn which *regions* of the program are productive. Step bucketing is the sweet spot: it gives location-aware guidance without overwhelming the bandit.

The bucket count is derived from the campaign budget N, so it automatically adjusts: larger budgets get more buckets (finer granularity), smaller budgets get fewer (coarser but learnable).

### How Phase II.1 differs from other phases

| Phase | What it does | Nature |
|-------|-------------|--------|
| **II.0** | Baseline touch snapshot | Measurement |
| **II.1** (this) | Build arm universe (action space for bandit) | **Data structure construction** |
| **II.1.5** | Pilot calibration of reward parameters | Calibration |
| **II.2** | CoverageState + reward function | Algorithm implementation |
| **II.3** | Bandit scheduler | Algorithm implementation |
| **II.4** | Campaign loop integration | Wiring |

Phase II.1 is the "shape the problem" step: it defines what the bandit can choose from, before the bandit itself is built.

---

## 10. New and Withheld Sections

**Sections retained**: All from previous plans (prerequisites, facts, steps, files, alignment, key variables, checklist, dependencies, for-anyone-new).

**Sections withheld**: None.

**New sections**: None beyond the standard set.

---

*End of Phase II.1 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*

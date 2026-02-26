# Phase II.1 Implementation Report: Arm Universe Construction

This report describes the implementation and testing of Phase II.1 (Arm Universe Construction), deviations from the plan, key variables and functions, testing performed, concrete arm universe measurements, and insights for Phase II.1.5.

**Reference plan**: [PHASE_II_1_IMPLEMENTATION_PLAN.md](./PHASE_II_1_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.1 was implemented as specified. A new `arm_universe.py` module provides the `ArmUniverse` class that computes the bandit's action space from `InspectionData` and campaign budget. 15 unit tests pass (synthetic data, no host required). 1 integration test passes (real inspection data, host required). The master plan's confidence gap about `max(union of S_k)` is now resolved: T=3930 for the default guest, matching `InspectionData.total_steps` exactly.

---

## 2. Deviations from the Phase II.1 Implementation Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Test assertions for T and B | Plan estimated T=100 and B=4 for synthetic data | T=70 and B=3 (steps 70-99 with major=7 are not valid for any kind) | Tests were initially wrong; fixed by correcting assertions. Implementation was correct from the start. |
| No other deviations | - | - | All steps implemented as planned. |

---

## 3. Key Variables and Functions

### 3.1 `pow2_clamp(x, lo, hi) -> int`

- **What**: Rounds x down to the nearest power of 2, then clamps to [lo, hi].
- **How**: Uses `x.bit_length() - 1` to find the highest set bit, which gives the largest power of 2 <= x. Then applies `max(lo, min(result, hi))`.
- **Why round down**: Fewer buckets means more samples per arm at a given budget, which is better for bandit learning. Rounding up would create more arms than the budget can explore.
- **Examples**: `pow2_clamp(41, 16, 128) = 32`; `pow2_clamp(5, 16, 128) = 16`.

### 3.2 `ArmUniverse` class

Constructor takes `(data: InspectionData, budget: int, mutation_kinds: List[str])` and computes everything in `__init__`.

**Attributes (computed)**:

- **`K`** (int): Number of mutation kinds. Currently 8. This is `len(mutation_kinds)`.
- **`T`** (int): Step horizon. `1 + max(union of all valid steps across all kinds)`. For the default guest: T=3930. This means steps 0 through 3929 are in scope.
- **`B_count`** (int): Number of step buckets. Computed as `pow2_clamp(budget // (K * 3), 16, 128)`. For N=1000: B_count=32.
- **`B`** (int): Steps per bucket. `ceil(T / B_count)`. For T=3930, B_count=32: B=123. This means bucket 0 covers steps 0-122, bucket 1 covers 123-245, etc.
- **`arms`** (Dict[Tuple[str, int], List[int]]): Mapping from `(kind_name, bucket_index)` to the sorted list of valid steps in that arm. Only non-empty arms are stored.
- **`available_arms`** (List[Tuple[str, int]]): Sorted list of all `(kind, bucket)` keys that have at least one valid step. This is the list the bandit selects from.
- **`num_arms`** (int): `len(available_arms)`. For N=1000: 254 arms (out of 256 possible = 8 x 32; STORE_OUT_MOD has only 30 arms because some buckets have no store instructions).
- **`n_min`** (int): Forced exploration minimum. `1 if budget >= num_arms else 0`. For N=1000, num_arms=254: n_min=1 (every arm must be tried at least once before UCB exploitation).
- **`steps_per_kind`** (Dict[str, List[int]]): `S_k` for each kind. For diagnostics.
- **`budget`** (int): The campaign budget N that was passed in.

**Methods**:

- **`bucket_for_step(step) -> int`**: Returns `step // B`. Deterministic mapping from any step to its bucket index.
- **`steps_in_arm(kind, bucket) -> List[int]`**: Returns the list of valid steps for that arm, or empty list if the arm doesn't exist.
- **`summary() -> str`**: Human-readable summary including all computed parameters and per-kind arm counts.

### 3.3 How bucket assignment works

Each step `s` maps to bucket `b = s // B` (integer division by the bucket size B).

For the default guest with N=1000: B=123, so:
- Steps 0-122 are bucket 0
- Steps 123-245 are bucket 1
- Steps 246-368 are bucket 2
- ...
- Steps 3813-3929 are bucket 31

Within each bucket, only steps that are actually valid for the given mutation kind are included. So arm `(LOAD_VAL_MOD, 5)` contains only the load-instruction steps (major=5) that fall in bucket 5.

### 3.4 How the arm universe is constructed (step by step)

1. For each of the 8 mutation kinds, call `data.get_valid_steps_for_kind(kind)` to get the sorted list of unique valid steps. This uses the inspection data (cycles with major/minor values) to filter.
2. Union all valid steps to find `T = 1 + max(all valid steps)`.
3. From budget N and K=8, compute `B_count = pow2_clamp(N // 24, 16, 128)` and `B = ceil(T / B_count)`.
4. For each kind and each of its valid steps, compute `bucket = step // B` and add the step to `arms[(kind, bucket)]`.
5. Enumerate all arms with non-empty step lists as `available_arms`.

---

## 4. Testing Performed

### 4.1 Unit tests (no host, synthetic data)

**Command**: `python -m pytest a4/standalone/tests/test_arm_universe.py -v -k "not real_inspection"`
**Result**: 15 passed in 0.20s.

| Test | What it verifies |
|------|-----------------|
| `test_exact_power` | pow2_clamp(64,16,128)=64, etc. |
| `test_round_down` | pow2_clamp(41,16,128)=32, etc. |
| `test_clamp_to_lo` | pow2_clamp(5,16,128)=16 |
| `test_clamp_to_hi` | pow2_clamp(200,16,128)=128 |
| `test_zero_and_negative` | pow2_clamp(0,16,128)=16 |
| `test_small_range` | pow2_clamp with lo=1, hi=4 |
| `test_basic_construction` | T, K, B_count, B, num_arms for synthetic 100-step trace |
| `test_T_from_valid_steps` | T excludes steps with major=7 (not valid for any kind) |
| `test_bucket_assignment` | step // B gives correct bucket index |
| `test_empty_kind_no_arms` | Kind with no valid steps produces zero arms |
| `test_n_min_with_large_budget` | n_min=1 when budget >> num_arms |
| `test_n_min_with_tiny_budget` | n_min=0 when budget < num_arms |
| `test_steps_in_arm` | steps_in_arm returns correct steps; nonexistent arm returns [] |
| `test_budget_scaling` | B_count increases with budget (16 for N=200, 128 for N=5000) |
| `test_summary_runs` | summary() produces readable string |

### 4.2 Integration test (real inspection data)

**Command**: `A4_TEST_HOST=... python -m pytest a4/standalone/tests/test_arm_universe.py::test_arm_universe_real_inspection -v -s`
**Result**: 1 passed in 11.46s.

**How the test works**: The test does NOT run mutations or a campaign. It runs the host binary **once** with `A4_INSPECT=1` (via `InspectionData.from_inspection`), which collects the preflight trace -- all cycles, steps, and their major/minor values. This is the same single-pass inspection that happens at the start of every campaign. From that one inspection output, the test constructs `ArmUniverse` three times (for budgets 500, 1000, 5000) purely in Python memory -- no further host calls. That is why it took only ~11 seconds.

### 4.3 Concrete arm universe measurements

**Default guest program**: `--in1 5 --in4 10`

| Parameter | N=500 | N=1000 | N=5000 |
|-----------|-------|--------|--------|
| T (step horizon) | 3930 | 3930 | 3930 |
| B_count (buckets) | 16 | 32 | 128 |
| B (steps/bucket) | 246 | 123 | 31 |
| Total arms | 128 | 254 | 967 |
| Max possible arms | 128 | 256 | 1024 |
| n_min | 1 | 1 | 1 |
| Avg steps/arm | 182.9 | 92.2 | 24.2 |
| Avg samples/arm | 3.9 | 3.9 | 5.2 |

**Per-kind step counts (same for all budgets)**:

| Kind | Valid steps (S_k) |
|------|------------------|
| COMP_OUT_MOD | 2615 |
| LOAD_VAL_MOD | 680 |
| STORE_OUT_MOD | 596 |
| PRE_EXEC_REG_MOD | 3891 |
| INSTR_TYPE_MOD | 3891 |
| MEM_VAL_MOD | 3930 |
| INSTR_WORD_MOD_FULL | 3906 |
| INSTR_WORD_MOD_SUR | 3906 |

**Observations**:

1. **T=3930 matches `total_steps`**: The master plan's confidence gap is resolved. `max(union S_k) = 3929`, so `T = 3930`. This equals `InspectionData.total_steps` because MEM_VAL_MOD accepts steps with memory transactions, and step 3929 has memory transactions.

2. **Most kinds cover nearly all steps**: PRE_EXEC_REG_MOD, INSTR_TYPE_MOD, MEM_VAL_MOD, INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR all have ~3900 valid steps. Only LOAD_VAL_MOD (680, load-only) and STORE_OUT_MOD (596, store-only) are restricted.

3. **Arm coverage is nearly complete for N=500 and N=1000**: With 16 buckets (N=500), all 128 possible arms are filled. With 32 buckets (N=1000), 254 of 256 are filled (STORE_OUT_MOD has 2 empty buckets where no store instructions fall).

4. **N=5000 creates sparser arms**: With 128 buckets, 967 of 1024 are filled. Some buckets have no steps for certain kinds (especially LOAD/STORE in regions with no load/store instructions). The avg samples/arm is 5.2, which gives the bandit enough data to learn.

5. **Avg samples/arm ~ 4-5 for all budgets**: The B_count derivation formula (`N // (K * 3)`) successfully targets ~3-5 samples per arm regardless of budget. This is the "sweet spot" the master plan aimed for.

---

## 5. Insights for Phase II.1.5 (Pilot Calibration)

### 5.1 Arm universe is ready for pilot sampling

Phase II.1.5 needs to run `N_pilot` random mutations. The arm universe provides the scaffolding: the pilot can randomly sample from `available_arms` to get a `(kind, bucket)` pair, then pick a random step from `steps_in_arm(kind, bucket)`. However, for the pilot phase, the existing `ZonedStepSelector` with `kind="all"` (uniform random kind + zoned step selection) is also acceptable and simpler.

### 5.2 Most kinds share the same step space

PRE_EXEC_REG_MOD and INSTR_TYPE_MOD have identical S_k (both accept major 0-6). MEM_VAL_MOD accepts even more (all steps with memory txns = 3930). This means many `(kind_A, bucket)` and `(kind_B, bucket)` arms cover the same physical steps but apply different mutation logic. The bandit will learn which mutation KIND is most productive at each bucket, which is the core value of the two-level scheduler.

### 5.3 Store/Load sparsity at fine granularity

At B_count=128 (N=5000), STORE_OUT_MOD fills only 94 of 128 buckets, and LOAD_VAL_MOD fills 111 of 128. This means ~20-25% of potential arms for these kinds are empty. The bandit must handle "arm not available" — it should skip unavailable arms. The `available_arms` list already excludes them.

### 5.4 No C++ or Rust changes needed

The arm universe is a pure Python data structure computed from inspection data. No host rebuild is needed for future changes to bucketing or arm construction.

---

## 6. Files Touched

| File | Change |
|------|--------|
| a4/standalone/arm_universe.py | **New**: pow2_clamp, ArmUniverse class. |
| a4/standalone/tests/test_arm_universe.py | **New**: 15 unit tests + 1 integration test. |
| a4/docs/touch/Phase II/PHASE_II_1_IMPLEMENTATION_REPORT.md | This report. |

No changes to: executor.py, fuzzer.py, touch_coverage.py, ffi.cpp, witgen.h, mod.rs, coverage_db.py, step_selector.py.

---

## 7. Completion Checklist

- [x] Step II.1.1: arm_universe.py with pow2_clamp and ArmUniverse.
- [x] Step II.1.2: Concrete T, B_count, B, num_arms computed for N=500/1000/5000.
- [x] Step II.1.3: 15 unit tests passing.
- [x] Step II.1.4: 1 integration test passing with real inspection data.
- [x] No changes to C++, Rust, executor, fuzzer, or DB.
- [x] Master plan confidence gap resolved: T=3930 = total_steps.

---

## 8. Variable Reference

This section lists every variable involved in Phase II.1, especially single-letter variables, with full definitions and concrete values for the default guest.

### Single-letter and short variables

| Variable | Full name | Type | Definition | Default guest value |
|----------|-----------|------|------------|-------------------|
| **K** | Mutation kind count | int | Number of distinct mutation kinds | 8 |
| **T** | Step horizon | int | `1 + max(union of S_k for all k)` -- the total range of step indices that the arm universe partitions into buckets | 3930 |
| **B** | Steps per bucket | int | `ceil(T / B_count)` -- how many consecutive steps each bucket covers | 123 (N=1000) |
| **B_count** | Bucket count | int | Number of step buckets; `pow2_clamp(N // (K * n_target), B_min, B_max)` | 32 (N=1000) |
| **B_min** | Minimum bucket count | int | Lower clamp for B_count | 16 |
| **B_max** | Maximum bucket count | int | Upper clamp for B_count | 128 |
| **N** | Campaign budget | int | Total number of mutations planned for the campaign | User-specified (e.g. 1000) |
| **n_target** | Target samples per arm | int | Desired average number of times each arm is pulled; used to derive B_count | 3 |
| **n_min** | Forced exploration minimum | int | Minimum number of times each arm must be pulled before UCB exploitation; `1 if N >= num_arms else 0` | 1 (N=1000) |
| **S_k** | Valid steps for kind k | List[int] | Sorted list of unique step numbers where mutation kind k can be applied | varies by kind (e.g. COMP_OUT_MOD: 2615 steps) |
| **b** or **bucket** | Bucket index | int | `step // B` -- which bucket a given step falls into | 0 to B_count-1 |
| **s** | Step | int | An instruction step index (a.k.a. `userCycle` in the preflight trace) | 0 to T-1 |
| **k** | Mutation kind | str | One of the 8 mutation kind names (e.g. "COMP_OUT_MOD") | - |
| **a** | Arm | Tuple[str, int] | A (kind, bucket) pair representing one bandit arm | e.g. ("COMP_OUT_MOD", 5) |

### Compound variables

| Variable | Type | Definition |
|----------|------|------------|
| **S_{k,b}** | List[int] | Steps in S_k that fall in bucket b: `{s in S_k : s // B == b}`. Stored in `arms[(k, b)]`. |
| **arms** | Dict[Tuple[str,int], List[int]] | Full mapping from arm `(kind, bucket)` to sorted step list. Only non-empty arms stored. |
| **available_arms** | List[Tuple[str,int]] | Sorted list of all arm keys with at least one valid step. This is what the bandit selects from. |
| **num_arms** | int | `len(available_arms)`. For N=1000: 254. |
| **steps_per_kind** | Dict[str, List[int]] | S_k for each kind name. For diagnostics. |

### Constants

| Constant | Value | Defined in | Purpose |
|----------|-------|-----------|---------|
| _N_TARGET | 3 | arm_universe.py | Desired average samples per arm |
| _B_MIN | 16 | arm_universe.py | Minimum step buckets |
| _B_MAX | 128 | arm_universe.py | Maximum step buckets |

---

*End of Phase II.1 Implementation Report.*

# Phase II.0 Implementation Report: Baseline Touch Snapshot

This report describes the implementation and testing of Phase II.0 (Baseline Touch Snapshot), deviations from the plan, key variables and functions, testing performed, and insights for Phase II.1.

**Reference plan**: [PHASE_II_0_IMPLEMENTATION_PLAN.md](./PHASE_II_0_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.0 was implemented with one significant unexpected discovery: the baseline (unmutated) run requires `StepMode::SeqForward` to emit the touch bitmap, but without `A4_MUTATION_CONFIG` set, the Rust code defaults to `StepMode::Parallel`. This was fixed by extending the Rust mode selection in `hal/mod.rs` to also check for `A4_COVERAGE_TOUCH`. After rebuilding the host, both tests pass.

**Baseline snapshot**: 1599 distinct buckets, 192676 total touches -- identical to the Phase 3.2 mutated-run measurement.

---

## 2. Deviations from the Phase II.0 Implementation Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Rust mod.rs change | Not anticipated in the plan | Added A4_COVERAGE_TOUCH check to StepMode selection in hal/mod.rs lines 149-151 | Critical fix: touch emission lives inside the `case kStepModeSeqForward` block in ffi.cpp. Without A4_MUTATION_CONFIG, Rust selects Parallel mode, so SeqForward (and touch emission) is never reached. Adding A4_COVERAGE_TOUCH forces SeqForward when touch coverage is requested without a mutation config. |
| Host rebuild | Plan mentioned "Build the host if not already built" | Full rebuild required (~12 min) | Rust mod.rs change triggers recompilation of risc0-circuit-rv32im and downstream. |
| Dict import | Plan noted "Add Dict to typing imports if not already present" | Dict added to executor.py; baseline_touch.py uses List only | Minor; no impact. |

### Why the Rust change was not anticipated

The plan flagged this as a confidence gap in section 2.3: "I have not directly run run_baseline with A4_COVERAGE_TOUCH=1 to verify the bitmap is emitted." The Phase I plans documented that SeqForward is forced by A4_MUTATION_CONFIG, but the implication for baseline runs (no A4_MUTATION_CONFIG) was not drawn out until testing revealed the failure. The confidence gap system worked as intended.

---

## 3. Key Variables and Functions

### 3.1 run_baseline(host_binary, host_args, extra_env=None) (executor.py)

- **What changed**: Added `extra_env: Optional[Dict[str, str]] = None`. When provided, merged into env via `env.update(extra_env)`.
- **Why**: Needed to inject A4_COVERAGE_TOUCH=1 without hardcoding it. Generic parameter reusable for future needs.
- **Backwards compatible**: Existing callers pass no extra_env.

### 3.2 BaselineTouch (dataclass, baseline_touch.py)

- **bitmap: bytes** -- Raw 65536-byte touch bitmap from the unmutated run.
- **distinct_buckets: int** -- Count of non-zero entries (1599 for default guest).
- **total_touches: int** -- Sum of all entries (192676).
- **touched_indices: List[int]** -- Sorted list of non-zero indices. The explicit baseline touch set.

### 3.3 capture_baseline_touch(host_binary, host_args) -> BaselineTouch

Runs host with A4_COVERAGE_TOUCH=1 (no mutation), parses bitmap, computes stats. Raises RuntimeError if bitmap not found.

### 3.4 save_baseline / load_baseline

- save: Writes stats + indices to JSON. No full bitmap (indices suffice for reconstruction).
- load: Reconstructs BaselineTouch with binary 0/1 bitmap from indices.

### 3.5 Rust StepMode selection (hal/mod.rs)

Lines 149-151 now check `A4_MUTATION_CONFIG.is_some() || A4_COVERAGE_TOUCH.is_some()` to force SeqForward. Ensures touch emission works even without a mutation config.

---

## 4. Testing Performed

### 4.1 First attempt (failed)

Both tests failed: RuntimeError "Baseline run did not produce a valid a4_touch_coverage tag."
Root cause: Parallel mode in Rust; SeqForward block never reached.
Fix: Added A4_COVERAGE_TOUCH to Rust mode check.

### 4.2 Host rebuild

cargo build --release from workspace/output. Succeeded in ~12 minutes.

### 4.3 Second attempt (passed)

2 passed in 62.34s:

| Test | Result | Details |
|------|--------|---------|
| test_baseline_produces_touch_bitmap | PASSED | distinct=1599, total=192676 |
| test_baseline_save_load_roundtrip | PASSED | JSON save/load preserves indices and stats |

### 4.4 Baseline vs mutated comparison

| Metric | Baseline (unmutated) | Phase 3.2 mutated run | Same? |
|--------|---------------------|----------------------|-------|
| Distinct buckets | 1599 | 1599 | Yes |
| Total touches | 192676 | 192676 | Yes |

The baseline and mutated runs produce identical touch bitmaps because value mutations do not change which major/minor branches execute at each cycle.

---

## 5. Insights for Phase II.1

### 5.1 Baseline-vs-mutated identity

Baseline and mutated touch bitmaps are identical. The campaign global bitmap reaches 1599 distinct buckets on the first run and stays there for value mutations. Only INSTR_TYPE_MOD can discover new touch buckets. The baseline is diagnostic, not functional.

### 5.2 Rust mode coupling

Any future env var needing C++ SeqForward path must be added to the Rust StepMode check in hal/mod.rs. This is a cross-language coupling point.

### 5.3 T computation

Phase II.1 needs T = 1 + max(union of S_k for all k). Should be computed from actual get_valid_steps_for_kind(k) union, not assumed from the 3930 total steps.

### 5.4 Host binary status

Host is up to date with all Phase I C++ changes plus Phase II.0 Rust change. No rebuild needed until further C++/Rust changes.

### 5.5 Performance

Baseline capture takes ~30s (one SeqForward host run). save/load avoids re-running.

---

## 6. Files Touched

| File | Change |
|------|--------|
| a4/core/executor.py | Dict import; run_baseline extended with extra_env. |
| a4/standalone/baseline_touch.py | New: BaselineTouch, capture_baseline_touch, save/load. |
| a4/standalone/tests/test_baseline_touch.py | New: 2 tests. |
| workspace/.../hal/mod.rs | A4_COVERAGE_TOUCH check in StepMode selection. |

---

## 7. Completion Checklist

- [x] Step II.0.1: run_baseline extended with extra_env.
- [x] Step II.0.2: baseline_touch.py created.
- [x] Step II.0.3: test_baseline_touch.py created.
- [x] Step II.0.4: Tests pass; baseline=1599 distinct, 192676 total.
- [x] Unplanned: Rust mod.rs fix; host rebuilt.

*End of Phase II.0 Implementation Report.*

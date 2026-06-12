# Catalog of Potential Global Constraint Hooks

This document lists every known approach for detecting global constraint (permutation/lookup argument) violations in RISC Zero, along with their properties, trade-offs, and current status.

## The Core Problem

A4 fuzzes zkVM executions by mutating the post-execution trace and replaying the prover. When a mutation breaks something, we want to know WHAT broke. For **local** constraints (instruction decode, ALU, memory format), our EQZ hooks give per-cycle, per-constraint-source information. For **global** constraints (permutation argument totals, lookup argument balances), we currently have no hook that provides equivalent detail.

The fundamental challenge: global constraint satisfaction is an emergent property of the ENTIRE trace, not a per-row check. No single row "contains" the global constraint -- it arises from the sum of all rows' contributions equaling zero.

## Important Context: Dual-Mode Requirement

A4's purpose is finding soundness bugs in zkVMs. This requires checking **whether the verifier accepts the proof** (exit code 0 = accepted = potential soundness bug). Some hooks below interfere with proof generation (making verification always fail), which means we would need to run each mutation TWICE:
1. **Diagnostic run** (with the hook active): Get detailed constraint violation data
2. **Verification run** (without the hook): Check if the verifier accepts or rejects

This "dual-mode" overhead is an important practical consideration.

---

## Hook 1: Post-Prefix-Sum Total Check

**Location:** `ffi.cpp`, inside `risc0_circuit_rv32im_cpu_accum`, between the prefix-sum and apply-totals phases.

**What it does:** After the prefix-sum converts per-row accumulator deltas into a running total, the last row of the last 4 accum columns holds the grand total of all contributions. If the permutation/lookup arguments hold, this total must be zero (in FpExt = 4 Fp elements). We check whether it's zero and emit a diagnostic tag.

**What it detects:** Whether ANY permutation or lookup argument (memory, U16, U8, cycle, BigInt) has a non-zero total. Binary signal: violated or not.

**Properties:**

| Property | Value |
|---|---|
| Granularity | Binary (failed / ok) |
| Per-cycle? | No -- single aggregate check |
| Per-argument-family? | No -- all families mixed into one total |
| Interferes with proof? | No -- read-only check, doesn't modify any buffers |
| Requires dual-mode? | **No** -- can run alongside normal proof generation |
| Requires circuit_debug? | No |
| Requires Rust changes? | No -- C++ only |
| Implementation effort | ~10 lines of C++ |
| Performance overhead | Negligible (read 4 values, compare to zero) |
| False negatives? | Theoretically possible (Schwartz-Zippel), practically negligible |

**Status: NOT YET IMPLEMENTED.** This is planned as Phase 2 in the master plan.

**Strengths:**
- Simplest possible implementation
- Zero interference with proof generation -- the verifier still gets a valid (or invalid) proof
- Can distinguish "local-only failure" from "local + global failure"

**Weaknesses:**
- Binary signal only -- no per-cycle or per-family information
- Doesn't tell you WHERE or WHICH argument failed
- All argument types mixed: memory, U16, U8, cycle, BigInt all contribute to one total

---

## Hook 2: Check Polynomial Scan (with circuit_debug)

**Location:** `prover.rs`, after `eval_check` computes the check polynomial.

**What it does:** Scans the check polynomial buffer for non-zero values at cycle-row positions. A non-zero entry at cycle index C means SOME constraint (local or global or both) evaluated to non-zero at that cycle.

**What it detects:** Per-cycle constraint violations on the FINALIZED columns (post prefix-sum + apply-totals). This includes both local AND global constraints. Global constraint failures appear at cycle 0 (the accumulator wrap-around point).

**Properties:**

| Property | Value |
|---|---|
| Granularity | Per-cycle (which cycles have failures) |
| Per-cycle? | Yes |
| Per-argument-family? | No -- all constraints mixed via poly_mix |
| Interferes with proof? | **YES** -- requires circuit_debug which disables ZK shift |
| Requires dual-mode? | **YES** -- proof is always invalid with circuit_debug |
| Requires circuit_debug? | **YES** -- without it, all check_poly entries are non-zero (coset evaluation) |
| Requires Rust changes? | Yes -- prover.rs + Cargo.toml feature flag |
| Implementation effort | ~20 lines of Rust (already implemented) |
| Performance overhead | Low (linear scan of check_poly buffer) |
| False negatives? | None -- if a constraint is violated, the check polynomial is non-zero at that cycle |

**Status: IMPLEMENTED AND TESTED.** Two mutations confirmed:
- COMP_OUT_MOD: nonzero_cycles=[0, 16777], local failures at cycle 16777 only
- LOAD_VAL_MOD: nonzero_cycles=[0, 9989, 10129], local failures at cycles 9989/10129 only
- Cycle 0 in both cases = accumulator wrap-around (global constraint failure)

**Strengths:**
- Per-cycle detection: shows exactly which cycles have constraint violations
- Catches BOTH local and global failures in one scan
- Global failures appear at cycle 0, distinguishable from local failures at other cycles
- Already implemented and working

**Weaknesses:**
- **Requires circuit_debug mode** which disables ZK shift and makes proof invalid
- **Requires dual-mode operation** for soundness bug detection: one run with circuit_debug for diagnostics, one without for verification
- Cannot distinguish which SPECIFIC constraint failed at a cycle (all mixed)
- Global failures always at cycle 0 regardless of which row caused the imbalance
- Cycle 0 is an aggregate of ALL argument families -- no per-family breakdown

---

## Hook 3: Shadow Accumulator Replay (Per-Family Residues)

**Location:** New code in `ffi.cpp`, running after `step_TopAccum` phase 1 completes.

**What it does:** Instead of relying on the existing accumulator (which mixes all argument families into one running sum), we build our OWN diagnostic replay. For each argument family separately (memory, U16, U8, cycle), we re-walk the data columns, compute that family's contribution using the same verifier randomness from the mix buffer, and sum them. Then we check each family's total independently.

**What it detects:** Which specific argument family has a non-zero total. For example: "memory permutation violated, U16 lookups OK, U8 lookups OK, cycle lookups OK."

**Properties:**

| Property | Value |
|---|---|
| Granularity | Per-argument-family |
| Per-cycle? | No -- computes family-level totals |
| Per-argument-family? | **Yes** -- the entire point |
| Interferes with proof? | No -- separate diagnostic computation |
| Requires dual-mode? | **No** -- runs alongside normal proof generation |
| Requires circuit_debug? | No |
| Requires Rust changes? | No -- C++ only |
| Implementation effort | Moderate (~100-200 lines of C++). Hard part: mapping data columns to argument families |
| Performance overhead | Moderate (re-walks all rows computing FpExt arithmetic per family) |
| False negatives? | Same as Hook 1 (Schwartz-Zippel, negligible) |

**Status: NOT YET IMPLEMENTED.** Planned as Phase 3 in the master plan.

**Strengths:**
- Per-family granularity without any interference with proof generation
- No dual-mode needed -- works in a single run
- Tells you "the memory permutation broke" vs "a U16 lookup broke"
- Can coexist with Hooks 1 and 2

**Weaknesses:**
- Still no per-cycle information (which row caused the family imbalance)
- Requires hardcoding the data-column-to-argument-family mapping
- Moderate implementation complexity
- Performance overhead from re-walking all rows

---

## Hook 4: Re-run step_TopAccum Without zeroBack on Finalized Columns

**Location:** New code in `ffi.cpp`, running after prefix-sum + apply-totals complete.

**What it does:** After the accum buffer is finalized (prefix-sum + apply-totals done), we re-run the `step_TopAccum` function but with `zeroBack` disabled. This means the accum transition constraints read REAL previous-row values instead of zeros. The EQZ checks would then detect if `accum[i] - accum[i-1] != delta[i]` on the finalized running sums.

**What it detects:** Per-cycle accumulator transition constraint violations on finalized columns. Only cycle 0 (or wherever the wrap-around is) would fail, since apply-totals makes all other transitions correct by construction.

**Properties:**

| Property | Value |
|---|---|
| Granularity | Per-cycle |
| Per-cycle? | Yes (but practically only cycle 0 ever fails) |
| Per-argument-family? | No -- same mixed EQZ as existing |
| Interferes with proof? | **Possibly** -- re-running step_TopAccum WRITES to the accum buffer, corrupting it |
| Requires dual-mode? | **Yes** (if it corrupts the accum buffer) or No (if we copy the buffer first) |
| Requires circuit_debug? | No |
| Requires Rust changes? | No -- C++ only |
| Implementation effort | Moderate. Need to either copy accum buffer or make a read-only evaluation mode |
| Performance overhead | High (re-runs entire accum phase) |
| False negatives? | None for the wrap-around check |

**Status: NOT TRIED.** Conceptual approach, not implemented.

**Strengths:**
- Uses existing EQZ infrastructure and hooks
- Global failures detected via the same `<constraint_fail>` format as local failures

**Weaknesses:**
- Re-running step_TopAccum writes to the accum buffer, potentially corrupting it for the subsequent eval_check
- Would need to copy the accum buffer first (memory overhead) or find a read-only mode
- Practically only detects at cycle 0 (apply-totals makes other transitions correct)
- No per-family information

---

## Hook 5: Evaluate poly_fp on Non-Coset Domain (Custom Rust Evaluation)

**Location:** New Rust code in `cpu.rs` or a new evaluation function.

**What it does:** Instead of evaluating `poly_fp` on the coset domain (as `eval_check` normally does), evaluate it on the ORIGINAL domain (without the ZK shift). This would show constraint violations directly at cycle rows without needing circuit_debug.

**What it detects:** Same as Hook 2 but without disabling ZK shift.

**Properties:**

| Property | Value |
|---|---|
| Granularity | Per-cycle |
| Per-cycle? | Yes |
| Per-argument-family? | No |
| Interferes with proof? | **No** -- separate evaluation, doesn't affect the committed polynomials |
| Requires dual-mode? | **No** |
| Requires circuit_debug? | **No** |
| Requires Rust changes? | Yes -- significant Rust changes to do a second NTT or evaluate on a different domain |
| Implementation effort | High. Need to either: (a) do inverse-NTT + re-NTT without shift, or (b) create unshifted column evaluations |
| Performance overhead | High (additional NTT computations for all column groups) |
| False negatives? | None |

**Status: NOT TRIED.** Conceptual approach, not investigated.

**Strengths:**
- Per-cycle detection without proof interference
- No dual-mode needed
- No circuit_debug dependency

**Weaknesses:**
- Significant implementation complexity (NTT operations, buffer management)
- High performance overhead (essentially doubles the evaluation work)
- Still no per-family information
- Still only cycle 0 for global failures (same as Hook 2)

---

## Hook 6: Enable circuit_debug at Runtime via Environment Variable

**Location:** Modification to `prover.rs` to check an env var instead of a compile-time feature flag.

**What it does:** Makes the ZK shift and check polynomial scan conditional on an environment variable (e.g., `A4_CHECK_POLY=1`) instead of requiring a different build. This would let us toggle circuit_debug behavior per-run without rebuilding.

**Properties:**

| Property | Value |
|---|---|
| Granularity | Same as Hook 2 (per-cycle) |
| Per-cycle? | Yes |
| Per-argument-family? | No |
| Interferes with proof? | **Only when the env var is set** |
| Requires dual-mode? | **Yes, but toggleable per-run** -- one run with env var for diagnostics, one without for verification |
| Requires circuit_debug? | No (replaces it with runtime check) |
| Requires Rust changes? | Yes -- modify prover.rs to use env var instead of cfg flag |
| Implementation effort | Moderate (~30 lines of Rust, replacing 3 cfg blocks with env var checks) |
| Performance overhead | Same as Hook 2 when active |
| False negatives? | None |

**Status: NOT TRIED.** This is a practical improvement over Hook 2 that eliminates the need for separate builds.

**Strengths:**
- Same capability as Hook 2 but without separate builds
- Dual-mode runs using the same binary: `A4_CHECK_POLY=1` for diagnostics, omit for verification
- Clean integration with A4's existing env var pattern

**Weaknesses:**
- Same fundamental limitations as Hook 2 (cycle 0 only for global, no per-family)
- Still requires two runs for soundness checking

---

## Comparison Summary

| Hook | Granularity | Interferes with Proof? | Dual-Mode Needed? | Per-Family? | Implementation Status |
|---|---|---|---|---|---|
| **1: Post-prefix-sum total** | Binary | No | No | No | NOT IMPLEMENTED |
| **2: Check poly scan (circuit_debug)** | Per-cycle | Yes | Yes | No | IMPLEMENTED, TESTED |
| **3: Shadow accumulator replay** | Per-family | No | No | Yes | NOT IMPLEMENTED |
| **4: Re-run step_TopAccum** | Per-cycle (only cycle 0) | Possibly | Possibly | No | NOT TRIED |
| **5: Non-coset poly_fp eval** | Per-cycle | No | No | No | NOT TRIED |
| **6: Runtime circuit_debug toggle** | Per-cycle | When active | Yes (toggleable) | No | NOT TRIED |

## Recommended Approach

The optimal strategy uses **multiple hooks together**:

1. **Hook 1 (binary residue)** on EVERY run -- zero overhead, zero interference, gives binary global signal
2. **Hook 3 (shadow replay)** on EVERY run -- moderate overhead, zero interference, gives per-family breakdown
3. **Hook 6 (runtime circuit_debug toggle)** on SELECTED runs -- when we need per-cycle global detection, enable it for one diagnostic run, then run again without it for verification

This avoids separate builds, gives us layered global signals (binary -> per-family -> per-cycle), and preserves the ability to check verification status for soundness bug detection.

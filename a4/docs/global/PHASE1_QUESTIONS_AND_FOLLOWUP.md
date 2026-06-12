# Phase 1 Questions and Follow-up Investigations

## Question 1: Is H2 Really Refuted?

### The concern

We observed:
- COMP_OUT_MOD: 2 local failures at cycle 16777, check polynomial non-zero at cycles [0, 16777]
- LOAD_VAL_MOD: 10 local failures at cycles 9989/10129, check polynomial non-zero at cycles [0, 9989, 10129]

Pattern: `nonzero_check_cycles = distinct_local_failure_cycles + 1` (the +1 being cycle 0)

The question is: **Is the non-zero at cycle 0 definitely from a global (accum) constraint, or could it be from a local constraint too?** We haven't run a case where there are 0 local failures to isolate the global signal.

### What we know for certain (fact-based)

1. **Cycle 0 is NOT where the mutation occurs.** COMP_OUT_MOD mutates cycle 16777, LOAD_VAL_MOD affects cycles 9989/10129. Cycle 0 is the very first execution cycle.

2. **The check polynomial mixes ALL constraints.** A non-zero at cycle 0 means some constraint expression evaluates to non-zero at cycle 0 when mixed with `poly_mix` powers. This could be from local constraints, accum constraints, or both.

3. **Local constraints at cycle 0 depend only on cycle 0's data columns.** If the mutation at cycle 16777 doesn't corrupt cycle 0's data columns, local constraints at cycle 0 should pass. But we haven't verified this -- some mutations might have cascading effects on early cycles.

4. **The accum transition constraint at cycle 0 references the previous row (row N-1) via back=1.** In the non-shifted evaluation (circuit_debug mode), this reads the actual finalized accum value at row N-1. If the permutation total is non-zero, the wrap-around at cycle 0 fails.

### What we DON'T know

- We haven't verified that cycle 0's data columns are unaffected by the mutation
- We haven't run a case with 0 local failures
- We haven't verified that the non-zero at cycle 0 is specifically from accum constraints vs local

### Is this "per-cycle global constraint detection"?

**No, not really.** If the global failure always shows at cycle 0 (the wrap-around point), this is a FIXED location, not a "per-cycle" detection of where the global violation occurred. It tells us "the permutation argument failed" but not "which specific cycle contributed the mismatched transaction." It's essentially a binary signal that happens to manifest at a specific cycle.

However, it IS more informative than a simple binary residue check because:
- We can see it alongside local failures (same output format)
- It confirms that the global failure is real (not just from local constraint spillover)
- The cycle 0 location is consistent and can be recognized programmatically

### What about aggregate: does cycle 0 aggregate ALL argument types?

**Yes.** The accumulator running sum at row N-1 is the total of ALL argument contributions (memory, U16, U8, cycle, BigInt). The transition constraint at cycle 0 checks `accum[0] - accum[N-1] = delta[0]`. If the total is non-zero (ANY argument type has an imbalance), this single constraint at cycle 0 fails. So it's a single-cycle aggregate check of all global properties.

---

## Question 2: Option A vs Option B

### What was implemented

**Option A (DONE):** We added an A4-conditional Rust code block in `prover.rs:159-183` that scans the check polynomial buffer when `A4_MUTATION_CONFIG` is set. It emits `<a4_check_poly_scan>` with the count and list of non-zero cycle indices. This gives us controlled output in our tag format.

**Option B (DONE):** We temporarily enabled the `circuit_debug` feature flag by adding `risc0-zkvm/circuit_debug` to the host's Cargo.toml features. We tested with it, then disabled it and left a comment.

### The critical dependency

**Option A DEPENDS on Option B.** Here's why:

Without `circuit_debug`:
- `zk_shift` IS applied (line 45)
- All column polynomials are evaluated on the coset `{3*omega^i}` instead of `{omega^i}`
- The check polynomial `ret = tot / (y-1)` uses coset-shifted values
- ALL check polynomial entries are non-zero regardless of constraint satisfaction
- Our Option A scan reports 32768/32768 cycles non-zero (useless)

With `circuit_debug`:
- `zk_shift` is SKIPPED
- Column polynomials are evaluated on the original domain `{omega^i}`
- At cycle rows, the constraint polynomial is genuinely zero if constraints pass
- The check polynomial entries are zero at cycle rows where constraints are satisfied
- Our Option A scan correctly identifies the 2-3 non-zero cycles

**So Option A is the output mechanism, and Option B (`circuit_debug`) is the prerequisite that makes the data meaningful.** They work together.

### Current state

Option A code is in prover.rs (always present, runs when `A4_MUTATION_CONFIG` is set). Option B (circuit_debug feature) is currently DISABLED in host Cargo.toml. To get meaningful check polynomial data, both must be active.

---

## Question 3: What Exactly Does circuit_debug Do?

### The three things circuit_debug changes

From `prover.rs`, `circuit_debug` affects exactly three behaviors:

**1. Disables ZK shift (line 45):**
```rust
#[cfg(not(feature = "circuit_debug"))]
hal.zk_shift(&coeffs, count);
```
Normally, `zk_shift` transforms polynomial coefficients `c_i` to `c_i * 3^i`, which shifts the evaluation domain from `{omega^i}` to `{3*omega^i}` (a coset). This provides zero-knowledge by hiding the constraint values. With `circuit_debug`, this shift is skipped, so evaluations happen on the original domain where constraint satisfaction is directly visible.

**2. Scans check polynomial for non-zero entries (lines 143-157):**
```rust
#[cfg(feature = "circuit_debug")]
check_poly.view(|check_out| {
    for i in (0..domain).step_by(4) {
        if check_out[i] != H::Elem::ZERO {
            tracing::debug!("check[{i}] = ...");
            bad_z.get_or_insert(...);
        }
    }
});
```
This logs non-zero entries via `tracing::debug` and captures the first failing evaluation point as `bad_z`.

**3. Uses bad_z as DEEP query point (lines 210-216):**
```rust
if #[cfg(feature = "circuit_debug")] {
    let z = if let Some(bad_z) = bad_z {
        self.iop.write_field_elem_slice(bad_z.subelems());
        bad_z
    } else {
        self.iop.random_ext_elem()
    };
}
```
If constraint violations were found (bad_z is Some), the DEEP query point is set to that point instead of being random. This forces the verifier to query at the failing point, guaranteeing detection.

### Does disabling ZK shift make the proof invalid?

**We need to test this.** The hypothesis is:
- Without ZK shift, the polynomial evaluations are on the original domain, not the coset
- The verifier expects coset evaluations (it evaluates at `z * back_one^k` where back_one accounts for the coset)
- Mismatch between what the prover commits and what the verifier expects causes `InvalidProof`

But there's a subtlety: if NO constraints are violated and bad_z is None, circuit_debug still uses a random DEEP query point (same as normal). The only difference is the ZK shift on the polynomial commitments. The verifier would see non-coset polynomial evaluations when it expected coset ones, causing a mismatch.

**We observed:** The no-op mutation (0 constraint failures) with circuit_debug exits with code 101 (verify segment panic). This is consistent with the ZK shift hypothesis. But we should verify this is specifically from the ZK shift mismatch, not from some other circuit_debug behavior.

---

## Required Follow-up Investigations

### Investigation F1: Verify that cycle 0 non-zero is from accum, not local

**Goal:** Confirm that the non-zero at cycle 0 in the check polynomial is from the accumulator transition constraint (global), not from a local constraint.

**Approach:**
- Check what local constraints exist at cycle 0 in the trace
- Run a mutation that affects a late cycle (e.g., cycle 16777) and verify cycle 0's data columns are unaffected
- Ideally: run step_Top for cycle 0 only and verify all local EQZ pass (they should, since our existing hooks show 0 local failures at cycle 0)

**Fact we already have:** Our `<constraint_fail>` output for COMP_OUT_MOD shows failures ONLY at cycle 16777. No local constraint failure at cycle 0. This is strong evidence that cycle 0's non-zero check polynomial value is from accum, not local.

### Investigation F2: Run 100-mutation campaign with circuit_debug to find global-only cases

**Goal:** Find mutations where `local_failures == 0` but `nonzero_check_cycles > 0`. This would definitively prove that the check polynomial catches global-only violations.

**Approach:**
- Enable circuit_debug
- Run the existing diagnostic campaign with 100 mutations
- For each run, collect: local failure count, accum failure count, check_poly nonzero_cycles, first_nonzero_cycles
- Look for the "premium bucket": local_failures == 0 AND nonzero_check_cycles > 0

**Note:** With circuit_debug, the verifier always rejects (due to ZK shift being disabled). So exit code will always be 101. We can't use "verify fails" as a signal. But we can use `nonzero_check_cycles > 0` as the global signal.

### Investigation F3: Verify that circuit_debug proof invalidity is solely from ZK shift

**Goal:** Confirm that the proof failure in circuit_debug mode comes from the ZK shift mismatch, not from some other behavioral change.

**Approach:**
- Check if there's a way to re-enable ZK shift while keeping the check polynomial scan
- Or: in circuit_debug mode, run a clean (unmutated) trace and check if the verifier explicitly complains about polynomial mismatch (InvalidProof) vs some other error
- This is low priority -- we already know circuit_debug mode works for our diagnostic purposes regardless of proof validity

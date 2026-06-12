# Deep Dive: Global Constraint Hooks -- Presentation Support

*Comprehensive answers to all questions about the global constraint hooks, the permutation argument, lookups, and how violations are caught.*

---

## Question 1: Is there one permutation argument or multiple?

### Easy explanation

There is **ONE single accumulator** that combines everything. Think of it like one giant ledger that tracks ALL types of transactions: memory reads/writes, U16 range checks, U8 range checks, and cycle ordering -- all in the same running total. If ANY of these is wrong, the total is non-zero.

### Technical detail

The zirgen compiler's `GenerateAccum.cpp` walks the layout and accumulates ALL argument types (MemoryArg, ArgU16, ArgU8, CycleArg) into a single variable `t` (line 244: `Value tNew = builder.create<AddOp>(..., t, delta)`). There is no separation by family -- they all feed into the same chain.

In the generated code (`exec_TopAccum` in `steps.cpp`), for instruction arm 0, the accumulation chain is:
- Columns 0: first 3 ArgU16 deltas
- Column 1: 1 ArgU16 + 2 MemoryArg deltas (added to column 0's result)
- Column 2: 3 CycleArg deltas (added to column 1's result)
- Column 3: 2 ArgU16 + 1 MemoryArg deltas (added to column 2's result)
- ... and so on until column 19 (the final total for this row)

After prefix-sum, the last 4 columns (which are 4 Fp elements forming one FpExt extension field element) hold the grand total of ALL families combined.

**So Hook 1 ("Grand Product Value") checks this ONE combined total.** It tells you "something is wrong" but cannot tell you which family caused it.

**Hook 3 ("Full Recordkeeping") works around this** by independently computing per-family sums from the raw extern records, letting it identify which specific family (memory, U16, U8, cycle) is broken.

**Confidence: 99%.** Directly verified from `GenerateAccum.cpp` source (single `t` variable), `exec_TopAccum` generated code (single chain of column stores), and prefix-sum code (one grand total in last 4 columns).

---

## Question 2: Are lookups part of the permutation argument?

### Easy explanation

**Yes.** In RISC Zero, lookups and permutations are unified into ONE mechanism called **LogUp** (Logarithmic derivative lookup argument). Both memory consistency (permutation) and range checks (lookups) use the same mathematical formula: `count / hash`. They all feed into the same accumulator. The only difference is what goes into the "hash":

- **Memory**: hash combines addr, cycle, dataLow, dataHigh
- **U16 lookup**: hash uses just the value being checked
- **U8 lookup**: hash uses just the value being checked
- **Cycle ordering**: hash uses the cycle number

### Technical detail

All four argument types are declared as `argument` components in the zirgen DSL:

```zir
argument ArgU16(count: Val, val: Val) {
  LookupDelta(16, val, count);       // lookup
}

argument MemoryArg(count: Val, addr: Val, cycle: Val, data: ValU32) {
  MemoryDelta(addr, cycle, dataLow, dataHigh, count);  // permutation
}
```

`GenerateAccum.cpp` treats ALL `LayoutKind::Argument` entries identically (line 266: `if (layoutType.getKind() == LayoutKind::Argument) { t = accumulateArgument(t, ...); }`). The accumulation formula is the same for all: `t' = t + count * inv(condensed_value + offset)`.

The "condensed value" differs by family (determined by `condenseArgument` which uses per-family randomness from the mix buffer), but the accumulation into `t` is the same operation.

**Confidence: 99%.** Directly verified from `GenerateAccum.cpp` and `lookups.zir` / `mem.zir`.

---

## Question 3: How do lookups work? What do they check?

### Easy explanation

A lookup argument verifies that every value the circuit USES is actually a VALID value. For example:

**U16 range check:** When the circuit needs to split a 32-bit word into two 16-bit halves, it needs to prove each half is actually in [0, 65535]. Rather than doing expensive bit-by-bit decomposition, it uses a lookup table:

1. **Use side (during instruction execution):** The circuit says "I'm using value 45000 as a U16" and adds +1 for that value to the accumulator.

2. **Table side (during system/control cycles):** Special "control table" cycles iterate through ALL valid values 0, 1, 2, ..., 65535 and add -1 for each one (specifically, `-LookupCurrent(16, idx)` which is the negative of however many times that value was used).

3. **Balance check:** If every used value was in the table, all +1s and -1s cancel to zero. If someone claims 70000 is a valid U16, there's no table entry to cancel it, and the accumulator total is non-zero.

**U8 range check:** Same thing but for [0, 255].

**Cycle ordering:** Same mechanism but for cycle numbers -- verifies that cycles are properly ordered.

### What zirgen constraints enforce

There are actually TWO mechanisms at play for lookups:

1. **The lookup argument itself** (LogUp accumulator): Ensures the multiset of "used" values equals the multiset of "provided" values. This is the GLOBAL check that goes into the accumulator.

2. **`AssertRange!` local constraint**: A SEPARATE local constraint that directly checks `0 <= val < range` using `InRange`. This is compiled into a polynomial constraint and checked per-row.

So lookups have BOTH a local check (AssertRange) AND a global check (LogUp accumulator). The local check catches "this value is out of range at this row." The global check catches "the multiset of all used values doesn't match the table."

### Technical detail

The table entries are generated in `ControlTable` (in `inst_control.zir` lines 130-165). During system cycles with `major=7, minor=6` (ControlTable state), the circuit processes batches of 16 values at a time:

```zir
for i : 0..16 {
    idx := entry + i;
    arg := ArgU16(-LookupCurrent(16, idx), idx);  // provides -count for each index
    arg.val = idx;
};
```

`LookupCurrent(16, idx)` returns how many times index `idx` was used across all instruction cycles. The table provides exactly that many copies (with negative count) to cancel them out.

**Confidence: 99%.** Verified from `lookups.zir`, `inst_control.zir`, and `LowerDirectives.cpp` (which shows `AssertRange!` lowering).

---

## Question 4: What ALL goes into the permutation argument?

### Easy explanation

Four families of entries go into the single accumulator:

1. **MemoryArg** (memory permutation): Every memory access creates two entries -- an "old" side (-1, referencing the previous access to this address) and a "new" side (+1, recording the current access). Fields: address, cycle, dataLow, dataHigh. This verifies read-write consistency.

2. **ArgU16** (16-bit range check lookup): Every time the circuit claims a value is a valid 16-bit number, it creates a +1 entry. The control table provides matching -1 entries. Field: val (the 16-bit value).

3. **ArgU8** (8-bit range check lookup): Same as U16 but for 8-bit values. Used less frequently (mainly by multiplication and division instructions).

4. **CycleArg** (cycle ordering): Verifies that execution cycles are properly ordered. Field: cycle number.

There is NOTHING else in the permutation argument. These four families are the complete set.

### How do I know?

The `argument` keyword in zirgen DSL marks a component as participating in the accumulator. Searching ALL `.zir` files for `argument `:

```
lookups.zir:8   - argument ArgU8(count, val)
lookups.zir:32  - argument ArgU16(count, val)
mem.zir:24      - argument MemoryArg(count, addr, cycle, data)
mem.zir:53      - argument CycleArg(count, cycle)
```

These are the ONLY four `argument` declarations in the entire rv32im circuit. `GenerateAccum.cpp` processes only `LayoutKind::Argument` entries, so nothing else contributes to the accumulator.

**Note:** BigInt is separate. It uses the user accum columns (0-22) with its own polynomial state machine, NOT the LogUp accumulator.

**Confidence: 99%.** Verified by exhaustive search of all `.zir` files for `argument ` declarations.

---

## Question 5: Slide 2 -- How is a mutated destination register caught if not by circuit constraints?

### Easy explanation

When you change an AUIPC instruction's destination register from x1 to x17, the circuit processes this perfectly -- it decodes the mutated instruction, computes the result, and writes it to register x17. Every row-level constraint passes. Every accum delta check passes. So how does the verifier know something is wrong?

The answer is: **the polynomial protocol catches it.** Here's the analogy:

Imagine a company where every employee logs their daily transactions in a personal ledger. At the end of the month, an auditor combines all ledgers into one big spreadsheet and checks that debits equal credits. Each employee's ledger is internally consistent (no arithmetic errors), but when combined, there's a discrepancy because employee A received payment for work that was supposed to go to employee B.

In RISC Zero:
- Each row's accumulator delta is "the employee's daily ledger entry" -- internally correct
- The grand total across all rows is "the combined spreadsheet" -- should balance to zero
- The prover builds a polynomial that encodes all the ledger entries and their running total
- The verifier picks a random point and evaluates this polynomial to check if it's consistent
- If the total is non-zero, the polynomial has a subtle inconsistency that the random evaluation catches

### Technical detail: The exact enforcement mechanism

**Step 1: The prover builds the accumulator.** `step_TopAccum` computes per-row deltas. Prefix-sum creates the running total. Apply-totals adjusts columns. All of this makes the transition constraint `accum[i] - accum[i-1] = delta[i]` hold at every cycle row.

**Step 2: The prover evaluates the constraint polynomial.** `poly_fp` evaluates ALL constraints (local + accum transition) at every point in the extended domain (4x the cycle count). On the coset domain (with ZK shift), these are NOT evaluated at the actual cycle rows but at shifted points. The constraint polynomial C(x) is zero at cycle rows (where constraints hold) but NOT zero as a polynomial (because the accumulator polynomial doesn't satisfy the transition as a polynomial IDENTITY when the total is non-zero).

**Step 3: The prover builds the check polynomial.** V(x) = C(x) / Z(x), where Z(x) is the vanishing polynomial. If C(x) were the zero polynomial, V(x) would be the zero polynomial too. But C(x) is NOT zero (it's zero at cycle rows but non-zero between them), so V(x) is a non-trivial polynomial with higher-than-expected degree.

**Step 4: The verifier checks.** The verifier picks a random DEEP query point z and evaluates:
- `result = poly_ext(poly_mix, eval_u, args)` -- the constraint polynomial C(z) evaluated using committed tap polynomials
- `check = V(z) * Z(z)` -- the committed check polynomial times the vanishing polynomial

The verifier requires `check == result`, i.e., `V(z) * Z(z) == C(z)`. If they don't match, the verifier returns `InvalidProof`.

**Why they don't match when the permutation is violated:** The prover committed the check polynomial V based on the trace evaluation. But the constraint polynomial C, when evaluated at the random point z using the committed tap polynomials, gives a value that's inconsistent with V(z) * Z(z). This inconsistency arises because the accum polynomial, interpolated from row-wise-correct but globally-inconsistent values, doesn't satisfy the transition constraint as a polynomial identity. At the random point z (which is off the cycle domain), this inconsistency manifests as C(z) ≠ 0.

**The exact code location of the failure:**
```rust
// verify/mod.rs lines 374-378
if check != result {
    tracing::debug!("check != result");
    return Err(VerificationError::InvalidProof);
}
```

This runs BEFORE FRI. It is the DEEP-ALI validity check. FRI (which checks polynomial degree) would also fail, but the validity check catches it first.

### So what IS catching it?

It's caught by **the polynomial protocol** (specifically the DEEP-ALI validity check), which is part of the STARK proof system, not a circuit constraint. The circuit constraints (EQZ checks) only verify row-level properties. The polynomial protocol verifies that the ENTIRE trace is consistent as a set of low-degree polynomials.

To fill in your slide: "However, the way it is caught is **not** by a circuit constraint, it is by **the DEEP-ALI validity check in the STARK polynomial protocol** -- the verifier evaluates the constraint polynomial at a random point and detects that the accumulator polynomial doesn't satisfy the transition identity, even though it does at every individual cycle row."

**Confidence: 95%.** Verified from `verify/mod.rs` lines 356-380 (the exact check), `cpu.rs` lines 192-196 (how V is built), and the mathematical analysis of why the polynomial identity fails when the total is non-zero. The 5% uncertainty is about whether there could be an even earlier detection mechanism (e.g., the Merkle commitment step), but the `check != result` line is clearly the first explicit rejection point in the code.

---

## Slide 1 Corrections

Your slide 1 is **mostly correct** with these clarifications:

**Validity Polynomial hook (Hook 2):**
- "Shows both local and global constraint failures via polynomial eval at each cycle" -- CORRECT
- "Only cycle 0 shows global constraint evaluation" -- CORRECT for the accum wrap-around
- "Requires turning off domain shifting → Valid proofs fail" -- CORRECT
- "Aggregate binary yes/no" -- **PARTIALLY WRONG**. It's not binary -- it shows WHICH cycles are non-zero. But for global constraints specifically, it only shows cycle 0, so in that sense it's binary for global.

**Grand Product Value hook (Hook 1):**
- "Shows grand product value" -- CORRECT
- "Extracted right before creation of constraint polynomial" -- **SLIGHTLY IMPRECISE**. It's extracted after PREFIX-SUM (within the accum phase), which is before EVAL_CHECK (where the constraint polynomial is evaluated). More precisely: after prefix-sum, before apply-totals.
- "Valid proofs can verify" -- CORRECT
- "Aggregate binary yes/no depending on = 0? ≠ 0?" -- CORRECT

**Full Recordkeeping hook (Hook 3):**
- "Collects memory and lookup records during witness generation" -- CORRECT
- "Computes the grand product values itself" -- **SLIGHT CLARIFICATION**: it computes per-family LogUp sums, not the grand product. "Grand product" is a PLONK term; RISC Zero uses LogUp (logarithmic derivative sums). The math is `sum(count/hash)` not `product(hash)`.
- "Identifies problematic memory addresses / lookup values" -- CORRECT
- "Able to distinguish precise mismatches" -- CORRECT

---

## Slide 2 Corrections

**"Global constraints ≡ circuit constraints" -- Partially true:**
- "∃ circuit constraints ensuring the grand product / lookup components are correctly formed" -- CORRECT. These are the 155 EQZ checks in `step_TopAccum` (GenerateAccum.cpp:182/125) that verify each row's delta is computed correctly from the data.
- "∄ circuit constraints catching e.g. value written in memory address a has an equivalent value read from memory address a" -- **CORRECT**. There is no per-row constraint that checks cross-row memory consistency. The `IsRead` constraint checks `prevWord == word` within the SAME transaction, but doesn't check that `prevWord` actually matches a prior write.

**"Mutating the address of a destination register is not caught by local constraints" -- CORRECT.**

**"But, it is caught by the permutation argument!" -- CORRECT.**

**"However, the way it is caught is not by a circuit constraint, it is by [???]":**

Fill in: **"the DEEP-ALI validity check in the STARK polynomial protocol."**

More specifically: the verifier evaluates the mixed constraint polynomial (which includes accum transition constraints) at a random point. The accumulator polynomial, interpolated from values that satisfy the transition at cycle rows but NOT as a polynomial identity (because the grand total ≠ 0), produces a non-zero constraint value at the random point. The verifier compares this with the committed check polynomial and detects the mismatch, returning `InvalidProof`.

---

## Additional Notes for Your Presentation

### Why this matters for A4

A4's goal is finding **underconstraints** -- cases where a mutation should be caught but isn't. The fact that the permutation argument enforcement happens at the polynomial level (not as a circuit constraint) means:

1. **If the circuit has a bug where a permutation entry is missing**: The polynomial protocol would still catch it (the total would be non-zero). So the permutation argument provides defense in depth.

2. **If the polynomial protocol has a bug**: The circuit constraints would NOT catch a permutation violation. This is why A4's global hooks are valuable -- they independently verify the permutation argument without relying on the polynomial protocol.

3. **Hook 3 is the most powerful**: It independently computes per-family residues from raw records, identifies broken addresses, and doesn't interfere with proof verification. It's the best tool for A4's specific use case.

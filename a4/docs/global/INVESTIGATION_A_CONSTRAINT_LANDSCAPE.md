# Investigation A: Mapping the Complete Constraint Landscape of RISC Zero

## What We Are Investigating and Why

Our goal is to hook into RISC Zero's global constraints (permutation and lookup arguments) to extract granular diagnostic information when a mutation breaks them. Before we can design any hooks, we need to definitively answer a foundational question: **What types of constraints exist in RISC Zero, where does each live in the codebase, and which are already captured by our existing A4 hooks?**

We previously assumed that the 155 EQZ checks in `step_TopAccum` constituted "global constraints." Through empirical testing (COMP_OUT_MOD mutation), we discovered that these EQZ checks pass even when the permutation argument is violated, because the `zeroBack` mechanism zeros all previous-row references on accumulator columns. This means we may have a fundamental misunderstanding of where global constraints live. Investigation A aims to map the COMPLETE constraint landscape so we don't miss anything.

### Specific Questions This Investigation Answers

- **Unknown 1:** Are permutation and lookup arguments the ONLY global constraint mechanisms in RISC Zero? Are there boundary constraints, initialization constraints, or other cross-row mechanisms?
- **Unknown 2 (partial):** Where exactly in the codebase are ALL the pieces of constraint enforcement?
- **Hypothesis H4:** Can we verify whether the accumulated total uses separate accumulators per argument type (memory, U16, U8, cycle)?
- **Hypothesis H6:** Is there an explicit "total = 0" boundary constraint anywhere, or is it purely emergent?

---

## Part 1: The Three Layers of Constraint Enforcement

RISC Zero enforces correctness through three distinct layers, each operating at a different level of abstraction. Understanding these layers is essential.

### Layer 1: Prover-Side Witness Checks (C++ EQZ)

**Where:** `witgen.h`, `steps.cpp`, `ffi.cpp`

During proving, the prover generates the witness (execution trace) and checks constraints row-by-row using the `EQZ` macro. This is the layer where our A4 hooks operate.

- `step_Top` (1757 EQZ calls): Local constraints -- instruction decoding, ALU operations, memory format, etc.
- `step_TopAccum` (155 EQZ calls): Accumulator delta computation -- verifies that per-row contributions to the running sum are arithmetically correct.

These checks throw `std::runtime_error` on failure (unless `CONSTRAINT_CONTINUE=1`). They operate on raw witness values during generation.

**What it catches:** Arithmetic errors in the witness computation. Any row where the EQZ expression evaluates to non-zero.

**What it CANNOT catch:** Cross-row properties (like the total of all deltas being zero) because the `zeroBack` mechanism makes `step_TopAccum` evaluate each row independently.

### Layer 2: Prover-Side Polynomial Evaluation (poly_fp)

**Where:** `rust_poly_fp_*.cpp`, `eval_check.cpp`, `cpu.rs:145-205`

After witness generation, the prover evaluates the constraint polynomial (`poly_fp`) at every point in the extended evaluation domain (which is 4x the number of cycles). This uses the FINALIZED accumulator columns (after prefix-sum and apply-totals). The result is the "check polynomial" which is committed and verified.

- `poly_fp` evaluates the SAME algebraic expressions as `step_Top` + `step_TopAccum`, but on the finalized columns.
- It uses direct array indexing (no `zeroBack`), so accum column back-references read actual values.
- However, as analyzed in Hypothesis H2, the apply-totals adjustment may algebraically cancel in the transition constraint at actual cycle rows, meaning poly_fp may give the same results as the EQZ checks at cycle rows.
- poly_fp runs on the full extended domain (4x cycles), and constraint violations may manifest at extended-domain points even if they're zero at cycle rows.

**What it catches (at cycle rows):** The same as Layer 1 -- local and delta computation errors.

**What it catches (at extended-domain points, if H2 is correct):** Polynomial degree issues caused by the accumulated total being non-zero. This is not a single "failing row" but a distributed error across extended points.

### Layer 3: Verifier-Side Checks

**Where:** `verify/mod.rs`, `fri.rs`

The verifier performs several checks that go beyond the validity polynomial:

1. **Seal format and protocol info** -- basic structural checks
2. **Globals (public outputs) commitment** -- `out` values are hashed and committed to the Fiat-Shamir transcript
3. **Merkle tree verification** -- code, data, and accum groups each have Merkle trees whose roots are verified
4. **Code root check** -- `check_code(po2, code_root)` verifies the code matches the expected image
5. **Validity polynomial** -- `verify_validity` evaluates `poly_ext` at a random DEEP query point and compares to the committed check polynomial
6. **FRI verification** -- proves the check polynomial has low degree
7. **IOP completeness** -- ensures the entire seal was consumed

**Important:** The globals (`out`) and mix values are NOT checked by separate constraints. They are INPUTS to `poly_ext`, referenced via `PolyExtStep::GetGlobal(arg, offset)`. The validity polynomial uses these values in its constraint expressions, so if the public outputs are wrong, the polynomial evaluation will detect it.

### In Plain English

Think of it like an exam with three grading passes:

- **Layer 1 (EQZ):** The student (prover) checks their own work as they go. They verify each calculation step is correct. But they can't see the big picture (whether all the parts add up globally) because they're working one problem at a time.

- **Layer 2 (poly_fp):** After finishing, the student evaluates their entire answer sheet using a special scoring formula. This formula can detect both per-problem errors AND global consistency issues (like "all the budget items should sum to zero"). But the detection of global issues happens through a mathematical subtlety -- it manifests as a polynomial degree problem, not as a single "wrong answer."

- **Layer 3 (verifier):** The teacher checks the student's claimed score against an independent evaluation of the answer sheet. If the student's score doesn't match, the exam fails.

---

## Part 2: Complete Inventory of Constraint Types

### 2.1 Per-Row Arithmetic Constraints (EQZ / EqualZeroOp)

These are the constraints generated by the zirgen compiler from `.zir` source files. They are expressed as `EqualZeroOp` in the compiler IR, which becomes the `EQZ` macro in generated C++ code and `AndEqz` entries in the validity polynomial.

**Total: 1912 EQZ call sites in steps.cpp**
- 1757 in `step_Top` (local constraints)
- 155 in `step_TopAccum` (accumulator delta constraints)

These expand to 6205 `AndEqz` entries in `poly_ext.rs` (due to function inlining across instruction arms).

**Status: Fully captured by our A4 hooks.**

### 2.2 Conditional Constraints (AndCond)

In addition to `AndEqz` (unconditional "expression must be zero"), the validity polynomial also uses `AndCond(condition, inner_constraint)` which means "if condition is non-zero, then inner_constraint must hold."

```rust
// From adapter.rs:141-152
pub enum PolyExtStep {
    // ...
    AndEqz(Var, Var),      // chain, expression_that_must_be_zero
    AndCond(Var, Var, Var), // chain, condition, inner_constraint
}
```

In the C++ witness generation, conditional constraints are expressed as `if` branches around EQZ calls (the instruction arm selectors). The `if (to_size_t(LOAD(selector, 0)))` pattern in `step_Top` and `step_TopAccum` implements this.

**Status: Captured by our A4 hooks.** When the selector is non-zero, the EQZ fires; when zero, the constraint is inactive. Our hooks see the same behavior.

### 2.3 Accumulator Transition Constraints (Generated by GenerateAccum.cpp)

This is the critical piece. The zirgen compiler's `GenerateAccum.cpp` pass generates the accumulator circuit. Here is exactly what it does, traced from the source:

**Initialization (GenerateAccum.cpp:88-96):**
```
oldT = Load(lastAccumColumn, distance=1)  // back=1: previous row's last accum column
t = oldT
```
This reads the previous row's final accumulator value. The `unchecked` attribute (line 94) tells the zeroBack mechanism to return 0 instead of reading actual values during prover-side execution.

**Per-argument accumulation (GenerateAccum.cpp:229-241):**
```
For each argument (MemoryArg, ArgU16, ArgU8, CycleArg):
  v = condense(argument fields, verifier randomness)  // random linear combination
  delta = count * inv(v + offset)                      // LogUp contribution
  t = t + delta                                        // accumulate
```

**Constraint generation (GenerateAccum.cpp:175-182):**
After every 3 arguments (or fewer if that's all there are), a constraint is emitted:
```
Store accum[col_k] = t
Load newT = accum[col_k]
EqualZero((newT - oldT) * product_of_denominators - sum_of_numerator_terms)
oldT = newT
```
This is the `GenerateAccum.cpp:182` constraint that we see 142 times in the generated code.

**Finalization (GenerateAccum.cpp:106-126):**
After all arguments for a row are accumulated, the final accumulator value is copied to the last column:
```
Store accum[lastCol] = t
Load newT = accum[lastCol]
EqualZero(newT - oldT)  // This is GenerateAccum.cpp:125
```
This ensures the last column holds the final accumulated value for the next row to read.

**Status: The EQZ checks are captured by our hooks. However, the `oldT = Load(lastCol, back=1)` at initialization reads 0 due to zeroBack, so the transition constraint effectively checks the delta, not the running sum.**

### 2.4 Lookup Arguments (LookupDelta / LookupCurrent)

Defined in the zirgen DSL via `extern` functions:

```zir
// lookups.zir
extern LookupDelta(table: Val, index: Val, count: Val);
extern LookupCurrent(table: Val, index: Val): Val;
```

Four argument types are defined, each with a table ID:

| Argument Type | Table ID | Fields | Defined In |
|---|---|---|---|
| `ArgU8` | 8 | count, val | lookups.zir:8 |
| `ArgU16` | 16 | count, val | lookups.zir:32 |
| `MemoryArg` | (implicit) | count, addr, cycle, dataLow, dataHigh | mem.zir:24 |
| `CycleArg` | 0 | count, cycle | mem.zir:53 |

The `LookupDelta` extern records the lookup usage into `LookupTables` during witness generation. These values are later used by the accumulator computation in `step_TopAccum`.

**Important finding:** All lookup arguments feed into the SAME accumulator running sum. There are NOT separate accumulators per argument type. The single running sum (stored across 20 accum layout columns per row) combines contributions from all four argument types. This confirms Hypothesis H4 (confidence 75%) -- we cannot separate which argument type failed from the accumulated total alone.

**Status: The lookup deltas are recorded during witgen. The accumulator constraints (which verify the delta computation) are captured by our hooks. The global property (total = 0) is NOT directly checked anywhere in the prover-side C++ code.**

### 2.5 Boundary / Initialization Constraints

**Finding: There are NO explicit boundary constraints in the RISC Zero rv32im circuit.**

Specific evidence:

1. **No "boundary" constraints in poly_ext.rs or steps.cpp** -- searched exhaustively, no results.
2. **No row-specific constraints** -- all EQZ checks in `step_TopAccum` fire within instruction-arm selector branches. There is no "if cycle == 0" or "if cycle == lastCycle" guard.
3. **`extern_isFirstCycle_0` (ffi.cpp:251-253)** exists but is used during witgen for initialization logic, not as a verifier constraint.
4. **The zirgen test runner (run.cpp:288-291)** explicitly sets the last row's last 4 accum columns to 0 BEFORE running the accum phase:
   ```cpp
   // Make final accum == 0
   for (size_t i = 0; i < 4; i++) {
       trace.accum.set(cycles - 1, trace.accum.getCols() - 4 + i, 0);
   }
   ```
   And the comment at line 296 says: `// TODO: Check final is zero?`

5. **The `unchecked` attribute on the back=1 load (GenerateAccum.cpp:94)** confirms that the initial "previous row" value is intentionally 0, not a constraint.

**This is a significant finding for Hypothesis H6.** The "total = 0" property is NOT enforced by an explicit boundary constraint in the circuit. It is enforced by the polynomial protocol: if the total is non-zero, the accum column polynomial cannot simultaneously satisfy all per-row transition constraints as a polynomial identity over the cyclic domain. The FRI check detects this as a degree violation.

**In plain English:** There is no constraint that explicitly says "the running sum at the end must equal the running sum at the beginning (which is zero)." Instead, the prover commits to the accumulator column polynomials, and the verifier checks that these polynomials satisfy the transition constraint at a random point. If the total is non-zero, the polynomials can't satisfy the transition constraint everywhere (they can at cycle rows, thanks to apply-totals, but not at extended-domain points), so the polynomial has higher-than-expected degree, and the FRI check fails.

### 2.6 The "Code" Register Group

The code group is a separate set of columns (1 column, back=0 only) that holds control/instruction trace information. It is committed as a Merkle tree and its root is checked via `check_code(po2, code_root)` in the verifier.

The code group's values are also used as inputs to constraints in `poly_fp` (via `PolyExtStep::Get` for code taps). These are NOT additional constraints -- they are input values to the existing constraint expressions.

**Status: The code root check is a verifier-side check (Layer 3). Our hooks don't need to capture this because it verifies the image identity, not constraint satisfaction.**

### 2.7 Global / Mix Buffers

The "global" buffer (out) holds per-segment public values: state_in, state_out, input, RNG seed, etc. The "mix" buffer holds verifier-supplied random challenge values used for constraint mixing and the accumulator.

Both are passed as `args` to `poly_ext`/`poly_fp` and referenced via `GetGlobal`. They are INPUTS to the constraint polynomial, not separate constraints.

**Status: These do not need separate hooking. They feed into the constraint expressions that our EQZ hooks already capture.**

### 2.8 Non-Arithmetic Checks (Throws in C++)

Several `throw` calls exist in the C++ code that are NOT circuit constraints:

| Location | Throw | Purpose |
|---|---|---|
| `witgen.h:204` | `eqz failure` | The EQZ constraint failure (our hook point) |
| `ffi.cpp:186` | `txn cycle mismatch` | Preflight trace consistency |
| `ffi.cpp:204` | `memory peek not in preflight` | Preflight trace consistency |
| `tables.h:46,58,79` | `Invalid lookup table` / `u8/16 table error` | Lookup table validation |
| `buffers.h:45,68` | `Inconsistent set` / `Read of unset value` | Buffer state validation |

These are prover-side implementation checks, not circuit constraints. They catch bugs in the prover code or invalid preflight traces. They cannot be triggered by a valid-structure mutation (which only modifies values within an existing trace, not the trace structure).

**Status: Not relevant for our global constraint hooking goal.**

---

## Part 3: The Tap Structure and What It Reveals

The taps definition (`taps.rs`) describes how the validity polynomial references columns across rows. This is critical for understanding which cross-row relationships are enforced.

### Tap Groups

| Group | Name | Taps | Description |
|---|---|---|---|
| 0 | accum | 119 | Accumulator columns (permutation/lookup running sums) |
| 1 | code | 1 | Control/instruction trace |
| 2 | data | 670 | Execution trace (memory, registers, ALU, etc.) |

### Combo Structure (Back Values)

Taps are organized into "combos" that share a denominator in the DEEP-ALI protocol:

| Combo | Back Values | What It Means |
|---|---|---|
| 0 | [0] | Current row only |
| 1 | [0, 1] | Current and previous row |
| 2 | [0, 1, 2, 3, 4, 68] | Current row and up to 68 rows back (BigInt accum powers) |
| 3 | [0, 2, 7, 15, 16] | BigInt accum with specific offsets |

**Key finding:** Most taps use back=0 or back=1. Only the BigInt accumulator uses larger back values (up to 68). This means cross-row relationships are primarily between adjacent rows (current and previous).

The accum group (119 taps) includes back=0 and back=1 references. The back=1 references are what create the transition constraints in the validity polynomial. During prover-side witness generation (`step_TopAccum`), these back=1 reads return 0 due to `zeroBack`. In the polynomial evaluation, they reference actual committed values.

### In Plain English

The taps are like a template that says "this constraint expression needs to read column X at the current row and column Y at the previous row." During witness generation, the "previous row" read for accum columns is artificially zeroed out (to make the computation work row-by-row). In the polynomial evaluation, the previous row read uses the actual polynomial value, creating a genuine cross-row constraint.

---

## Part 4: How the Permutation Argument Total Is (Not) Checked

This is the most important finding of the investigation. There are three places where the accumulated total could theoretically be checked:

### 4.1 During step_TopAccum (NOT checked)

The `zeroBack` mechanism makes the initial accumulator value 0 for every row. Each row computes its delta independently. No row checks the running total.

### 4.2 After prefix-sum (NOT checked)

After prefix-sum, the last row of the last 4 columns contains the total of all deltas. The prover does NOT check this value. The code proceeds directly to apply-totals without any assertion on the total.

### 4.3 In the validity polynomial / FRI (CHECKED, but indirectly)

The total-is-zero property is enforced by the polynomial protocol. The logic is:

1. The prover commits to accum column polynomials (these interpolate the finalized values)
2. The verifier evaluates the constraint polynomial at a random point z
3. The constraint polynomial includes `accum[col0](z) - accum[col19](z * omega^{-1})` (the transition constraint)
4. If the total is zero, the accum polynomials satisfy the transition constraint as a polynomial identity, so the constraint polynomial evaluates to zero at z (with overwhelming probability)
5. If the total is NON-zero, the accum polynomials do NOT satisfy the constraint as a polynomial identity -- they only satisfy it at cycle rows (by construction of apply-totals). The constraint polynomial has higher degree than expected, and the FRI check detects this.

**This means the permutation argument failure is detected as a DEGREE VIOLATION in the check polynomial, not as a CONSTRAINT VIOLATION at any specific row.**

### In Plain English

Imagine a bookkeeper who tracks debits and credits. At the end of each day (row), they correctly record the day's transactions (delta). At the end of the month, the running total should be zero (all debits match credits). But the bookkeeper doesn't explicitly check "does the total equal zero?" Instead, they hand their ledger to an auditor who uses a mathematical trick: the auditor evaluates the ledger as a polynomial and checks its degree. If the total is non-zero, the polynomial has an unexpected bump, and the auditor catches it. But no single ledger entry is "wrong" -- the error is emergent from the entire sequence.

---

## Part 5: Implications for Our Master Plan Hypotheses

### Hypothesis H1 (post-prefix-sum total check, confidence 85%): STRENGTHENED to 90%

The investigation confirms that the accumulated total (last row of last 4 prefix-summed columns) is the cleanest signal for permutation/lookup argument failure. The zirgen test runner (`run.cpp:296`) even has a TODO comment about checking this. No one is currently checking it on the prover side.

### Hypothesis H4 (per-argument-type granularity not available, confidence 75%): CONFIRMED at 90%

All four argument types (MemoryArg, ArgU16, ArgU8, CycleArg) feed into the SAME accumulated running sum via `GenerateAccum.cpp`'s layout traversal. There are NOT separate accumulators per argument type. The single total mixes all contributions together.

### Hypothesis H6 (no explicit boundary constraint, confidence 65%): CONFIRMED at 95%

Evidence:
- No boundary constraint in poly_ext.rs or steps.cpp
- The zirgen test runner explicitly sets the "initial" accum value to 0 before the accum phase
- `GenerateAccum.cpp:94` marks the back=1 load as `unchecked`
- The `run.cpp:296` TODO says "Check final is zero?"

The "total = 0" property is enforced PURELY by the polynomial protocol (FRI degree check), not by any explicit constraint.

### NEW Finding: All argument types share one accumulator

This means:
- A non-zero total tells us "SOME argument failed" but not "memory vs U16 vs U8 vs cycle"
- To get per-argument-type info, we'd need to replay the accumulator computation separately for each type and check each partial sum
- This is possible (the data columns contain the argument fields) but requires significant additional computation

---

## Part 6: Complete Constraint Map

| Constraint Category | Count | Where Enforced | Our Hook Status | Catches Permutation Violations? |
|---|---|---|---|---|
| Local (instruction, ALU, memory format, etc.) | 1757 EQZ | step_Top | Hooked | No (different mechanism) |
| Accum delta computation | 142 EQZ | step_TopAccum (GenerateAccum:182) | Hooked | No (zeroBack) |
| Accum column continuity | 13 EQZ | step_TopAccum (GenerateAccum:125) | Hooked | No (zeroBack) |
| Accumulated total = 0 | 0 explicit | Polynomial degree (FRI) | NOT hooked | Yes (indirectly, via degree) |
| Public output consistency | Embedded in poly | poly_ext (GetGlobal) | Hooked (via EQZ) | N/A |
| Code image identity | 1 | Verifier check_code | Not hooked (not needed) | N/A |
| Merkle commitments | 3 | Verifier verify_group | Not hooked (not needed) | N/A |

### The Gap

The ONLY constraint category that catches permutation/lookup argument violations is "Accumulated total = 0", and it has **0 explicit constraints**. It is enforced purely through polynomial degree checking. This is the gap we need to fill.

---

## Part 7: Answers to Investigation Questions

**Q: Are permutation and lookup arguments the ONLY global constraint mechanisms?**
Yes. The RISC Zero rv32im circuit uses exactly four argument types (MemoryArg, ArgU16, ArgU8, CycleArg), all implemented through the same LogUp-style accumulator mechanism via `GenerateAccum.cpp`. There are no other cross-row enforcement mechanisms, no boundary constraints, and no initialization constraints. The first-cycle logic (`isFirstCycle`) is used for witgen initialization, not as a verifier constraint.

**Q: Are there constraint types we haven't found?**
No. The complete set is: EQZ (AndEqz in polynomial), conditional constraints (AndCond in polynomial), Merkle commitments, code root check, and polynomial degree (FRI). The first two are arithmetic constraints captured by our hooks. The last three are structural/commitment checks handled by the verifier.

**Q: Do lookup arguments and permutation arguments account for ALL non-local constraints?**
Yes. Every non-local constraint in the circuit is expressed through the accumulator mechanism. There are no other global constraint types.

---

## Part 8: What This Means for Next Steps

1. **The post-prefix-sum total check (H1) is our best option for detecting permutation/lookup failures.** It's cheap, direct, and provides a binary signal. We should implement this first.

2. **Per-argument-type granularity requires additional work** beyond the total check. Since all argument types share one accumulator, we'd need to compute partial sums separately. This could be a later enhancement.

3. **Investigation C (verifying H2 about poly_fp) is still important** to confirm whether poly_fp at cycle rows adds anything beyond what EQZ already captures. But given our findings about the polynomial degree enforcement, it's less likely to be a useful hook point for global constraints.

4. **Investigation B (full lifecycle trace) can be simplified** now that we understand the GenerateAccum.cpp structure. The key remaining question is whether the apply-totals cancellation analysis is correct (which is Investigation C territory).

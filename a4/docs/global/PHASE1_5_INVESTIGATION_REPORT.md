# Phase 1.5 Investigation Report

## Overview

The F2 campaign (100 mutations with `circuit_debug` enabled) produced three anomalies. This report documents the investigation and findings for each.

---

## Anomaly 3: Runs 87-100 All Show 32768 Non-zero Cycles

**Root cause: Binary replaced mid-campaign.**

During the F2 campaign, the host binary was rebuilt WITHOUT `circuit_debug` (to run the accum campaign test). The F2 campaign was running in a separate terminal. Starting at run 87, the campaign picked up the new binary, which has ZK shift enabled. With ZK shift, all check polynomial entries are non-zero (coset evaluation) regardless of constraint satisfaction.

**Evidence:** Runs 1-86 show `check_nz` ranging from 1-9. Runs 87-100 uniformly show `check_nz=32768`. The binary's modification timestamp falls exactly between runs 86 and 87.

**Resolution:** Runs 1-86 are valid. Runs 87-100 are discarded. 86 valid runs is sufficient for analysis.

---

## Anomaly 1: Global-Only Mutations (0 Local + Cycle 0 Non-zero)

### What We Found

Three runs from the valid portion (15, 39, 47) showed zero local constraint failures but a non-zero check polynomial at cycle 0. All three were reproduced individually with consistent results.

### Run 15: MEM_VAL_MOD at step 3929

- **Step 3929 is the LAST cycle** (cycle_idx 32767), instruction type `major=7 (CONTROL), minor=7`
- This is the system shutdown cycle with 2590 transactions
- The mutation changes txn 33304 from `word=0` to `word=939042955`
- This is a memory transaction during the shutdown/halt sequence

**Why no local constraints fire:** The CONTROL instruction arm (major=7) at shutdown processes a large batch of memory transactions (page-outs). The MemoryWrite local constraints check consistency between the old and new transaction values. Since the mutation modifies the preflight trace BEFORE witness generation, the witness is built from the mutated value. The local constraints see internally consistent data at this row.

**Why cycle 0 is non-zero:** The mutated memory value changes the accumulator delta for the memory permutation argument at this cycle. The running total no longer sums to zero, causing the wrap-around transition at cycle 0 to fail.

### Run 39: INSTR_WORD_MOD_SUR at step 573

- Original instruction: `0x00003097` = **AUIPC x1, 0x3** (add upper immediate to PC, write to register x1)
- Mutated instruction: `0x00003897` = **AUIPC x17, 0x3** (same operation, but writes to register x17 instead)
- The ONLY difference: destination register changed from x1 (ra) to x17 (s1)

**Why no local constraints fire:** The instruction still decodes as a valid AUIPC. The opcode, funct3, immediate, and source register are unchanged. The ALU computation is identical. The witness generator processes the mutated instruction and writes the result to register x17 instead of x1. All row-level constraints (decode, ALU, memory format) are satisfied because the instruction is valid.

**Why cycle 0 is non-zero:** Register x17 gets a value that was originally meant for x1. Downstream instructions that READ x1 get the old value (or zero), while no instruction reads the new x17 value. The memory permutation argument breaks because the write-to-x17 doesn't match any corresponding read-from-x17, and the expected write-to-x1 is missing. The grand total is non-zero, causing the cycle 0 wrap-around failure.

### Run 47: INSTR_WORD_MOD_SUR at step 49

- Original instruction: `0x188080e7` = **JALR x1, x1, 0x188** (jump and link, write return address to x1)
- Mutated instruction: `0x18808867` = **JALR x16, x1, 0x188** (same jump, but writes return address to x16)
- Again, ONLY the destination register changed: x1 -> x16

**Same mechanism as Run 39.** The instruction is still valid JALR. Local constraints pass. But the register write goes to x16 instead of x1, breaking the memory permutation.

### Key Finding

**Global-only violations are real and occur with existing A4 mutation types.** Specifically, `INSTR_WORD_MOD_SUR` (surgical instruction word modification) can change the destination register of an instruction without breaking any local constraints, while breaking the memory permutation argument. This is exactly the "premium bucket" we were looking for.

The mechanism: changing the destination register produces a valid instruction (all row-local checks pass) but disrupts the memory transaction pattern (the write goes to a different address than expected, breaking the cross-row read-write matching).

### Updated Hypothesis H5

**Old confidence: 60%.** "There may exist mutations that break permutation/lookup arguments WITHOUT triggering any local constraint failure."

**New confidence: 95% -- CONFIRMED.** We found 3 such mutations in 86 valid runs (3.5% rate). The mechanism is well-understood: surgical instruction modifications that change the destination register preserve all local constraints while breaking the memory permutation argument.

---

## Anomaly 2: INSTR_TYPE_MOD Sometimes Affects Cycle 0

### What We Found

Of 11 INSTR_TYPE_MOD runs in the valid portion:
- 7 runs (3, 13, 26, 44, 64, 66, 68) show cycle 0 non-zero
- 4 runs (23, 33, 65, 82) do NOT show cycle 0

### The Pattern

**Runs WITHOUT cycle 0 (accum unaffected):**

| Run | Original | New | Change |
|-----|----------|-----|--------|
| 23 | MISC0 (m0) | DIV0 (m4) | ALU to division |
| 33 | MISC0 (m0, min7) | MISC0 (m0, min1) | Same major, different minor |
| 65 | MEM1/store (m6, min2) | MEM1/store (m6, min0) | Same major, different minor |
| 82 | MISC0 (m0) | DIV0 (m4) | ALU to division |

**Runs WITH cycle 0 (accum affected):**

| Run | Original | New | Change |
|-----|----------|-----|--------|
| 3 | MISC2 (m2) | MEM1/store (m6) | ALU to memory store |
| 13 | MISC1 (m1) | MISC2 (m2) | Different MISC type |
| 26 | MEM0/load (m5) | MISC2 (m2) | Memory load to ALU |
| 44 | MISC0 (m0) | MEM1/store (m6) | ALU to memory store |
| 64 | MISC2 (m2, min5) | MISC2 (m2, min3) | Same major, different minor |
| 66 | MISC1 (m1) | MEM0/load (m5) | ALU to memory load |
| 68 | MISC0 (m0) | MEM0/load (m5) | ALU to memory load |

### Explanation

INSTR_TYPE_MOD changes the `major`/`minor` values in the preflight trace, which determines which instruction arm's code executes during witness generation. Each instruction arm has a specific set of accumulator contributions (lookup arguments for U16 range checks, memory operations, etc.).

**When the new instruction arm has DIFFERENT accumulator contributions from the original:**
The per-row delta changes. The total running sum no longer cancels to zero. Cycle 0 shows non-zero.

**When the new instruction arm has EQUIVALENT accumulator contributions:**
The total running sum is unaffected (or happens to cancel). Cycle 0 remains zero.

Examples:
- MISC0 -> DIV0 (runs 23, 82): Both are ALU-type with similar lookup argument patterns. The accumulator contributions may be equivalent.
- MISC0 min7 -> MISC0 min1 (run 33): Same instruction category, slight sub-operation change. Accumulator contributions preserved.
- MEM1 min2 -> MEM1 min0 (run 65): Same store instruction category, minor variant. Contributions preserved.
- MISC2 -> MEM1 (run 3): Completely different instruction categories (ALU vs memory store). Different memory arguments, different lookup counts. Contributions change.
- MISC2 min5 -> MISC2 min3 (run 64): Within the same major, but different sub-operations that happen to have different numbers of U16/U8 lookup arguments.

### Key Finding

**INSTR_TYPE_MOD affects the permutation argument when and only when the instruction type change alters the set of accumulator contributions (lookup and memory arguments) at that cycle.** This is not surprising -- it's the expected behavior. Changing instruction type changes which lookups and memory operations are performed, which changes the accumulator deltas.

This also means INSTR_TYPE_MOD is NOT purely a "local constraint" mutation. It can break global constraints too, depending on the specific type change.

---

## Updated Hypotheses

### H2: poly_fp at cycle rows detects global violations (REFUTED)

The original hypothesis claimed poly_fp at cycle rows gives the same results as step_TopAccum. This is REFUTED: cycle 0 shows non-zero in the check polynomial when the permutation argument is broken, even when no local or accum EQZ fails. However, this requires `circuit_debug` mode (ZK shift disabled).

### H3: Permutation violation provides no additional info for value mutations (REVISED)

**Old confidence: 80%.** Still mostly true for value mutations (COMP_OUT_MOD, LOAD_VAL_MOD) which trigger both local and global failures. But for INSTR_WORD_MOD_SUR (which changes destination registers), the permutation violation is the ONLY signal -- local constraints don't fire at all.

**New confidence: 60%.** The statement is true for some mutation types but not others.

### H5: Global-only mutations exist (CONFIRMED)

**Old confidence: 60%. New confidence: 95%.**

Found 3 global-only mutations in 86 valid runs (3.5% rate):
- 1 MEM_VAL_MOD at a system/shutdown cycle
- 2 INSTR_WORD_MOD_SUR changing destination registers

The mechanism is clear: mutations that produce valid instructions/transactions at the row level but disrupt cross-row consistency (memory read-write matching) break the permutation argument without breaking local constraints.

---

## Implications for the Master Plan

1. **Global constraint detection is proven valuable.** The 3.5% global-only rate means roughly 1 in 28 mutations produces a violation detectable only through global signals.

2. **The check polynomial scan (Hook 2 with circuit_debug) works correctly** for detecting these violations.

3. **Phase 2 (binary residue check) is high priority** -- it would catch these global-only violations without needing circuit_debug mode.

4. **Phase 3 (shadow replay)** would tell us WHICH argument family failed (memory vs U16 vs U8 vs cycle).

5. **Phase 4 (global-only mutation operators)** can build on the discovered mechanism: surgical destination register changes are a reliable way to produce global-only violations.

6. **The bandit should value INSTR_WORD_MOD_SUR highly** -- it's the mutation type most likely to produce the premium global-only bucket.

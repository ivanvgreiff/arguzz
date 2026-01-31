# A3 Mutation Strategy

> ⚠️ **STATUS: DEPRECATED** - See [Why A3 Was Abandoned](#why-a3-was-abandoned) below. Use **A4** instead.

A3 is a mutation strategy that modifies the **post-witness-built DATA matrix** directly, as opposed to Arguzz which hooks into the executor during instruction execution.

## Why A3 Was Abandoned

### The Fundamental Problem

A3 mutates the DATA matrix **AFTER** witness generation completes. However, constraint checking (`EQZ` calls) happens **DURING** witness generation, not after.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Witness Generation Flow                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. WitnessGenerator::new()                                      │
│     └── stepExec() for each cycle                                │
│         └── EQZ() ← CONSTRAINT CHECKING HAPPENS HERE             │
│                                                                  │
│  2. A3 mutation hook ← WE MUTATE HERE (TOO LATE!)                │
│                                                                  │
│  3. prover.commit_group(DATA) ← Mutated data goes to prover      │
│                                                                  │
│  4. Proving (polynomial evaluation) ← Catches violation, but     │
│                                        NO granular EQZ output    │
└─────────────────────────────────────────────────────────────────┘
```

### What We Discovered

1. **EQZ is never called after witness generation** - We verified through source code analysis that all 1912 `EQZ` calls in `steps.cpp` occur within `step_Top()` during witness generation.

2. **Polynomial evaluation doesn't provide granularity** - The `poly_fp()` function aggregates all constraints with random mixing coefficients. Even with `circuit_debug` enabled, we can only identify which CYCLE failed, not which specific constraint.

3. **A3 mutations ARE detected** - The prover does fail (`"status":"error"`), proving the mutation is caught. But the detection mechanism is polynomial identity testing, not `EQZ`.

### Test Results

```bash
# A3 mutation was applied successfully...
<a3_mutation_applied>{"row":16625, "col":61, "old":5109, "new":41845}</a3_mutation_applied>
<a3_mutation_applied>{"row":16625, "col":62, "old":34, "new":1145}</a3_mutation_applied>

# ...but NO constraint_fail messages, only prover failure
<record>{"context":"Prover", "status":"error", "time":"13.27s"}</record>
```

### The Solution: A4

A4 solves this by mutating the **PreflightTrace** (memory transactions) BEFORE witness generation:

```
Execution → PreflightTrace.txns[] → A4 MUTATION → WitnessGenerator::new()
                                                          ↓
                                                   stepExec() → EQZ()
                                                          ↓
                                                   Granular failures! ✓
```

See the `a4/` folder for the working implementation.

---

## Original A3 Documentation (For Reference)

### Purpose

Compare constraint failures between:
- **Arguzz**: Executor-level mutation (modifies values during execution)
- **A3**: Post-witness mutation (modifies DATA matrix cells after witness generation)

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      zkVM Pipeline                               │
├──────────────┬──────────────────────┬───────────────────────────┤
│   Executor   │  Witness Generation  │   Constraint Checking     │
│              │                      │                           │
│  ┌────────┐  │                      │                           │
│  │ Arguzz │  │                      │                           │
│  │mutation│──┼──────────────────────┼──► Constraints see        │
│  └────────┘  │                      │    corrupted trace        │
│              │                      │                           │
│              │  ┌────────────────┐  │                           │
│              │  │ A3 mutation    │  │                           │
│              │  │ (post-witness) │──┼──► Prover failure only    │
│              │  └────────────────┘  │    (no EQZ granularity)   │
└──────────────┴──────────────────────┴───────────────────────────┘
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `A3_CONFIG=/path/to/config.json` | Path to JSON mutation config file |
| `A3_INSPECT=1` | Enable DATA matrix inspection output |
| `A3_DUMP_ROW=N` | Dump specific cell (requires A3_DUMP_COL) |
| `A3_DUMP_COL=M` | Column for cell dump |
| `A3_DUMP_ROW_FULL=N` | Dump all 211 columns for row N |

### JSON Config Format

```json
{
  "mutations": [
    {"row": 16625, "col": 61, "value": 41845},
    {"row": 16625, "col": 62, "value": 1145}
  ]
}
```

### Key Discoveries (Still Valuable)

#### Row Mapping
- DATA matrix rows ≠ instruction steps
- Thousands of setup rows exist before first instruction
- Row index shifts when Arguzz mutations cause trace divergence
- Always find row dynamically using `A3_INSPECT`

#### Column Layout (Block Type Dependent)
For `block_type 0` (Globals) with computation instructions:
- Column 61: Low 16 bits of output
- Column 62: High 16 bits of output

**Note**: Column offsets vary by block type. Empirical verification recommended.

### Files

- `configs/` - JSON mutation configuration files (kept for reference)
- Runtime code in `risc0-modified/risc0/circuit/rv32im/src/prove/hal/mod.rs`

---

## Conclusion

A3's approach of mutating the post-witness DATA matrix is fundamentally incompatible with getting granular `EQZ` constraint failure information. The constraint checking phase has already completed by the time A3 can mutate.

**Use A4 instead** - it mutates at the right point in the pipeline to get full `EQZ` granularity while still being a post-execution mutation strategy.

# PRE_EXEC_REG_MOD Mutation Strategy

## Overview

`PRE_EXEC_REG_MOD` is an A4 mutation strategy that corrupts a register value in the PreflightTrace to simulate what Arguzz does when it injects a random value into a random register **BEFORE** instruction execution.

**Arguzz's PRE_EXEC_REG_MOD:**
- Executes during instruction execution (rv32im.rs)
- Picks a random register and writes a random value to it BEFORE the instruction executes
- This causes cascading effects as subsequent instructions use the corrupted register value

**A4's PRE_EXEC_REG_MOD:**
- Operates on the post-execution PreflightTrace (preflight.rs)
- Targets a specific transaction in the trace to simulate the same corruption
- Two strategies available: `next_read` and `prev_write`

## Strategies

### Strategy 1: `next_read` (Default)

**How it works:**
1. Parse Arguzz fault to get target register (e.g., "a7") and corrupted value
2. Find the A4 step corresponding to the Arguzz injection step
3. Search FORWARD to find the NEXT READ transaction of that register **during an instruction cycle**
4. Modify that READ's `word` field to the corrupted value
5. Keep `prev_word` unchanged to create `word ≠ prev_word` inconsistency

**Expected constraint failures:**
- `IsRead@mem.zir` (direct) - word doesn't match prev_word
- `MemoryWrite@mem.zir` (cascade) - downstream effects

**When to use:** When you want to verify that the circuit detects a register READ with an inconsistent value.

### Strategy 2: `prev_write`

**How it works:**
1. Parse Arguzz fault to get target register (e.g., "a7") and corrupted value
2. Find the A4 step corresponding to the Arguzz injection step
3. Search BACKWARD to find the PREVIOUS WRITE to that register
4. Modify that WRITE's `word` field to the corrupted value
5. The next READ's `prev_word` won't match the modified WRITE's `word`

**Expected constraint failures:**
- `MemoryWrite@mem.zir` ONLY - the WRITE has wrong value, but writes don't check IsRead

**When to use:** When you want to verify that the circuit detects a modified WRITE that creates inconsistency with subsequent reads.

## Important Implementation Details

### Instruction Cycle Filtering (next_read only)

The `next_read` strategy **ONLY targets transactions during instruction execution cycles** (major 0-6). This is critical because:

1. **Non-instruction cycles don't check IsRead constraints** - Poseidon hash (major 9-10), SHA (major 11), BigInt (major 12), and Control/Ecall (major 7-8) cycles have different constraint logic that doesn't include memory consistency checks.

2. **Semantic correctness** - Arguzz corrupts registers during instruction execution. A4 should target the same type of operations to simulate equivalent behavior.

### Major Value Reference

From `platform.rs`:

| Major | Name | Description | IsRead Checked? |
|-------|------|-------------|-----------------|
| 0 | MISC0 | Compute (Add, Sub, Xor, Or, And, Slt, SltU, AddI) | **YES** |
| 1 | MISC1 | Immediate (XorI, OrI, AndI, SltI, SltIU, Beq, Bne, Blt) | **YES** |
| 2 | MISC2 | Branch/Jump (Bge, BltU, BgeU, Jal, JalR, Lui, Auipc) | **YES** |
| 3 | MUL0 | Multiply/Shift (Sll, SllI, Mul, MulH, MulHSU, MulHU) | **YES** |
| 4 | DIV0 | Divide/Shift (Srl, Sra, SrlI, SraI, Div, DivU, Rem, RemU) | **YES** |
| 5 | MEM0 | Load (Lb, Lh, Lw, LbU, LhU) | **YES** |
| 6 | MEM1 | Store (Sb, Sh, Sw) | **YES** |
| 7 | CONTROL0 | Control/padding | NO |
| 8 | ECALL0 | Ecall operations | NO |
| 9 | POSEIDON0 | Poseidon hash | NO |
| 10 | POSEIDON1 | Poseidon hash | NO |
| 11 | SHA0 | SHA operations | NO |
| 12 | BIGINT0 | BigInt operations | NO |

### Why prev_write Always Works

The `prev_write` strategy always finds valid instruction-cycle targets because:
- Register WRITEs only occur during instruction execution (ADD, LW, ADDI, etc.)
- All instructions that write to registers have major 0-6
- The search looks backward from the injection point (during normal execution)

## Known Limitations

### Limitation 1: next_read May Skip Valid Targets

If the only READ of a corrupted register after the injection point occurs during a non-instruction cycle (e.g., Poseidon hash finalization), `next_read` will report "no valid target" and skip the test.

**Example scenario discovered during verification:**
- Arguzz step 3714 corrupts register a7
- The next READ of a7 happens at cycle_idx 21267, which is a Poseidon hash cycle (major=9)
- A4's `next_read` cannot target this because Poseidon cycles don't check IsRead constraints
- Result: Test marked as "N/A (no valid target in instruction cycles)"

**Workaround:** Use `prev_write` strategy instead, which always finds instruction-cycle targets.

### Limitation 2: Different Constraint Types

The two strategies trigger **different constraint types**:

| Strategy | Expected Constraints |
|----------|---------------------|
| `next_read` | `IsRead@mem.zir` + `MemoryWrite@mem.zir` |
| `prev_write` | `MemoryWrite@mem.zir` ONLY |

When comparing with Arguzz, be aware that Arguzz typically triggers `IsRead` failures (because it effectively corrupts the value that gets read), while `prev_write` only triggers `MemoryWrite` failures.

### Limitation 3: Comparison Method

Because Arguzz and A4 mutate at **different steps** (Arguzz injects at step N, A4 might mutate at step N-50 for prev_write or N+10 for next_read), we use `compare_failures_by_constraint_only()` instead of exact step/PC comparison.

This means we only verify that the **same constraint types** are triggered, not that they occur at exactly the same step/PC.

## Usage

### CLI Commands

```bash
# Compare with next_read strategy (default)
python3 -m a4.cli compare --step 200 --kind PRE_EXEC_REG_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args "--in1 5 --in4 10" \
    --strategy next_read

# Compare with prev_write strategy
python3 -m a4.cli compare --step 200 --kind PRE_EXEC_REG_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args "--in1 5 --in4 10" \
    --strategy prev_write

# Output to JSON
python3 -m a4.cli compare --step 200 --kind PRE_EXEC_REG_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args "--in1 5 --in4 10" \
    --strategy next_read \
    --output-json results.json
```

### Verification Pipeline

The verification pipeline (`a4/verification/scripts/run_tests.py`) automatically runs both strategies for each selected step, producing separate result files:
- `pre_exec_reg_mod_next_read_step{N}.json`
- `pre_exec_reg_mod_prev_write_step{N}.json`

## Debugging Tips

### 1. Inspect Cycle Info

To understand what cycle type a transaction belongs to:

```bash
A4_INSPECT=1 ./risc0-host --in1 5 --in4 10 2>&1 | grep "cycle_idx\":12345"
```

Check the `major` field:
- major 0-6: Instruction cycle (valid for next_read)
- major 7+: Non-instruction cycle (skip for next_read)

### 2. Dump All Register Transactions

```bash
A4_INSPECT=1 A4_DUMP_REG_TXNS=1 ./risc0-host --in1 5 --in4 10 2>&1 | grep "a4_reg_txn"
```

### 3. Check Why next_read Failed

When `next_read` reports "no valid target", look for the skip reason:
- "register READ found at step X but it's during POSEIDON0" - READ exists but in wrong cycle type
- "register not read during any instruction execution after injection point" - No READ found at all

### 4. Compare Constraint Types

Arguzz:
```
<constraint_fail>{"step":100, ..., "loc":"IsRead@mem.zir:79"}</constraint_fail>
```

A4 (next_read):
```
<constraint_fail>{"step":105, ..., "loc":"IsRead@mem.zir:79"}</constraint_fail>  # Similar
```

A4 (prev_write):
```
<constraint_fail>{"step":80, ..., "loc":"MemoryWrite@mem.zir:99"}</constraint_fail>  # Different!
```

## File References

- **Implementation:** `a4/mutations/pre_exec_reg_mod.py`
- **CLI Integration:** `a4/cli.py` (`cmd_compare_pre_exec_reg_mod`)
- **Trace Parser:** `a4/common/trace_parser.py` (`A4RegTxn`)
- **Major Constants:** `workspace/risc0-modified/risc0/circuit/rv32im/src/execute/platform.rs`
- **Arguzz Implementation:** `workspace/risc0-modified/risc0/circuit/rv32im/src/execute/rv32im.rs`

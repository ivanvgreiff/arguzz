# Detailed Implementation Report: COMP_OUT_MOD Support

## Summary

Successfully implemented `COMP_OUT_MOD` mutation support with automatic WRITE transaction identification. The implementation adds a new mutation type that targets the output value of compute instructions (`ADD`, `ADDI`, etc.) by mutating the WRITE transaction's `word` field in the `PreflightTrace`.

---

## Files Modified/Created

### 1. `a4/common/trace_parser.py` (Modified)

**Changes**:
- Updated `ArguzzFault` dataclass to handle multiple fault info formats:
  - `word:X => word:Y` for `INSTR_WORD_MOD`
  - `out:X => out:Y` for `COMP_OUT_MOD`
- Added new field `info_type` to identify the fault format
- Renamed `original_word`/`mutated_word` to generic `original_value`/`mutated_value`
- Added backwards-compatible property aliases
- Added new dataclasses:
  - `A4StepTxns`: Parses `<a4_step_txns>` (transaction range for a step)
  - `A4Txn`: Parses `<a4_txn>` (individual transaction details)
    - Includes `is_write()`, `is_read()`, `is_register()`, `register_index()` methods
- Added new parser functions:
  - `parse_all_step_txns()`
  - `parse_all_txns()`

**Key Code**:
```python
@dataclass
class ArguzzFault:
    info_type: str          # "word" for INSTR_WORD_MOD, "out" for COMP_OUT_MOD
    original_value: int     # Generic: original word or output
    mutated_value: int      # Generic: mutated word or output

@dataclass
class A4Txn:
    def is_write(self) -> bool:
        return self.cycle % 2 == 1  # Odd cycle = WRITE
    
    def register_index(self) -> Optional[int]:
        USER_REGS_BASE = 1073725472  # USER_REGS_ADDR / 4
        if self.is_register():
            return self.addr - USER_REGS_BASE
        return None
```

---

### 2. `a4/mutations/base.py` (Created)

**Purpose**: Shared utilities used by all mutation types.

**Functions**:
- `run_a4_inspection()`: Run A4 with `A4_INSPECT=1`
- `run_a4_inspection_with_step()`: Run A4 with both `A4_INSPECT=1` and `A4_DUMP_STEP=N`
- `run_arguzz_mutation()`: Run Arguzz mutation with fault injection
- `run_a4_mutation()`: Run A4 mutation with config file
- `compare_failures()`: Compare Arguzz vs A4 constraint failures
- `find_a4_step_for_arguzz_step()`: Map Arguzz step to A4 user_cycle using PC matching

**Key Code**:
```python
def find_a4_step_for_arguzz_step(
    arguzz_step: int,
    arguzz_pc: int,
    a4_cycles: List[A4CycleInfo]
) -> int:
    """
    Uses PC-based matching since A4 records next PC = Arguzz PC + 4.
    For loops, picks the latest iteration <= Arguzz step.
    """
    expected_a4_pc = arguzz_pc + 4
    matches = [c for c in a4_cycles if c.pc == expected_a4_pc]
    
    if len(matches) > 1:
        valid = [c for c in matches if c.step <= arguzz_step]
        return max(valid, key=lambda c: c.step).step
    
    return matches[0].step
```

---

### 3. `a4/mutations/instr_type_mod.py` (Modified)

**Changes**:
- Removed duplicated utility functions (now imported from `base.py`)
- Re-exports shared functions for backwards compatibility
- Renamed internal references to use generic `original_value`/`mutated_value`

---

### 4. `a4/mutations/comp_out_mod.py` (Created)

**Purpose**: COMP_OUT_MOD-specific mutation logic.

**Key Components**:

1. **`CompOutModTarget` dataclass**:
```python
@dataclass
class CompOutModTarget:
    cycle_idx: int          # Index into trace.cycles[]
    step: int               # user_cycle (A4 step)
    pc: int
    major: int
    minor: int
    write_txn_idx: int      # Index of WRITE transaction
    write_addr: int
    register_idx: int       # Destination register (0-31)
    register_name: str      # e.g., "a2"
    original_value: int     # From Arguzz fault
    mutated_value: int      # From Arguzz fault
```

2. **`find_write_transaction()`**: Automatically identifies the WRITE transaction:
```python
def find_write_transaction(txns: List[A4Txn], step_txns: A4StepTxns) -> Optional[A4Txn]:
    # Filter to transactions in the step's range
    step_txn_list = [t for t in txns if t.txn_idx in range(step_txns.txn_start, step_txns.txn_end)]
    
    # Find WRITE transactions (odd cycle)
    write_txns = [t for t in step_txn_list if t.is_write()]
    
    # For compute instructions, prefer register writes
    if len(write_txns) > 1:
        reg_writes = [t for t in write_txns if t.is_register()]
        if reg_writes:
            return reg_writes[-1]
    
    return write_txns[-1] if write_txns else None
```

3. **`find_mutation_target()`**: Full algorithm:
```python
def find_mutation_target(arguzz_fault, a4_cycles, step_txns_list, txns):
    # 1. Find A4 step using PC matching (Arguzz PC + 4)
    a4_step = find_a4_step_for_arguzz_step(...)
    
    # 2. Get transaction range for this step
    step_txns = [st for st in step_txns_list if st.step == a4_step][0]
    
    # 3. Find the WRITE transaction (odd cycle, register address)
    write_txn = find_write_transaction(txns, step_txns)
    
    # 4. Return target with all info
    return CompOutModTarget(...)
```

4. **`run_full_inspection()`**: Two-phase inspection for COMP_OUT_MOD:
```python
def run_full_inspection(host_binary, host_args, arguzz_fault):
    # Phase 1: Get all cycles to find A4 step
    output1, cycles, _, _ = run_a4_inspection_with_step(host_binary, host_args, 0)
    a4_step = find_a4_step_for_arguzz_step(arguzz_fault.step, arguzz_fault.pc, cycles)
    
    # Phase 2: Get transactions for specific step
    output2, _, step_txns, txns = run_a4_inspection_with_step(host_binary, host_args, a4_step)
    
    return cycles, step_txns, txns, a4_step
```

---

### 5. `a4/injection/patches/mod_rs_patch.py` (Modified)

**Added COMP_OUT_MOD Rust mutation handler**:

```rust
(Some("COMP_OUT_MOD"), Some(target_step)) => {
    let txn_idx = extract_num("txn_idx");
    let new_word = extract_num("word");
    
    match (txn_idx, new_word) {
        (Some(idx), Some(word)) => {
            let idx = idx as usize;
            if idx < trace.txns.len() {
                let txn = &mut trace.txns[idx];
                let old_word = txn.word;
                
                // Mutate the word (value being written)
                txn.word = word;
                // Note: prev_word kept as-is (represents previous value at address)
                
                println!("<a4_comp_out_mod>{{...}}</a4_comp_out_mod>");
            }
        }
        _ => { /* error handling */ }
    }
}
```

**Config format**:
```json
{
    "mutation_type": "COMP_OUT_MOD",
    "step": 198,
    "txn_idx": 16261,
    "word": 73117827
}
```

---

### 6. `a4/cli.py` (Modified)

**Changes**:
- Added routing based on `--kind` argument
- Split comparison logic into separate functions:
  - `cmd_compare_instr_word_mod()`: For INSTR_WORD_MOD
  - `cmd_compare_comp_out_mod()`: For COMP_OUT_MOD
- Updated `--kind` to be a choice: `{INSTR_WORD_MOD, COMP_OUT_MOD}`
- Updated `cmd_find_target()` to route based on fault kind

---

## Usage Commands

### Compare INSTR_WORD_MOD (existing)
```bash
cd /root/arguzz && python3 -m a4.cli compare \
    --step 200 \
    --kind INSTR_WORD_MOD \
    --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host
```

### Compare COMP_OUT_MOD (new)
```bash
cd /root/arguzz && python3 -m a4.cli compare \
    --step 200 \
    --kind COMP_OUT_MOD \
    --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host
```

---

## Transaction Identification Algorithm

For COMP_OUT_MOD at step 198 (AddI `li a2, 3`):

```
Step 198 transactions:
┌─────────┬─────────────┬───────┬───────────┬──────────┐
│ txn_idx │ addr        │ cycle │ type      │ meaning  │
├─────────┼─────────────┼───────┼───────────┼──────────┤
│ 16258   │ 536104      │ 33554 │ READ      │ insn fetch│
│ 16259   │ 1073725472  │ 33554 │ READ      │ x0 (rs1) │
│ 16260   │ 1073725475  │ 33554 │ READ      │ x3 (rs2) │
│ 16261   │ 1073725484  │ 33555 │ WRITE ←   │ a2 (rd)  │
└─────────┴─────────────┴───────┴───────────┴──────────┘
```

**Identification logic**:
1. Filter transactions in step's range `[16258, 16262)`
2. Find WRITE transactions: `cycle % 2 == 1` → **txn 16261**
3. Verify it's a register: `addr ∈ [1073725472, 1073725504)` ✓
4. Get register index: `1073725484 - 1073725472 = 12` → **a2**

---

## Before Testing

The A4 hooks need to be re-injected after the new COMP_OUT_MOD code:

```bash
# Check current state
cd /root/arguzz && python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified --check

# Re-inject if needed
cd /root/arguzz && python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified

# Rebuild
cd /root/arguzz/workspace/risc0-modified && cargo build -p risc0-circuit-rv32im-sys
cd /root/arguzz/workspace/output && cargo build --release
```

## Correction: Build Question
`cargo build -p risc0-circuit-rv32im-sys` builds the C++ kernels (including `witgen.h` where `<constraint_fail>` is printed). You do *not* need this for A4 mutations because:
- A4 hooks are in Rust code (`mod.rs`)
- The constraint failure reporting is already in the C++ code and unchanged
- Only changes to `witgen.h` or the C++ sources require rebuilding -sys

`cargo build --release` from workspace/output is sufficient because:
- `workspace/output/Cargo.toml` has path dependencies to `risc0-modified`
- Cargo detects changes in dependent crates and rebuilds them


---
# Results

```shell
=== Step 1: Arguzz COMP_OUT_MOD at step 200 (seed 12345) ===
Fault: out:3 => out:73117827
Arguzz constraint failures: 2

=== Step 2: A4 Inspection ===
Parsed 32768 cycles
A4 step: 198 (offset from Arguzz: 2)

=== Step 3: Find Mutation Target ===
Target: cycle_idx=16777, step=198
  write_txn_idx=16261
  register: a2 (x12)
  3 => 73117827

=== Step 4: A4 COMP_OUT_MOD ===
A4 constraint failures: 2

=== Step 5: Comparison ===

============================================================
CONSTRAINT FAILURE COMPARISON
============================================================

Arguzz: 2 failures
A4:     2 failures

--- Common (2) ---
  step=198, pc=2144420, major=0, minor=7: MemoryWrite@mem.zir:100
  step=198, pc=2144420, major=0, minor=7: MemoryWrite@mem.zir:99

--- Arguzz only (0) ---

--- A4 only (0) ---
=============================================================
```
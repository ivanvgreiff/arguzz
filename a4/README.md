# A4: Post-Preflight Trace Mutation for RISC Zero

A4 is a mutation testing strategy that modifies the **PreflightTrace** (execution witness data) BEFORE witness generation, enabling precise constraint failure analysis without cascading execution effects.

## Table of Contents

1. [Overview](#overview)
2. [How A4 Works](#how-a4-works)
3. [Reproducing the Workflow](#reproducing-the-workflow)
4. [Detailed Component Explanation](#detailed-component-explanation)
5. [File Locations](#file-locations)
6. [Environment Variables](#environment-variables)

---

## Overview

### A4 vs Arguzz: Key Difference

| Aspect | Arguzz | A4 |
|--------|--------|-----|
| **When** | During execution | After preflight, before witness gen |
| **What changes** | Actual execution (values, PC, etc.) | Recorded trace metadata only |
| **Failures** | Cascading (mutation propagates) | Localized (surgical mutation) |
| **Use case** | Find what constraints catch execution errors | Find the CORE constraint for a mutation type |

### Example: `INSTR_WORD_MOD` at Step 200

```
Arguzz INSTR_WORD_MOD at step 200:
  - Mutates instruction word DURING execution
  - XorI executes instead of AddI
  - Wrong value propagates through program
  - Results: 6 constraint failures (1 core + 5 cascading)

A4 INSTR_TYPE_MOD at step 198 (equivalent):
  - Mutates cycles[].major/minor AFTER execution
  - Execution was normal (AddI ran correctly)
  - Only the recorded instruction type is wrong
  - Results: 1 constraint failure (the CORE check: VerifyOpcodeF3)
```

---

## How A4 Works

### Pipeline Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       RISC Zero Execution Pipeline                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Executor runs RISC-V program                                         │
│     └── Arguzz injects faults HERE (during execution)                   │
│                                                                          │
│  2. Preflight creates trace                                             │
│     ├── trace.cycles[] - Per-instruction metadata (PC, major, minor)    │
│     └── trace.txns[] - Memory/register transactions (addr, word)        │
│                                                                          │
│  3. ★ A4 MUTATION POINT ★                                               │
│     └── We modify trace.cycles[].major/minor HERE                       │
│                                                                          │
│  4. WitnessGenerator processes trace                                     │
│     └── stepExec() → EQZ() constraint checks                            │
│         └── VerifyOpcodeF3: decoded_word must match major/minor         │
│                                                                          │
│  5. Constraint failures reported                                         │
│     └── A4 sees failures from our mutation!                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step Counting: Arguzz vs A4

**Critical:** Arguzz `step` ≠ A4 `user_cycle` (they differ by ecall count)

| Event | Arguzz step | A4 user_cycle |
|-------|-------------|---------------|
| Regular instruction | +1 | +1 |
| Machine-mode ecall | +1 | **+0** (no increment!) |

**Solution:** We match by PC instead of step:
- Arguzz records PC **before** execution
- A4 records PC **after** execution (next PC)
- For sequential instructions: `A4_pc = Arguzz_pc + 4`

---

## Reproducing the Workflow

### Prerequisites

```bash
cd /root/arguzz/workspace/output
# Ensure binary is up-to-date
cargo build --release
```

### Quick: Full Automated Comparison

```bash
python3 /root/arguzz/a4/find_mutation_target.py compare \
  --step 200 \
  --kind INSTR_WORD_MOD \
  --seed 12345 \
  --host-binary ./target/release/risc0-host \
  --host-args '--in1 5 --in4 10' \
  --output-json /tmp/comparison_result.json
```

### Manual Step-by-Step Workflow

#### Step 1: Run Arguzz Mutation

```bash
cd /root/arguzz/workspace/output

# Run with constraint tracing
CONSTRAINT_CONTINUE=1 CONSTRAINT_TRACE_ENABLED=1 \
./target/release/risc0-host --trace --inject \
  --seed 12345 \
  --inject-step 200 \
  --inject-kind INSTR_WORD_MOD \
  --in1 5 --in4 10 2>&1 | tee /tmp/arguzz_output.txt

# Extract key info
grep "<fault>" /tmp/arguzz_output.txt
# Output: <fault>{"step":200, "pc":2144416, "kind":"INSTR_WORD_MOD", "info":"word:3147283 => word:8897555"}</fault>

grep "<constraint_fail>" /tmp/arguzz_output.txt
# Shows 6 constraint failures
```

#### Step 2: Find A4 Mutation Target

```bash
# Option A: Use Python script
python3 /root/arguzz/a4/find_mutation_target.py find-target \
  --arguzz-fault '<fault>{"step":200, "pc":2144416, "kind":"INSTR_WORD_MOD", "info":"word:3147283 => word:8897555"}</fault>' \
  --host-binary ./target/release/risc0-host \
  --host-args '--in1 5 --in4 10'

# Option B: Manual inspection
A4_INSPECT=1 ./target/release/risc0-host --in1 5 --in4 10 2>&1 \
  | grep "a4_cycle_info" | grep '"pc":2144420,'
# Output: <a4_cycle_info>{"cycle_idx":16777, "step":198, "pc":2144420, "txn_idx":16258, "major":0, "minor":7}</a4_cycle_info>
```

**Key finding:**
- Arguzz step 200 → A4 user_cycle 198 (offset of 2 due to 2 machine ecalls)
- A4 PC = 2144420 = Arguzz PC + 4 (next instruction)
- major=0, minor=7 = AddI (the original instruction)

#### Step 3: Decode Instructions

```
Original word: 3147283 (0x00300613)
  opcode=0x13, func3=0 → AddI
  Assembly: li a2, 3

Mutated word: 8897555 (0x0087c413)
  opcode=0x13, func3=4 → XorI
  Assembly: xori s0, a5, 8

AddI: InsnKind=7  → major=0, minor=7
XorI: InsnKind=8  → major=1, minor=0
```

#### Step 4: Create A4 Config and Run

```bash
# Create config file
cat > /tmp/a4_mutation.json << 'EOF'
{
  "mutation_type": "INSTR_TYPE_MOD",
  "step": 198,
  "major": 1,
  "minor": 0
}
EOF

# Run A4 mutation
A4_MUTATION_CONFIG=/tmp/a4_mutation.json \
CONSTRAINT_CONTINUE=1 CONSTRAINT_TRACE_ENABLED=1 \
./target/release/risc0-host --in1 5 --in4 10 2>&1 | tee /tmp/a4_output.txt

# Check A4 mutation was applied
grep "<a4_instr_type_mod>" /tmp/a4_output.txt
# Output: <a4_instr_type_mod>{"step":198, "cycle_idx":16777, "pc":2144420, "old_major":0, "old_minor":7, "new_major":1, "new_minor":0}</a4_instr_type_mod>

# Check constraint failures
grep "<constraint_fail>" /tmp/a4_output.txt
# Shows 1 constraint failure (VerifyOpcodeF3)
```

#### Step 5: Compare Results

```bash
echo "=== Arguzz Constraint Failures (6 total) ==="
grep "<constraint_fail>" /tmp/arguzz_output.txt

echo ""
echo "=== A4 Constraint Failures (1 total) ==="
grep "<constraint_fail>" /tmp/a4_output.txt
```

**Expected output:**

```
=== Arguzz Constraint Failures (6 total) ===
<constraint_fail>{"cycle":17359, "step":198, "pc":2144420, "major":1, "minor":0, "loc":"VerifyOpcodeF3...", "value":2013265917}</constraint_fail>
<constraint_fail>{"cycle":17359, "step":198, "pc":2144420, "major":1, "minor":0, "loc":"MemoryWrite...", "value":2013265916}</constraint_fail>
<constraint_fail>{"cycle":18362, "step":1136, "pc":2144572, "major":6, "minor":2, "loc":"OpSW...", "value":1}</constraint_fail>
<constraint_fail>{"cycle":18362, "step":1136, "pc":2144572, "major":6, "minor":2, "loc":"OpSW...", "value":1}</constraint_fail>
<constraint_fail>{"cycle":18383, "step":1157, "pc":2136648, "major":5, "minor":2, "loc":"OpLW...", "value":1}</constraint_fail>
<constraint_fail>{"cycle":18383, "step":1157, "pc":2136648, "major":5, "minor":2, "loc":"OpLW...", "value":1}</constraint_fail>

=== A4 Constraint Failures (1 total) ===
<constraint_fail>{"cycle":16777, "step":198, "pc":2144420, "major":1, "minor":0, "loc":"VerifyOpcodeF3...", "value":2013265917}</constraint_fail>
```

**Analysis:**
- **Common failure:** `VerifyOpcodeF3` - This is the CORE constraint that verifies instruction type
- **Arguzz-only failures:** MemoryWrite (step 198), OpSW (step 1136), OpLW (step 1157) - These are CASCADING effects

---

## Detailed Component Explanation

### 1. Python Script: `find_mutation_target.py`

**Location:** `/root/arguzz/a4/find_mutation_target.py`

**Key Functions:**

| Function | Purpose |
|----------|---------|
| `get_insn_kind(word)` | Decode RISC-V word → InsnKind (0-57) |
| `kind_to_major_minor(kind)` | Convert InsnKind → (major, minor) |
| `ArguzzFault.parse(line)` | Parse `<fault>` JSON from Arguzz |
| `A4CycleInfo.parse(line)` | Parse `<a4_cycle_info>` from A4 |
| `find_mutation_target(fault, cycles)` | Match Arguzz fault to A4 cycle by PC |
| `run_arguzz_mutation(...)` | Execute Arguzz and capture results |
| `run_a4_mutation(...)` | Execute A4 and capture results |
| `compare_mutations(...)` | Compare constraint failures |

**Subcommands:**

```bash
# Find A4 target for a given Arguzz fault
python3 find_mutation_target.py find-target --arguzz-fault '...'

# Run full comparison pipeline
python3 find_mutation_target.py compare --step N --kind KIND --seed S
```

### 2. Rust Hook: `mod.rs`

**Location:** `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`

**Key sections:**

```rust
// Lines 77-127: A4_INSPECT - Dumps cycle and transaction info
if std::env::var("A4_INSPECT").is_ok() {
    // Prints <a4_cycle_info> for each cycle
    // Prints <a4_step_txns> and <a4_txn> for A4_DUMP_STEP
}

// Lines 148-266: A4_MUTATION_CONFIG - Applies mutations
if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
    // Reads JSON config
    // For "INSTR_TYPE_MOD": mutates trace.cycles[].major/minor
    // For "INSTR_WORD_MOD": mutates trace.txns[].word
}
```

### 3. How PC Matching Works

The Python script finds the correct A4 cycle without counting ecalls:

```python
def find_mutation_target(arguzz_fault, a4_cycles):
    # 1. Calculate expected A4 PC (next PC after instruction)
    expected_a4_pc = arguzz_fault.pc + 4  # For sequential instructions
    
    # 2. Calculate expected major/minor from original word
    original_kind = get_insn_kind(arguzz_fault.original_word)
    expected_major, expected_minor = kind_to_major_minor(original_kind)
    
    # 3. Search for matching cycle
    for cycle in a4_cycles:
        if cycle.pc == expected_a4_pc and \
           cycle.major == expected_major and \
           cycle.minor == expected_minor:
            # Found! If multiple (loops), pick highest user_cycle <= arguzz_step
            ...
```

### 4. InsnKind to Major/Minor Mapping

From `rv32im.rs`:

```rust
pub enum InsnKind {
    Add = 0,   // major=0, minor=0
    Sub = 1,   // major=0, minor=1
    ...
    AddI = 7,  // major=0, minor=7
    XorI = 8,  // major=1, minor=0
    ...
    Lw = 42,   // major=5, minor=2
    ...
    Sw = 50,   // major=6, minor=2
}
```

Formula: `major = kind / 8`, `minor = kind % 8`

---

## File Locations

### A4 Components

| File | Purpose |
|------|---------|
| `/root/arguzz/a4/find_mutation_target.py` | Main automation script |
| `/root/arguzz/a4/README.md` | This documentation |

### Rust Modifications

| File | Purpose |
|------|---------|
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | A4 hooks (inspection + mutation) |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/execute/rv32im.rs` | Arguzz fault injection |

### Temporary Files (created during runs)

| File | Purpose |
|------|---------|
| `/tmp/arguzz_output.txt` | Arguzz execution output |
| `/tmp/a4_output.txt` | A4 execution output |
| `/tmp/a4_mutation.json` | A4 config file |
| `/tmp/comparison_result.json` | Full comparison results |

---

## Environment Variables

### A4 Inspection

| Variable | Example | Purpose |
|----------|---------|---------|
| `A4_INSPECT=1` | `A4_INSPECT=1` | Enable trace inspection output |
| `A4_DUMP_STEP=N` | `A4_DUMP_STEP=200` | Dump transactions for step N |
| `A4_DUMP_TXN=N` | `A4_DUMP_TXN=16258` | Dump specific transaction |

### A4 Mutation

| Variable | Example | Purpose |
|----------|---------|---------|
| `A4_MUTATION_CONFIG=/path` | `A4_MUTATION_CONFIG=/tmp/a4.json` | Path to mutation config |

### Constraint Tracing

| Variable | Purpose |
|----------|---------|
| `CONSTRAINT_CONTINUE=1` | Don't abort on first constraint failure |
| `CONSTRAINT_TRACE_ENABLED=1` | Print constraint failure details |

---

## Config File Format

### INSTR_TYPE_MOD (for INSTR_WORD_MOD mutations)

```json
{
  "mutation_type": "INSTR_TYPE_MOD",
  "step": 198,
  "major": 1,
  "minor": 0
}
```

- `step`: A4 user_cycle (NOT Arguzz step!)
- `major`: New instruction major (kind / 8)
- `minor`: New instruction minor (kind % 8)

### INSTR_WORD_MOD (for direct word mutation)

```json
{
  "mutation_type": "INSTR_WORD_MOD",
  "step": 198,
  "word": 8897555
}
```

---

## Summary

A4 enables **surgical constraint failure analysis** by mutating the recorded trace metadata without affecting execution. This isolates the **core constraint** that would catch a forged mutation, separate from cascading execution effects.

Key insight: For `INSTR_WORD_MOD`, the core constraint is `VerifyOpcodeF3` which checks that the decoded instruction word matches the recorded `major/minor` instruction type.

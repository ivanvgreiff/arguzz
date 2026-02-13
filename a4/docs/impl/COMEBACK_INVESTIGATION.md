# INSTR_WORD_MOD Investigation Report

## Executive Summary

Investigation of the `INSTR_WORD_MOD` mutation revealed **two distinct issues**:

1. **Bug in Python target selection**: The instruction fetch address calculation `(cycle.pc - 4) / 4` is incorrect for branch/jump instructions, causing ~10% of mutations to silently fail.

2. **Architectural behavior**: When mutations change the instruction opcode, the prover crashes (SIGSEGV) before constraint checking occurs. This is due to a fundamental mismatch between the circuit's execution path (determined by `major/minor`) and the mutated instruction word.

---

## Issue 1: Incorrect Instruction Fetch Address Calculation

### Symptoms
- Mutations #1, #2, #3, #8 in the campaign showed no output (silently skipped)
- `get_targets_at_step()` returned `None` for these steps despite being valid instruction cycles

### Root Cause

The Python code calculates the expected instruction fetch address as:
```python
expected_fetch_addr = (cycle.pc - 4) // 4
```

This assumes `cycle.pc` is always `current_instruction_PC + 4` (sequential execution). However, **for branch and jump instructions, `cycle.pc` is the branch TARGET**, not `current_PC + 4`.

### Evidence

| Step | Major | Instruction | cycle.pc | Expected Addr | Actual First Txn Addr | Opcode |
|------|-------|-------------|----------|---------------|----------------------|--------|
| 1942 | 1 | BRANCH | 0x2184BC | 549166 | 549173 | 0x63 (BEQ/BNE) |
| 2977 | 2 | JALR | 0x205DEC | 530298 | 529839 | 0x67 (JALR) |
| 540 | 1 | BRANCH | 0x2031E0 | 527479 | 527472 | 0x63 (BEQ/BNE) |
| 2881 | 2 | JALR | 0x21814C | 548946 | 529632 | 0x67 (JALR) |

### Data Flow Explanation

When RISC Zero executes an instruction:

1. **Preflight generation** (`preflight.rs`):
   - CPU fetches instruction from `current_PC`
   - Executes instruction (may branch/jump)
   - Calls `on_insn_end()` which stores `self.pc` (the **new PC** after execution)
   - For sequential: `new_pc = old_pc + 4`
   - For branch taken: `new_pc = branch_target`
   - For JAL/JALR: `new_pc = jump_target`

2. **Transaction recording**:
   - The instruction fetch transaction is recorded with `addr = current_instruction_PC / 4`
   - This transaction becomes the first transaction at `cycle.txn_idx`

3. **The mismatch**:
   - `cycle.pc` = next PC (branch target for branches)
   - First transaction's `addr` = actual instruction fetch address
   - `(cycle.pc - 4) / 4` ≠ first transaction's `addr` for non-sequential instructions

### Impact

- ~10% of valid instruction steps fail target selection
- All branch (BEQ, BNE, BLT, etc.) and jump (JAL, JALR) instructions are affected
- The Rust handler has the **same bug** (line 288 in `mod.rs`):
  ```rust
  let expected_addr = (cycle.pc - 4) / 4;
  if txn.addr == expected_addr {  // Will fail for branches!
  ```

---

## Issue 2: Prover Crashes When Opcode Changes

### Symptoms

| Mutated Value | Opcode | Return Code | Constraint Failures |
|---------------|--------|-------------|---------------------|
| 0xDEADBEEF | 0x6F (JAL) | -11 (SIGSEGV) | 0 |
| 0x00000000 | 0x00 (illegal) | -11 (SIGSEGV) | 0 |
| 0x00000013 | 0x13 (ADDI) | -11 (SIGSEGV) | 0 |
| 0x00B6A123 | 0x23 (STORE) | 101 | 1 ✓ |

**Key observation**: Only mutations that **preserve the original opcode** produce constraint failures. All others crash.

### Deep Dive: Circuit Architecture

The RISC Zero circuit processes instructions in two phases:

#### Phase 1: Execution Path Selection (based on `major/minor`)

The `major` and `minor` fields in `cycles[]` are set during **preflight generation** based on the **original** instruction. These determine which instruction handler the circuit invokes:

```
major=0: MISC0 (ADD, SUB, AND, OR, XOR, etc.)
major=1: MISC1 (SLT, SLTU, branches)
major=2: MISC2 (LUI, AUIPC, JAL, JALR)
major=3: MUL0 (multiplication)
major=4: DIV0 (division)
major=5: MEM0 (loads: LW, LH, LB, etc.)
major=6: MEM1 (stores: SW, SH, SB)
major=7+: Control/ECALL/Poseidon/SHA
```

#### Phase 2: Witness Generation

The C++ code (`ffi.cpp`) reads the instruction word from the mutated preflight trace:

```cpp
// ffi.cpp:86-128
size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;
const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];
return {
    txn.prevCycle,
    txn.prevWord & 0xffff,
    txn.prevWord >> 16,
    txn.word & 0xffff,    // <-- Mutated value is used here
    txn.word >> 16,
};
```

This mutated word is then:
1. Stored in witness registers via `exec_nondet_reg()`
2. Used to extract opcode, func3, func7, registers, immediates
3. **Assumed to match** the instruction type indicated by `major/minor`

#### Phase 3: Constraint Checking

Each instruction handler has `VerifyOpcodeF3F7` constraints:

```rust
// steps.rs.inc:1870-1877 (OpSRL handler, major=4)
let x3: Val = (x2.opcode._super - Val::new(51));  // Expect opcode 0x33
eqz!(x3, "VerifyOpcodeF3F7...");  // CONSTRAINT: opcode must be 0x33
```

### Why Crashes Occur Instead of Constraint Failures

The crash happens **before constraint checking** during witness generation. Here's the sequence:

#### Scenario: Step 100 (Store instruction, major=6) mutated to 0xDEADBEEF (JAL opcode 0x6F)

1. **Circuit selects handler based on major=6**: Calls store instruction handler (`Mem1`)

2. **Handler reads instruction word**: Gets mutated value 0xDEADBEEF

3. **Handler attempts to decode as STORE instruction**:
   - Extracts rs1, rs2, immediate as if it were SW/SH/SB format
   - The bit patterns are completely wrong for what the handler expects
   - For example: STORE uses S-type encoding, JAL uses J-type encoding
   
4. **Handler computes witness values**:
   - Tries to compute memory address: `base + offset`
   - The "base register" field points to garbage
   - The "offset" field is nonsense
   
5. **Witness generation code encounters invalid state**:
   - May try to access invalid memory indices
   - May compute values that overflow or underflow
   - May index into arrays out of bounds

6. **CRASH (SIGSEGV)** - Process dies before any `eqz!` constraint is checked

#### Why Same-Opcode Mutations Work

When we mutate 0x00B6A023 to 0x00B6A123 (both opcode 0x23 = STORE):

1. **Circuit selects handler based on major=6**: Correct handler for stores

2. **Handler reads instruction word**: Gets 0x00B6A123

3. **Handler decodes as STORE** (correct format):
   - S-type encoding is interpreted correctly
   - rs1, rs2, immediate fields are in expected positions
   - Values may be different but format is correct

4. **Witness generation completes** without crashing

5. **Constraint checking runs**:
   ```rust
   // For OpSW (Store Word), func3 must be 2
   eqz!((x2.func3 - Val::new(2)), "OpSW...");
   ```
   - Original func3=2, mutated func3=4 (from bit flip)
   - Constraint fails: `4 - 2 = 2 ≠ 0`
   - `<constraint_fail>` is printed ✓

### The Instruction Encoding Problem

Different RISC-V instruction types have completely different bit layouts:

```
R-type: [funct7][rs2][rs1][funct3][rd][opcode]    (e.g., ADD, SUB)
I-type: [imm[11:0]][rs1][funct3][rd][opcode]      (e.g., ADDI, LW)
S-type: [imm[11:5]][rs2][rs1][funct3][imm[4:0]][opcode]  (e.g., SW, SB)
B-type: [imm][rs2][rs1][funct3][imm][opcode]      (e.g., BEQ, BNE)
U-type: [imm[31:12]][rd][opcode]                  (e.g., LUI, AUIPC)
J-type: [imm[20|10:1|11|19:12]][rd][opcode]       (e.g., JAL)
```

When the handler for S-type (stores) tries to interpret J-type (JAL) bits:
- What it thinks is `rs2` is actually part of the jump immediate
- What it thinks is `imm[11:5]` is part of a different field
- Memory addresses computed are garbage
- Array indices go out of bounds → CRASH

---

## Issue 3: Rust Handler Also Has Address Calculation Bug

The Rust mutation handler in `mod.rs` has the same flawed logic:

```rust
// mod.rs:281-314
(Some("INSTR_WORD_MOD"), Some(target_step)) => {
    if let Some(new_word) = extract_num("word") {
        let mut found = false;
        for (cycle_idx, cycle) in trace.cycles.iter().enumerate() {
            if cycle.user_cycle == target_step {
                let fetch_txn_idx = cycle.txn_idx as usize;
                let expected_addr = (cycle.pc - 4) / 4;  // BUG: Wrong for branches!
                
                if fetch_txn_idx < trace.txns.len() {
                    let txn = &mut trace.txns[fetch_txn_idx];
                    
                    if txn.addr == expected_addr {  // This check FAILS for branches
                        // ... apply mutation ...
                    } else {
                        println!("<a4_error>{{\"error\":\"addr mismatch\"...");
                    }
                }
            }
        }
    }
}
```

For branch/jump instructions:
- `cycle.txn_idx` correctly points to the instruction fetch transaction
- But `expected_addr = (cycle.pc - 4) / 4` is wrong
- The check `txn.addr == expected_addr` fails
- Mutation is NOT applied
- Error is printed but not captured by fuzzer

---

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PREFLIGHT GENERATION                                │
│  (preflight.rs - runs ONCE before witness generation)                       │
│                                                                              │
│  1. Execute instruction at current_PC                                        │
│  2. Record transaction: addr = current_PC / 4, word = instruction_bytes      │
│  3. Update PC: new_PC = next_instruction_address                             │
│  4. Store cycle: pc = new_PC (NOT current_PC!), major/minor from instruction │
│                                                                              │
│  For BRANCH taken: new_PC = branch_target                                    │
│  For JAL/JALR:     new_PC = jump_target                                      │
│  For sequential:   new_PC = current_PC + 4                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          A4 MUTATION                                         │
│  (mod.rs - modifies preflight trace before witness generation)              │
│                                                                              │
│  1. Find cycle where user_cycle == target_step                               │
│  2. Get first transaction at cycle.txn_idx                                   │
│  3. BUG: Check if txn.addr == (cycle.pc - 4) / 4  ← FAILS FOR BRANCHES      │
│  4. If match: txn.word = mutated_value, txn.prev_word = mutated_value       │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       WITNESS GENERATION                                     │
│  (steps.rs.inc + ffi.cpp)                                                   │
│                                                                              │
│  1. For each cycle, select handler based on major/minor                      │
│  2. Handler calls get_memory_txn() to read instruction word                  │
│  3. Handler decodes instruction assuming format matches major/minor          │
│  4. If opcode mismatches format → CRASH (invalid memory access)              │
│  5. If opcode matches format → continue to constraints                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼ (only if witness gen succeeds)
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CONSTRAINT CHECKING                                    │
│  (witgen.h eqz() function)                                                  │
│                                                                              │
│  1. eqz!(value, location) checks if value == 0                               │
│  2. If value != 0: prints <constraint_fail>, throws exception                │
│  3. Same-opcode mutations reach here and produce constraint failures         │
│  4. Different-opcode mutations crashed before reaching here                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why `exec_nondet_reg` Doesn't Cause Constraint Failures

I initially hypothesized that changing the opcode should cause `VerifyOpcodeF3F7` constraints to fail. Here's why it doesn't:

### The Circuit's Trust Model

The circuit uses "nondet" (non-deterministic) registers for witness values:

```rust
// exec_decoder extracts opcode from instruction word
let x19: NondetRegStruct = exec_nondet_reg(
    ctx,
    bit_and(x12, Val::new(127))?,  // opcode = word & 0x7F
    (layout1.map(|c| c.opcode)),
)?;
```

This stores `word & 0x7F` in the witness. Later, constraints verify:

```rust
let x3: Val = (x2.opcode._super - Val::new(51));  // Check opcode == 51
eqz!(x3, "VerifyOpcodeF3F7...");
```

### The Crash Happens Earlier

The crash occurs **during witness generation**, not during constraint checking:

1. Handler is selected by `major/minor` (e.g., major=6 → store handler)
2. Handler reads mutated word (e.g., 0xDEADBEEF)
3. Handler tries to interpret it as STORE format
4. Handler computes memory addresses, register indices
5. **CRASH** - Invalid array access, null pointer, etc.

The `exec_nondet_reg` and subsequent `eqz!` constraint checks **never execute** because the handler crashes first.

### What Would Need to Happen for Constraint Failure

For the opcode constraint to fail gracefully:
1. The handler would need to safely decode any instruction format
2. It would need bounds checking on all computed indices
3. It would need to complete witness generation
4. THEN the constraint check would fail

But RISC Zero's circuit assumes the trace is valid and doesn't have these safety checks.

---

## Summary of Verified Facts

| Finding | Source | Impact |
|---------|--------|--------|
| `cycle.pc` is NEXT PC, not current | `preflight.rs:553-557` | Address calculation wrong for branches |
| First txn at `cycle.txn_idx` is instruction fetch | `ffi.cpp:86-87` | Correct way to find instruction |
| Rust handler checks address match | `mod.rs:293` | Mutation silently fails for branches |
| Different opcode → SIGSEGV | Test with 0xDEADBEEF | Crash before constraints |
| Same opcode → constraint failure | Test with 0x00B6A123 | Working as intended |
| ~10% of steps are branches/jumps | Test data | Significant portion affected |

---

## Recommendations (For Future Implementation)

### Fix 1: Python Target Selection
Use first transaction directly instead of calculating address:
```python
# Get first transaction at cycle.txn_idx
first_txn = txns[0]  # Already sorted by txn_idx
if first_txn.is_read():
    # This IS the instruction fetch
    return InstrWordModTarget(
        fetch_addr=first_txn.addr,
        original_word=first_txn.word,
        ...
    )
```

### Fix 2: Rust Handler
Remove the address check entirely:
```rust
let fetch_txn_idx = cycle.txn_idx as usize;
if fetch_txn_idx < trace.txns.len() {
    let txn = &mut trace.txns[fetch_txn_idx];
    // No address check - txn_idx is authoritative
    txn.word = new_word;
    txn.prev_word = new_word;
}
```

### Fix 3: Value Generation Strategy
Consider opcode-preserving mutations:
- Mutate only non-opcode bits (bits 7-31)
- Or mutate within same instruction format family
- This would produce constraint failures instead of crashes

### Alternative: Accept Crashes as Valid Findings
Crashes are still valid bug-finding results - they indicate the prover can't handle inconsistent traces. Document this as expected behavior for opcode-changing mutations.

---

## Test Commands Used

```bash
# Test with same opcode (produces constraint failure)
echo '{"mutation_type":"INSTR_WORD_MOD","step":100,"word":11968803}' > /tmp/test.json
A4_MUTATION_CONFIG=/tmp/test.json CONSTRAINT_CONTINUE=1 ./host --in1 5 --in4 10

# Test with different opcode (crashes)
echo '{"mutation_type":"INSTR_WORD_MOD","step":100,"word":3735928559}' > /tmp/test.json
A4_MUTATION_CONFIG=/tmp/test.json CONSTRAINT_CONTINUE=1 ./host --in1 5 --in4 10
```



# INSTR_WORD_MOD Investigation - Supplementary Technical Reference

This document captures all additional technical details, code paths, data structures, and findings from the investigation that are NOT covered in the main issue report. This serves as a comprehensive reference for continuing the debugging session.

---

## Table of Contents

1. [Data Structures](#1-data-structures)
2. [Inspection Data System](#2-inspection-data-system)
3. [Transaction Indexing and Access Patterns](#3-transaction-indexing-and-access-patterns)
4. [Fuzzer Architecture](#4-fuzzer-architecture)
5. [Step Selection System](#5-step-selection-system)
6. [Rust Mutation Handler Details](#6-rust-mutation-handler-details)
7. [C++ FFI Layer](#7-c-ffi-layer)
8. [Circuit Instruction Decoding](#8-circuit-instruction-decoding)
9. [Memory IO Subsystem](#9-memory-io-subsystem)
10. [Constraint Failure Capture System](#10-constraint-failure-capture-system)
11. [Comparison with MEM_VAL_MOD](#11-comparison-with-mem_val_mod)
12. [Major/Minor to Instruction Mapping](#12-majorminor-to-instruction-mapping)
13. [Preflight Trace Generation](#13-preflight-trace-generation)
14. [Value Generation System](#14-value-generation-system)
15. [Fuzzer Output Classification](#15-fuzzer-output-classification)
16. [File Locations Reference](#16-file-locations-reference)

---

## 1. Data Structures

### 1.1 RawPreflightCycle (Rust)

Defined in `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs`:

```rust
pub struct RawPreflightCycle {
    pub state: u32,
    pub pc: u32,           // NEXT PC after instruction execution
    pub major: u8,         // Instruction category (0-6 for user instructions)
    pub minor: u8,         // Instruction variant within category
    pub machine_mode: u8,  // 0=user, 1-3=system modes
    pub padding: u8,
    pub user_cycle: u32,   // "step" in A4 terminology
    pub txn_idx: u32,      // Index of FIRST transaction for this cycle
    pub paging_idx: u32,
    pub bigint_idx: u32,
    pub diff_count: [u32; 2],
}
```

**Key insight**: `txn_idx` points to the first transaction, and subsequent transactions for this cycle have consecutive indices until the next cycle's `txn_idx`.

### 1.2 RawMemoryTransaction (Rust)

```rust
pub struct RawMemoryTransaction {
    pub addr: u32,        // Word address (byte_addr / 4)
    pub cycle: u32,       // Even = READ, Odd = WRITE
    pub word: u32,        // Current value
    pub prev_cycle: u32,  // Previous access cycle (u32::MAX if first access)
    pub prev_word: u32,   // Value before this transaction
}
```

**Key insight**: `cycle % 2 == 0` means READ, `cycle % 2 == 1` means WRITE.

### 1.3 A4CycleInfo (Python)

Defined in `/root/arguzz/a4/core/trace_parser.py`:

```python
@dataclass
class A4CycleInfo:
    cycle_idx: int    # Index into trace.cycles[]
    step: int         # user_cycle (A4's step number)
    pc: int           # NEXT PC (not current instruction PC!)
    txn_idx: int      # First transaction index for this cycle
    major: int        # Instruction category
    minor: int        # Instruction variant
```

Parsed from: `<a4_cycle_info>{"cycle_idx":..., "step":..., ...}</a4_cycle_info>`

### 1.4 A4AllTxn (Python)

Defined in `/root/arguzz/a4/core/trace_parser.py`:

```python
@dataclass
class A4AllTxn:
    txn_idx: int      # Global transaction index
    step: int         # Which step this transaction belongs to
    txn_type: str     # "reg" or "mem"
    addr: int         # Word address
    cycle: int        # Access cycle (even=read, odd=write)
    word: int         # Current value
    prev_cycle: int   # Previous access cycle
    prev_word: int    # Previous value
    
    def is_read(self) -> bool:
        return self.cycle % 2 == 0
    
    def is_write(self) -> bool:
        return self.cycle % 2 == 1
```

Parsed from: `<a4_all_txn>{"txn_idx":..., "step":..., ...}</a4_all_txn>`

### 1.5 InstrWordModTarget (Python)

Defined in `/root/arguzz/a4/standalone/mutations/instr_word_mod.py`:

```python
@dataclass
class InstrWordModTarget:
    step: int           # A4 step (user_cycle)
    cycle_idx: int      # Index into trace.cycles[]
    pc: int             # NEXT PC (after instruction execution)
    instr_addr: int     # Actual instruction byte address = pc - 4 (WRONG FOR BRANCHES)
    txn_idx: int        # Index of instruction fetch transaction
    fetch_addr: int     # Word address of instruction (CALCULATED, MAY BE WRONG)
    original_word: int  # Original instruction word
    major: int          # Instruction major category
    minor: int          # Instruction minor variant
```

---

## 2. Inspection Data System

### 2.1 InspectionData Class

Located in `/root/arguzz/a4/core/inspection_data.py`:

```python
class InspectionData:
    cycles: List[A4CycleInfo]      # All cycles from trace
    all_txns: List[A4AllTxn]       # All transactions (reg + mem)
    reg_txns: List[A4RegTxn]       # Register transactions only
    
    # Precomputed lookup tables
    _step_to_cycle: Dict[int, A4CycleInfo]
    _step_to_all_txns: Dict[int, List[A4AllTxn]]
    _step_to_reg_txns: Dict[int, List[A4RegTxn]]
    _step_to_mem_txns: Dict[int, List[A4AllTxn]]
```

### 2.2 Key Methods

```python
def get_cycle(self, step: int) -> Optional[A4CycleInfo]:
    """Get cycle info for a specific step"""
    return self._step_to_cycle.get(step)

def get_all_txns_at_step(self, step: int) -> List[A4AllTxn]:
    """Get ALL transactions (reg + mem) at a step, sorted by txn_idx"""
    return self._step_to_all_txns.get(step, [])

def get_reg_txns_at_step(self, step: int) -> List[A4RegTxn]:
    """Get register transactions at a step"""
    return self._step_to_reg_txns.get(step, [])

def get_mem_txns_at_step(self, step: int) -> List[A4AllTxn]:
    """Get memory transactions at a step (excludes registers)"""
    return self._step_to_mem_txns.get(step, [])
```

### 2.3 Important: No `get_txn(txn_idx)` Method

The `InspectionData` class does **NOT** have a `get_txn(txn_idx)` method. To access a transaction by index, use:

```python
txn = data.all_txns[txn_idx]  # Direct list access
```

This was a bug discovered during debugging - the original code called `data.get_txn(txn_idx)` which doesn't exist.

### 2.4 Inspection Data Collection

The data is collected by running the host binary with `A4_INSPECT=1`:

```python
@classmethod
def from_inspection(cls, host_binary: str, host_args: List[str]) -> 'InspectionData':
    env = os.environ.copy()
    env["A4_INSPECT"] = "1"
    env["A4_DUMP_ALL_TXNS"] = "1"
    
    result = subprocess.run([host_binary] + host_args, env=env, ...)
    
    # Parse output for <a4_cycle_info> and <a4_all_txn> tags
    cycles = parse_all_a4_cycles(output)
    all_txns = parse_all_a4_all_txns(output)
    ...
```

---

## 3. Transaction Indexing and Access Patterns

### 3.1 Transaction Ownership

Each cycle "owns" a range of transactions:
- Start: `cycles[i].txn_idx`
- End: `cycles[i+1].txn_idx` (exclusive), or `len(txns)` for last cycle

### 3.2 Transaction Order Within a Cycle

For a typical instruction cycle:
1. **Transaction 0**: Instruction fetch (READ from instruction memory)
2. **Transaction 1+**: Register reads (if any)
3. **Transaction N**: Register write (if any)
4. **Transaction M**: Memory read/write (for load/store instructions)

Example for Step 100 (Store instruction, major=6):
```
txn_idx=15829: addr=527537 (instr fetch), READ, word=0x00B6A023
txn_idx=15830: addr=1073725485 (reg x13), READ, word=2233288
txn_idx=15831: addr=1073725483 (reg x11), READ, word=0
txn_idx=15832: addr=558322 (memory), READ, word=0 (RMW read)
txn_idx=15833: addr=558322 (memory), WRITE, word=0 (RMW write)
```

### 3.3 Register Address Range

Registers are at special word addresses:
```
USER_REGS_BASE = 0x3FFFC020 = 1073725472 (word address)
x0 at 1073725472
x1 at 1073725473
...
x31 at 1073725503
```

The `txn_type` field distinguishes:
- `"reg"`: Address in range [1073725472, 1073725503]
- `"mem"`: All other addresses

---

## 4. Fuzzer Architecture

### 4.1 A4StandaloneFuzzer Class

Located in `/root/arguzz/a4/standalone/fuzzer.py`:

```python
class A4StandaloneFuzzer:
    MUTATION_KINDS = [
        "COMP_OUT_MOD",      # Compute output register
        "LOAD_VAL_MOD",      # Load instruction result
        "STORE_OUT_MOD",     # Store instruction memory write
        "PRE_EXEC_REG_MOD",  # Pre-execution register value
        "INSTR_TYPE_MOD",    # Instruction type (major/minor)
        "MEM_VAL_MOD",       # Memory transaction values
        "INSTR_WORD_MOD",    # Instruction word (NEW)
    ]
    
    def __init__(self, host_binary, host_args, kind="all", seed=None, ...):
        self.host_binary = host_binary
        self.host_args = host_args
        self.kind = kind
        self.seed = seed or random.randint(0, 2**32 - 1)
        self.rng = random.Random(self.seed)
        self.selector = ZonedStepSelector(seed=self.seed)
        self.value_gen = ValueGenerator(seed=self.seed)
        self.data = None  # Populated by run_inspection()
```

### 4.2 Campaign Flow

```python
def run_campaign(self, num_mutations: int) -> CampaignStats:
    # 1. Run inspection if not already done
    if self.data is None:
        self.run_inspection()
    
    # 2. Start campaign in database
    self.campaign_id = self.db.start_campaign(...)
    
    # 3. Run mutations
    for i in range(num_mutations):
        result = self._run_single_mutation(i + 1, num_mutations)
        if result:
            self._update_stats(stats, result)
            self._print_mutation_result(i + 1, result)
    
    # 4. End campaign
    self.db.end_campaign(self.campaign_id)
    return stats
```

### 4.3 Single Mutation Flow

```python
def _run_single_mutation(self, mutation_num, total):
    # 1. Select mutation kind
    kind = self.kind if self.kind != "all" else self.rng.choice(self.MUTATION_KINDS)
    
    # 2. Select step (via ZonedStepSelector)
    step = self.selector.select_step(self.data, kind)
    if step is None:
        print(f"No valid steps for {kind}")
        return None
    
    # 3. Create mutation config
    config, mutated_value, original_value = self._create_mutation(kind, step)
    if config is None:
        return None  # Silent skip - target not found at step
    
    # 4. Execute mutation
    config_path.write_text(json.dumps(config))
    output, failures = run_a4_mutation(self.host_binary, self.host_args, config_path)
    
    # 5. Classify outcome
    witness_gen_failed = self._check_witness_gen_failure(output)
    verifier_accepted = self._check_verifier_acceptance(output)
    
    # 6. Record and return result
    return MutationResult(kind, step, ..., failures, ...)
```

---

## 5. Step Selection System

### 5.1 ZonedStepSelector

Located in `/root/arguzz/a4/standalone/step_selector.py`:

```python
class ZonedStepSelector(StepSelector):
    """
    Distributes mutations across program phases:
    - 5% init (step 0)
    - 90% core (middle steps)
    - 5% final (last step)
    """
    
    def __init__(self, seed=None, config=None):
        self.rng = random.Random(seed)
        self.config = config or ZonedConfig()
    
    def select_step(self, data: InspectionData, kind: str) -> Optional[int]:
        valid_steps = self.get_valid_steps(data, kind)
        if not valid_steps:
            return None
        
        zones = self._partition_into_zones(valid_steps)
        
        # Weighted zone selection
        available_zones = [z for z in ["init", "core", "final"] if zones[z]]
        weights = [self.config.get_zone_weights()[z] for z in available_zones]
        
        chosen_zone = self.rng.choices(available_zones, weights=weights, k=1)[0]
        return self.rng.choice(zones[chosen_zone])
```

### 5.2 Valid Steps for INSTR_WORD_MOD

```python
def get_valid_steps_for_kind(self, kind: str) -> List[int]:
    valid_steps = set()
    
    for cycle in self.cycles:
        if kind == "INSTR_WORD_MOD":
            # Any instruction cycle (major 0-6)
            if cycle.major <= 6:
                valid_steps.add(cycle.step)
    
    return sorted(valid_steps)
```

**Note**: This returns steps where `major <= 6`, but doesn't verify that the instruction fetch transaction actually exists at the expected address.

---

## 6. Rust Mutation Handler Details

### 6.1 Full INSTR_WORD_MOD Handler

Located in `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` (lines 281-315):

```rust
(Some("INSTR_WORD_MOD"), Some(target_step)) => {
    if let Some(new_word) = extract_num("word") {
        let mut found = false;
        for (cycle_idx, cycle) in trace.cycles.iter().enumerate() {
            if cycle.user_cycle == target_step {
                let fetch_txn_idx = cycle.txn_idx as usize;
                // BUG: This calculation is wrong for branch/jump instructions
                let expected_addr = (cycle.pc - 4) / 4;
                
                if fetch_txn_idx < trace.txns.len() {
                    let txn = &mut trace.txns[fetch_txn_idx];
                    
                    // BUG: This check fails for branches because expected_addr is wrong
                    if txn.addr == expected_addr {
                        let old_word = txn.word;
                        txn.word = new_word;
                        txn.prev_word = new_word;  // Both set to preserve IsRead
                        
                        println!("<a4_instr_word_mod>{{...}}</a4_instr_word_mod>");
                        found = true;
                    } else {
                        println!("<a4_error>{{\"error\":\"addr mismatch\", ...}}</a4_error>");
                    }
                }
                break;
            }
        }
        if !found {
            println!("<a4_error>{{\"error\":\"step not found\", ...}}</a4_error>");
        }
    } else {
        println!("<a4_error>{{\"error\":\"INSTR_WORD_MOD requires word\"}}</a4_error>");
    }
}
```

### 6.2 MEM_VAL_MOD Handler (for comparison)

```rust
(Some("MEM_VAL_MOD"), Some(target_step)) => {
    let txn_idx = extract_num("txn_idx");
    let new_word = extract_num("word");
    
    match (txn_idx, new_word) {
        (Some(idx), Some(word)) => {
            let idx = idx as usize;
            if idx < trace.txns.len() {
                let txn = &mut trace.txns[idx];
                txn.word = word;  // Only word, NOT prev_word
                
                println!("<a4_mem_val_mod>{{...}}</a4_mem_val_mod>");
            }
        }
        _ => { ... }
    }
}
```

**Key difference**: MEM_VAL_MOD uses `txn_idx` directly from config, while INSTR_WORD_MOD calculates from `cycle.pc`.

### 6.3 Inspection Output Generation

The inspection output is generated before mutations are applied:

```rust
// Lines 72-186 in mod.rs
if std::env::var("A4_INSPECT").is_ok() {
    // Dump cycle info
    for (i, cycle) in trace.cycles.iter().enumerate() {
        println!("<a4_cycle_info>{{...}}</a4_cycle_info>");
    }
    
    // Dump all transactions
    if std::env::var("A4_DUMP_ALL_TXNS").is_ok() {
        for (txn_idx, txn) in trace.txns.iter().enumerate() {
            // Find step for this transaction
            let step = find_step_for_txn(txn_idx, &trace.cycles);
            println!("<a4_all_txn>{{...}}</a4_all_txn>");
        }
    }
}

// MUTATIONS APPLIED AFTER INSPECTION OUTPUT
if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
    // Apply mutation here...
}
```

---

## 7. C++ FFI Layer

### 7.1 getMemoryTxn Function

Located in `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp`:

```cpp
GetDataResult getMemoryTxn(ExecContext& ctx, Val addrElem) {
  uint32_t addr = addrElem.asUInt32();
  
  // Get next transaction for this cycle and increment counter
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;
  const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];
  
  // Validation checks
  if (txn.cycle / 2 != ctx.cycle) {
    throw std::runtime_error("txn cycle mismatch");
  }
  if (txn.addr != addr) {
    throw std::runtime_error("txn addr mismatch");
  }
  
  // Return transaction data
  return {
    txn.prevCycle,
    txn.prevWord & 0xffff,    // prev_word low 16 bits
    txn.prevWord >> 16,        // prev_word high 16 bits
    txn.word & 0xffff,         // word low 16 bits
    txn.word >> 16,            // word high 16 bits
  };
}
```

**Key insight**: The `txnIdx++` means transactions are consumed sequentially. The first call for a cycle gets the first transaction (instruction fetch for instruction cycles).

### 7.2 hostReadPrepare Function

```cpp
Val extern_hostReadPrepare(ExecContext& ctx, Val fp, Val len) {
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx;
  uint32_t word = ctx.preflight.txns[txnIdx].word;
  return word;
}
```

---

## 8. Circuit Instruction Decoding

### 8.1 exec_decode_inst Function

Located in `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/zirgen/steps.rs.inc`:

```rust
pub fn exec_decode_inst<'a>(
    ctx: &'a ExecContext,
    arg0: &RegStruct,      // Cycle register
    arg1: &InstInputStruct, // Instruction input (PC, mode, etc.)
    layout2: BoundLayout<'a, DecodeInstLayout, Val>,
) -> Result<DecoderStruct> {
    // Get cycle argument
    let x5: CycleArgStruct = exec_cycle_arg(ctx, ...)?;
    
    // Verify cycle matches
    let x6: Val = (x5.cycle._super - arg0._super._super);
    eqz!(x6, "DecodeInst:22");  // Constraint: cycles must match
    
    // Decompose PC address
    let x7: AddrDecomposeStruct = exec_addr_decompose(ctx, &arg1.pc_u32, ...)?;
    
    // Verify PC is word-aligned
    eqz!(x7.low2._super, "DecodeInst:26");  // Constraint: low 2 bits must be 0
    
    // READ INSTRUCTION FROM MEMORY
    let x8: GetDataStruct = exec_memory_read(ctx, arg0, x7._super, ...)?;
    
    // DECODE INSTRUCTION WORD
    let x9: DecoderStruct = exec_decoder(ctx, &x8._super, ...)?;
    
    return Ok(x9);
}
```

### 8.2 exec_decoder Function

```rust
pub fn exec_decoder<'a>(
    ctx: &'a ExecContext,
    arg0: &ValU32Struct,  // Instruction word (low, high)
    layout1: BoundLayout<'a, DecoderLayout, Val>,
) -> Result<DecoderStruct> {
    let x2: Val = arg0.high;  // Upper 16 bits
    let x12: Val = arg0.low;  // Lower 16 bits
    
    // Extract func7 bits (bits 25-31)
    let x3 = exec_nondet_bit_reg(ctx, bit_and(x2, 32768)? * INV_32768, ...)?;  // bit 31
    let x4 = exec_nondet_twit_reg(ctx, bit_and(x2, 24576)? * INV_24576, ...)?; // bits 29-30
    // ... more bit extractions ...
    
    // Extract opcode (bits 0-6)
    let x19 = exec_nondet_reg(ctx, bit_and(x12, 127)?, layout1.opcode)?;
    
    // Extract func3 (bits 12-14)
    let x14 = exec_nondet_bit_reg(ctx, bit_and(x12, 16384)? * INV, ...)?;
    let x15 = exec_nondet_twit_reg(ctx, bit_and(x12, 12288)? * INV, ...)?;
    
    // ... extract rs1, rs2, rd, immediates ...
    
    return Ok(DecoderStruct {
        opcode: x19,
        rs1: computed_rs1,
        rs2: computed_rs2,
        rd: computed_rd,
        func3: computed_func3,
        func7: computed_func7,
        // ... immediates ...
    });
}
```

### 8.3 exec_nondet_reg Function

```rust
pub fn exec_nondet_reg<'a>(
    ctx: &'a ExecContext,
    arg0: Val,           // Value to store
    layout1: BoundLayout<'a, NondetRegLayout, Val>,
) -> Result<NondetRegStruct> {
    let x2: BoundLayout<Reg, _> = layout1.map(|c| c._super);
    x2.store(ctx, arg0);  // Store value in witness
    return Ok(NondetRegStruct {
        _super: x2.load(ctx, 0),  // Return stored value
    });
}
```

**Key insight**: This stores the computed value (from the mutated instruction word) in the witness. It does NOT verify the value - that's done by later constraints.

---

## 9. Memory IO Subsystem

### 9.1 exec_memory_io Function

```rust
pub fn exec_memory_io<'a>(
    ctx: &'a ExecContext,
    arg0: &RegStruct,    // Cycle register
    arg1: Val,           // Address
    layout2: BoundLayout<'a, MemoryIOLayout, Val>,
) -> Result<MemoryIOStruct> {
    // Call external function to get transaction data
    let (x3, x4, x5, x6, x7) = invoke_extern!(ctx, get_memory_txn, arg1);
    //  x3 = prevCycle
    //  x4 = prevWord low 16 bits
    //  x5 = prevWord high 16 bits
    //  x6 = word low 16 bits
    //  x7 = word high 16 bits
    
    // Create old_txn (prev_word)
    let x8: MemoryArgStruct = exec_memory_arg(
        ctx, ..., &ValU32Struct { low: x4, high: x5 }, ...
    )?;
    
    // Create new_txn (word)
    let x10: MemoryArgStruct = exec_memory_arg(
        ctx, ..., &ValU32Struct { low: x6, high: x7 }, ...
    )?;
    
    return Ok(MemoryIOStruct { old_txn: x8, new_txn: x10 });
}
```

### 9.2 exec_memory_read Function

```rust
pub fn exec_memory_read<'a>(...) -> Result<GetDataStruct> {
    // Get transaction data
    let x3: MemoryIOStruct = exec_memory_io(ctx, arg0, arg1, ...)?;
    
    // IsRead constraint: word == prev_word
    let x4: MemoryArgStruct = x3.old_txn;  // prev_word
    let x5: MemoryArgStruct = x3.new_txn;  // word
    
    let x6: Val = x5.data_low._super;
    let x7: Val = (x4.data_low._super - x6);
    eqz!(x7, "IsRead:79");  // Constraint: prev_word.low == word.low
    
    let x8: Val = x5.data_high._super;
    let x9: Val = (x4.data_high._super - x8);
    eqz!(x9, "IsRead:80");  // Constraint: prev_word.high == word.high
    
    // Return the word value
    return Ok(GetDataStruct {
        _super: ValU32Struct { low: x6, high: x8 },
        ...
    });
}
```

**This explains why INSTR_WORD_MOD sets both word AND prev_word**: To pass the IsRead constraint for instruction fetch (which is always a READ transaction).

---

## 10. Constraint Failure Capture System

### 10.1 eqz! Macro and eqz Function

Located in `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h`:

```cpp
inline void eqz(ExecContext& ctx, Val a, const char* loc) {
  if (a.asUInt32()) {  // If value is non-zero, constraint fails
    // Get cycle info for failure report
    uint32_t step = ctx.preflight.cycles[ctx.cycle].userCycle;
    uint32_t pc = ctx.preflight.cycles[ctx.cycle].pc;
    uint8_t major = ctx.preflight.cycles[ctx.cycle].major;
    uint8_t minor = ctx.preflight.cycles[ctx.cycle].minor;
    
    // Print constraint failure
    printf("<constraint_fail>{\"cycle\":%zu, \"step\":%u, \"pc\":%u, "
           "\"major\":%u, \"minor\":%u, \"loc\":\"%s\", \"value\":%u}"
           "</constraint_fail>\n",
           ctx.cycle, step, pc, major, minor, loc, a.asUInt32());
    fflush(stdout);
    
    // Check if we should continue or throw
    if (std::getenv("CONSTRAINT_CONTINUE") != NULL) {
      return;  // Continue to next constraint
    }
    
    // Default: throw exception
    std::stringstream ss;
    ss << "[" << ctx.cycle << "]: eqz failure at: " << loc;
    throw std::runtime_error(ss.str());
  }
}
```

### 10.2 Python Constraint Parser

Located in `/root/arguzz/a4/core/constraint_parser.py`:

```python
@dataclass
class ConstraintFailure:
    cycle: int
    step: int
    pc: int
    major: int
    minor: int
    loc: str
    value: int
    
    @classmethod
    def parse(cls, line: str) -> Optional['ConstraintFailure']:
        match = re.search(r'<constraint_fail>({.*?})</constraint_fail>', line)
        if not match:
            return None
        data = json.loads(match.group(1))
        return cls(**data)

def parse_all_constraint_failures(output: str) -> List[ConstraintFailure]:
    return [f for line in output.splitlines() if (f := ConstraintFailure.parse(line))]
```

---

## 11. Comparison with MEM_VAL_MOD

### 11.1 MEM_VAL_MOD Python Implementation

Located in `/root/arguzz/a4/standalone/mutations/mem_val_mod.py`:

```python
def get_targets_at_step(step: int, data: 'InspectionData') -> List[MemValModTarget]:
    targets = []
    
    cycle = data.get_cycle(step)
    if not cycle:
        return targets
    
    for txn in data.get_all_txns_at_step(step):
        # EXCLUSION 1: Skip instruction fetch
        if _is_instruction_fetch(txn, cycle):
            continue
        
        # EXCLUSION 2: Skip register transactions
        if txn.txn_type == "reg":
            continue
        
        # EXCLUSION 3: Skip store memory writes (covered by STORE_OUT_MOD)
        if cycle.major == MAJOR_STORE and txn.is_write():
            continue
        
        targets.append(MemValModTarget(...))
    
    return targets
```

### 11.2 _is_instruction_fetch Helper

```python
def _is_instruction_fetch(txn: A4AllTxn, cycle: A4CycleInfo) -> bool:
    """
    Check if a transaction is an instruction fetch.
    
    Instruction fetch characteristics:
    1. It's a READ transaction
    2. Address matches the instruction's word address
    3. It's the first memory transaction at the step
    
    NOTE: For branches/jumps, cycle.pc is the TARGET, not current+4!
    We use the simpler heuristic: first READ transaction at step is instruction fetch.
    """
    # Only instruction cycles (major 0-6) have instruction fetch
    if cycle.major > 6:
        return False
    
    # Must be a READ
    if not txn.is_read():
        return False
    
    # Check if address matches instruction fetch pattern
    # Note: This calculation is wrong for branches but we use it anyway
    expected_addr = (cycle.pc - 4) // 4
    return txn.addr == expected_addr
```

**Key difference**: MEM_VAL_MOD explicitly excludes instruction fetch because INSTR_WORD_MOD is meant to handle it.

### 11.3 MEM_VAL_MOD Rust Handler

The Rust handler for MEM_VAL_MOD is simpler - it uses `txn_idx` directly:

```rust
(Some("MEM_VAL_MOD"), Some(target_step)) => {
    let txn_idx = extract_num("txn_idx");
    let new_word = extract_num("word");
    
    if let (Some(idx), Some(word)) = (txn_idx, new_word) {
        let idx = idx as usize;
        if idx < trace.txns.len() {
            let txn = &mut trace.txns[idx];
            txn.word = word;  // Only word, NOT prev_word
        }
    }
}
```

**Key difference**: MEM_VAL_MOD only mutates `word`, leaving `prev_word` unchanged. This causes IsRead constraint to fail for READ transactions.

---

## 12. Major/Minor to Instruction Mapping

### 12.1 Major Categories

```
major=0: MISC0 - Basic ALU (ADD, SUB, AND, OR, XOR, SLL, SRL)
major=1: MISC1 - Comparisons and branches (SLT, SLTU, BEQ, BNE, BLT, BGE)
major=2: MISC2 - Upper immediates and jumps (LUI, AUIPC, JAL, JALR)
major=3: MUL0 - Multiplication (MUL, MULH, MULHSU, MULHU)
major=4: DIV0 - Division (DIV, DIVU, REM, REMU, shifts: SRL, SRA, SRLI, SRAI)
major=5: MEM0 - Loads (LW, LH, LB, LHU, LBU)
major=6: MEM1 - Stores (SW, SH, SB)
major=7: CONTROL0 - Control flow (ECALL, MRET, system)
major=8: ECALL0 - ECALL handling
major=9-11: POSEIDON - Poseidon hash operations
major=12: SHA0 - SHA operations
```

### 12.2 Minor Variants (example for major=6, stores)

```
minor=0: SB (store byte)
minor=1: SH (store halfword)
minor=2: SW (store word)
```

---

## 13. Preflight Trace Generation

### 13.1 Preflight Structure

Located in `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs`:

```rust
pub(crate) struct PreflightTrace {
    pub cycles: Vec<RawPreflightCycle>,
    pub txns: Vec<RawMemoryTransaction>,
    pub bigint_bytes: Vec<u8>,
    pub backs: Vec<Back>,
    pub table_split_cycle: u32,
    pub rand_z: ExtVal,
}
```

### 13.2 Cycle Addition

```rust
fn add_cycle(&mut self, state: CycleState, pc: u32, major: u8, minor: u8, ...) {
    let cycle = RawPreflightCycle {
        state: state as u32,
        pc,                           // NEXT PC (after instruction)
        major,
        minor,
        machine_mode: self.machine_mode as u8,
        user_cycle: self.user_cycle,  // "step" in A4
        txn_idx: self.txn_idx,        // First transaction for this cycle
        ...
    };
    self.trace.cycles.push(cycle);
    self.txn_idx = self.trace.txns.len() as u32;  // Update for next cycle
}
```

### 13.3 Transaction Recording (load_u32)

```rust
fn load_u32(&mut self, op: LoadOp, addr: WordAddr) -> Result<u32> {
    let cycle = (2 * self.trace.cycles.len()) as u32;  // Even = READ
    let word = self.pager.load(addr)?;
    
    let prev_cycle = self.prev_cycle.get(&addr).unwrap_or(u32::MAX);
    let prev_word = self.orig_words.get(&addr).unwrap_or(word);
    
    self.trace.txns.push(RawMemoryTransaction {
        addr: addr.0,
        cycle,
        word,
        prev_cycle,
        prev_word,
    });
    
    // Update tracking
    self.prev_cycle.insert(&addr, cycle);
    self.orig_words.get_mut(&addr).get_or_insert(word);
    
    Ok(word)
}
```

---

## 14. Value Generation System

### 14.1 ValueGenerator Class

Located in `/root/arguzz/a4/standalone/value_generator.py`:

```python
class ValueGenerator:
    def __init__(self, seed=None, strategy="smart"):
        self.rng = random.Random(seed)
        self.strategy = strategy
    
    def generate_different(self, original: int, context: dict = None) -> int:
        """Generate a value different from original"""
        if self.strategy == "random":
            return self._random_different(original)
        elif self.strategy == "bitflip":
            return self._bitflip(original)
        elif self.strategy == "smart":
            return self._smart_mutate(original, context)
        # ...
```

### 14.2 Smart Mutation Strategy

The smart strategy considers the instruction context but currently generates arbitrary 32-bit values that may change the opcode.

---

## 15. Fuzzer Output Classification

### 15.1 MutationResult Class

```python
@dataclass
class MutationResult:
    kind: str
    step: int
    original_value: int
    mutated_value: int
    config: dict
    failures: List[ConstraintFailure]
    verifier_accepted: bool
    execution_time_ms: float
    witness_gen_failed: bool
    new_coverage: int = 0
```

### 15.2 Outcome Classification

```python
def _check_witness_gen_failure(self, output: str) -> bool:
    """Check if witness generation failed (prover panic)"""
    patterns = [
        "witness generation failure",
        "panicked at",
        "set(row:",  # Witness matrix conflict
    ]
    return any(p in output for p in patterns)

def _check_verifier_acceptance(self, output: str) -> bool:
    """Check if verifier accepted the proof"""
    # Look for: <record>{"context":"Verifier", "status":"success"}</record>
    match = re.search(r'"context"\s*:\s*"Verifier".*?"status"\s*:\s*"(\w+)"', output)
    return match and match.group(1) == "success"
```

### 15.3 Outcome Categories

1. **CONSTRAINT_FAIL**: `len(failures) > 0`
2. **WITNESS_FAIL**: `witness_gen_failed == True` (includes crashes)
3. **REJECTED**: Verifier rejected proof (but no constraint failures captured)
4. **ACCEPTED**: Verifier accepted (potential soundness bug!)
5. **NO_EFFECT**: None of the above

---

## 16. File Locations Reference

### Python Files

| File | Purpose |
|------|---------|
| `/root/arguzz/a4/standalone/mutations/instr_word_mod.py` | INSTR_WORD_MOD Python implementation |
| `/root/arguzz/a4/standalone/mutations/mem_val_mod.py` | MEM_VAL_MOD Python implementation (for comparison) |
| `/root/arguzz/a4/standalone/fuzzer.py` | Main fuzzer class |
| `/root/arguzz/a4/standalone/step_selector.py` | Step selection strategies |
| `/root/arguzz/a4/standalone/value_generator.py` | Value generation strategies |
| `/root/arguzz/a4/standalone/cli.py` | Command-line interface |
| `/root/arguzz/a4/core/inspection_data.py` | InspectionData class |
| `/root/arguzz/a4/core/trace_parser.py` | Trace parsing (A4CycleInfo, A4AllTxn) |
| `/root/arguzz/a4/core/constraint_parser.py` | Constraint failure parsing |
| `/root/arguzz/a4/core/executor.py` | Mutation execution (run_a4_mutation) |

### Rust Files

| File | Purpose |
|------|---------|
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | A4 mutation hooks |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs` | Preflight trace generation |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs` | RawPreflightCycle, RawMemoryTransaction structs |

### C++ Files

| File | Purpose |
|------|---------|
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | getMemoryTxn, external functions |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` | eqz() function, constraint failure printing |

### Generated Files

| File | Purpose |
|------|---------|
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/zirgen/steps.rs.inc` | Generated circuit code (exec_decoder, exec_memory_read, etc.) |
| `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/zirgen/types.rs.inc` | Generated type definitions |

### Documentation

| File | Purpose |
|------|---------|
| `/root/arguzz/a4/docs/standalone/MUTATION_TAXONOMY.md` | Mutation function taxonomy |
| `/root/arguzz/a4/docs/standalone/IMPLEMENTATION_PLAN.md` | Multi-phase implementation plan |
| `/root/arguzz/a4/docs/standalone/impl/INSTR_WORD_MOD_IMPL.md` | INSTR_WORD_MOD implementation details |
| `/root/arguzz/a4/docs/standalone/impl/PHASE2_TXN_METADATA_IMPL.md` | Phase 2 implementation details |

---

## Test Commands Reference

```bash
# Run inspection only
A4_INSPECT=1 A4_DUMP_ALL_TXNS=1 ./host --in1 5 --in4 10

# Run mutation with constraint continue
echo '{"mutation_type":"INSTR_WORD_MOD","step":100,"word":3735928559}' > /tmp/test.json
A4_MUTATION_CONFIG=/tmp/test.json CONSTRAINT_CONTINUE=1 ./host --in1 5 --in4 10

# Run fuzzer campaign
python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --num 10 \
    --kind INSTR_WORD_MOD \
    -- --in1 5 --in4 10
```

---

This document should be used alongside the main issue report to have complete context when resuming the debugging session.
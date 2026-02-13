# A4 Standalone Mutation Taxonomy

This document provides a comprehensive taxonomy of all A4 standalone mutations, organized by category. It is the authoritative reference for what each mutation covers, what it excludes, and how mutations relate to each other.

## Table of Contents

1. [PreflightTrace Data Structures](#1-preflighttrace-data-structures)
2. [Transaction Anatomy & Address Spaces](#2-transaction-anatomy--address-spaces)
3. [Mutation Function Detailed Reference](#3-mutation-function-detailed-reference)
4. [Complete Variable Coverage Matrix](#4-complete-variable-coverage-matrix)
5. [`txns[].word` Context Coverage](#5-txnsword-context-coverage)
6. [Gap Analysis](#6-gap-analysis)
7. [Implementation Roadmap](#7-implementation-roadmap)
8. [Appendix A: Cycle State Values](#appendix-a-cycle-state-values)
9. [Appendix B: Major/Minor Values](#appendix-b-majorminor-values)

---

## 1. PreflightTrace Data Structures

### 1.1 PreflightTrace (Top-Level)

**Location**: `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs:64-75`

```rust
pub(crate) struct PreflightTrace {
    pub cycles: Vec<RawPreflightCycle>,      // Array of cycle metadata
    pub txns: Vec<RawMemoryTransaction>,     // Array of memory/register transactions
    pub bigint_bytes: Vec<u8>,               // BigInt computation data
    pub backs: Vec<Back>,                    // Back-references for special ops
    pub table_split_cycle: u32,              // Cycle where table splits
    pub rand_z: ExtVal,                      // Random value for checksums
}
```

### 1.2 RawPreflightCycle

**Location**: `workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs:35-49`

```rust
pub struct RawPreflightCycle {
    pub state: u32,           // Cycle state (Decode, MemIO, Poseidon, etc.)
    pub pc: u32,              // Program Counter (NEXT PC after execution)
    pub major: u8,            // InsnKind / 8
    pub minor: u8,            // InsnKind % 8
    pub machine_mode: u8,     // 0 = user mode, 1 = machine mode
    pub padding: u8,          // Alignment padding
    pub user_cycle: u32,      // Instruction step counter ("step")
    pub txn_idx: u32,         // Index into trace.txns[] where this cycle's transactions START
    pub paging_idx: u32,      // Index for paging operations
    pub bigint_idx: u32,      // Index into bigint_bytes[]
    pub diff_count: [u32; 2], // Diff counts for memory
}
```

### 1.3 RawMemoryTransaction

**Location**: `workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs:22-31`

```rust
pub struct RawMemoryTransaction {
    pub addr: u32,        // Word address (actual_addr / 4)
    pub cycle: u32,       // READ (even) or WRITE (odd) cycle
    pub word: u32,        // Value read/written
    pub prev_cycle: u32,  // Previous cycle that accessed this address
    pub prev_word: u32,   // Previous value at this address
}
```

### 1.4 Back Enum (Special Operation State)

**Location**: `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs:50-61`

```rust
pub(crate) enum Back {
    None,
    Ecall(u32, u32, u32),
    Poseidon2(Poseidon2State),
    Sha2(Sha2State),
    BigInt(BigIntState),
}
```

---

## 2. Transaction Anatomy & Address Spaces

### 2.1 Address Space Classification

Transactions are classified by their address:

| Address Range | Type | Description |
|---------------|------|-------------|
| `0x3FFFC020` - `0x3FFFC03F` (word addr: `0x0FFF F008` - `0x0FFF F00F`) | **Register** | 32 RISC-V general-purpose registers (x0-x31) |
| All other addresses | **Memory** | Program code, data, stack, heap |

**How to identify:**
- Register transactions: `addr >= 0x0FFFF008 && addr <= 0x0FFFF00F` (word addresses)
- Memory transactions: Everything else

### 2.2 Transaction Types at Each Step

#### Compute Instructions (major 0-4)
Transactions in order:
1. **Instruction Fetch** (Memory READ) - Fetches the instruction word from `addr = (pc-4)/4`
2. **Register READs** (Register READ) - Read source register(s) rs1, rs2
3. **Register WRITE** (Register WRITE) - Write result to destination register rd

#### Load Instructions (major 5)
Transactions in order:
1. **Instruction Fetch** (Memory READ) - Fetches the instruction word
2. **Register READ** (Register READ) - Read base address register rs1
3. **Memory READ** (Memory READ) - Read data from memory at computed address
4. **Register WRITE** (Register WRITE) - Write loaded data to destination register rd

#### Store Instructions (major 6) - Read-Modify-Write Pattern
Transactions in order:
1. **Instruction Fetch** (Memory READ) - Fetches the instruction word
2. **Register READs** (Register READ) - Read base address (rs1) and store value (rs2)
3. **Memory READ** (Memory READ) - **RMW Read**: Read current word from memory (for byte/halfword stores)
4. **Memory WRITE** (Memory WRITE) - **RMW Write**: Write modified word back to memory

**Why Read-Modify-Write?** Memory is word-aligned. For sub-word stores (SB, SH), the circuit must:
1. READ the existing 32-bit word
2. MODIFY only the relevant bytes
3. WRITE the modified word back

#### Non-Instruction Cycles (major 7+)
These include control flow, ECALL, Poseidon, SHA, BigInt operations. Transaction patterns vary.

### 2.3 Read vs Write Classification

The `txns[].cycle` field determines READ vs WRITE:
- **READ**: `cycle` is even
- **WRITE**: `cycle` is odd

---

## 3. Mutation Function Detailed Reference

This section documents EVERY mutation function (existing, partial, and planned) with complete details about what it covers, excludes, and how it relates to other mutations.

### 3.1 INSTR_TYPE_MOD

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented, Verified |
| **File** | `instr_type_mod.py` |
| **Target Field(s)** | `cycles[].major`, `cycles[].minor` |
| **Scope** | Instruction cycles only (major 0-6) |
| **Expected Constraint Failures** | VerifyOpcodeF3 |
| **Verified Against Arguzz** | ✅ Yes |

**What It Covers:**
- Changes the instruction type (major/minor) at instruction cycles
- Tests instruction decoding constraints

**What It EXCLUDES:**
- Non-instruction cycles (major 7+): Control, ECALL, Poseidon, SHA, BigInt cycles

**Relationship to Other Mutations:**
- This is the ONLY mutation targeting `cycles[].major` and `cycles[].minor`
- Complementary to INSTR_WORD_MOD (which changes the instruction word in `txns[]`)

---

### 3.2 COMP_OUT_MOD

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented, Verified |
| **File** | `comp_out_mod.py` |
| **Target Field(s)** | `txns[].word` |
| **Scope** | Last register WRITE transaction at compute instructions (major 0-4) |
| **Expected Constraint Failures** | MemoryWrite |
| **Verified Against Arguzz** | ✅ Yes |

**What It Covers:**
- The final result of compute instructions (the value written to rd)
- Only the LAST register write (the destination register)

**What It EXCLUDES:**
- Register READs (source registers) - covered by PRE_EXEC_REG_MOD
- Earlier register WRITEs if any - covered by PRE_EXEC_REG_MOD
- Non-compute instructions (major 5, 6, 7+)
- Memory transactions

**Relationship to Other Mutations:**
- **Overlaps with PRE_EXEC_REG_MOD**: PRE_EXEC_REG_MOD can also target register writes at compute steps, but COMP_OUT_MOD specifically targets the LAST write (the output)
- **Complementary to LOAD_VAL_MOD**: LOAD_VAL_MOD covers the same pattern but for load instructions (major 5)

---

### 3.3 LOAD_VAL_MOD

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented, Verified |
| **File** | `load_val_mod.py` |
| **Target Field(s)** | `txns[].word` |
| **Scope** | Last register WRITE transaction at load instructions (major 5) |
| **Expected Constraint Failures** | MemoryWrite |
| **Verified Against Arguzz** | ✅ Yes |

**What It Covers:**
- The loaded value written to the destination register (rd)
- Only load instructions (LW, LH, LB, LHU, LBU)

**What It EXCLUDES:**
- The memory READ that fetches the data - covered by MEM_VAL_MOD (load_mem_read)
- Register READs (base address register) - covered by PRE_EXEC_REG_MOD
- Non-load instructions

**Relationship to Other Mutations:**
- **Complementary to MEM_VAL_MOD (load_mem_read)**: MEM_VAL_MOD targets the memory READ side; LOAD_VAL_MOD targets the register WRITE side of the same operation
- **Overlaps with PRE_EXEC_REG_MOD**: PRE_EXEC_REG_MOD can also target register writes at load steps
- **Complementary to COMP_OUT_MOD**: Same pattern but for different instruction types

---

### 3.4 STORE_OUT_MOD

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented, Verified |
| **File** | `store_out_mod.py` |
| **Target Field(s)** | `txns[].word` |
| **Scope** | Memory WRITE transaction at store instructions (major 6) |
| **Expected Constraint Failures** | MemoryWrite |
| **Verified Against Arguzz** | ✅ Yes |

**What It Covers:**
- The final value written to memory by store instructions (SW, SH, SB)
- This is the WRITE part of the Read-Modify-Write pattern

**What It EXCLUDES:**
- The memory READ (RMW read) - covered by MEM_VAL_MOD (store_rmw_read)
- Register READs (base address and value registers) - covered by PRE_EXEC_REG_MOD
- Memory writes at non-store instructions

**Relationship to Other Mutations:**
- **Mutually exclusive with MEM_VAL_MOD for store writes**: MEM_VAL_MOD explicitly excludes store memory writes because STORE_OUT_MOD covers them
- **Complementary to MEM_VAL_MOD (store_rmw_read)**: MEM_VAL_MOD targets the READ side; STORE_OUT_MOD targets the WRITE side

---

### 3.5 PRE_EXEC_REG_MOD

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented, Verified |
| **File** | `pre_exec_reg_mod.py` |
| **Target Field(s)** | `txns[].word` |
| **Scope** | Register READ or WRITE transactions at instruction cycles (major 0-6) |
| **Strategies** | `next_read` (target register READs), `prev_write` (target register WRITEs) |
| **Expected Constraint Failures** | IsRead (next_read), MemoryWrite (prev_write) |
| **Verified Against Arguzz** | ✅ Yes |

**What It Covers:**
- ALL register transactions at instruction steps (major 0-6)
- Both READs (source registers) and WRITEs (destination registers)
- Has two strategies:
  - `next_read`: Mutates a register that will be READ by the current instruction
  - `prev_write`: Mutates a register that was WRITTEN by a previous instruction

**What It EXCLUDES:**
- Memory transactions (instruction fetch, data memory) - registers only
- Non-instruction cycles (major 7+) - **GAP: see REG_TXN_NON_INSN_MOD**

**Relationship to Other Mutations:**
- **Overlaps with COMP_OUT_MOD**: Both can target register WRITEs at compute steps; COMP_OUT_MOD is more specific (last write only)
- **Overlaps with LOAD_VAL_MOD**: Both can target register WRITEs at load steps
- **Does NOT overlap with STORE_OUT_MOD**: STORE_OUT_MOD targets memory, not registers
- **Complementary to MEM_VAL_MOD**: PRE_EXEC_REG_MOD covers registers; MEM_VAL_MOD covers memory

---

### 3.6 MEM_VAL_MOD

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented |
| **File** | `mem_val_mod.py` |
| **Target Field(s)** | `txns[].word` |
| **Scope** | Memory transactions (non-register addresses) with specific exclusions |
| **Expected Constraint Failures** | MemoryRead, MemoryWrite |
| **Verified Against Arguzz** | ❌ No (Standalone-only, no Arguzz equivalent) |

**What It Covers (txn_type classifications):**
- `load_mem_read`: Memory READ at load instructions (major 5) - the data fetched from memory
- `store_rmw_read`: Memory READ at store instructions (major 6) - the RMW read
- `other_mem_read`: Memory READ at other cycle types (ECALL, crypto, etc.)
- `other_mem_write`: Memory WRITE at non-store cycles (ECALL, crypto, etc.)

**What It EXPLICITLY EXCLUDES (and why):**

1. **Instruction fetch transactions** - Excluded because INSTR_WORD_MOD covers them
   - Detection: First transaction of cycle (`txn_idx == cycle.txn_idx`) AND is READ AND `addr == (pc-4)/4`
   - See `_is_instruction_fetch()` function in `mem_val_mod.py`

2. **Store memory writes** - Excluded because STORE_OUT_MOD covers them
   - Detection: `is_write AND major == 6`

3. **Register transactions** - Excluded because PRE_EXEC_REG_MOD covers them
   - Detection: Address in register range (`0x0FFFF008` - `0x0FFFF00F`)
   - Note: This is handled by `get_mem_txns_at_step()` which only returns memory transactions

**Relationship to Other Mutations:**
- **Complementary to INSTR_WORD_MOD**: MEM_VAL_MOD explicitly excludes instruction fetch; INSTR_WORD_MOD covers it
- **Complementary to STORE_OUT_MOD**: MEM_VAL_MOD excludes store writes; STORE_OUT_MOD covers them
- **Complementary to PRE_EXEC_REG_MOD**: MEM_VAL_MOD covers memory; PRE_EXEC_REG_MOD covers registers
- **Complementary to LOAD_VAL_MOD**: MEM_VAL_MOD covers the memory READ; LOAD_VAL_MOD covers the register WRITE

---

### 3.7 INSTR_WORD_MOD (Overview)

There are **two variants** of instruction word mutation, each with distinct strategies and purposes:

| Variant | File | Strategy | Produces Invalid Instructions? |
|---------|------|----------|-------------------------------|
| **INSTR_WORD_MOD_FULL** | `instr_word_mod.py` | Full 32-bit word mutation | ❌ No (Arguzz-aligned validation) |
| **INSTR_WORD_MOD_SUR** | `instr_word_mod_sur.py` | Surgical field-level mutation | ✅ Yes (intentional for constraint coverage) |

---

### 3.7.1 INSTR_WORD_MOD_FULL

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented |
| **File** | `instr_word_mod.py` |
| **Target Field(s)** | `txns[].word` AND `txns[].prev_word` (both set to same mutated value) |
| **Scope** | Instruction fetch transactions at instruction cycles (major 0-6) |
| **Mutation Strategy** | Arguzz-aligned: bit flips + random words with validation loop |
| **Produces Invalid Instructions** | ❌ No - always generates valid RV32IM |
| **Expected Constraint Failures** | VerifyOpcodeF3, VerifyOpcodeF3F7, instruction execution constraints |
| **Rust Support** | ✅ Yes (in mod.rs) |
| **Verified Against Arguzz** | ✅ Yes |

#### Purpose & Philosophy

INSTR_WORD_MOD_FULL tests what happens when the **entire instruction word** is changed to a **different but valid** RV32IM instruction. This simulates scenarios where:
- Memory corruption changes an instruction
- An attacker replaces one valid instruction with another
- The wrong instruction is fetched

By ensuring the mutated instruction is always valid, this mutation focuses on testing **instruction execution constraints** and **opcode/funct mismatch detection** rather than invalid instruction handling.

#### Mutation Strategy (Arguzz-Aligned)

The mutation strategy is directly ported from Arguzz's `rv32im.rs`:

```python
def _generate_valid_full_word_mutation(original_word, max_attempts=100):
    for _ in range(max_attempts):
        selector = random(0, 2)
        if selector == 0:
            new_word = single_bit_flip(original_word)      # Flip 1 bit (not bits 0-1)
        elif selector == 1:
            new_word = multi_bit_flip(original_word)       # Flip 1-29 random bits
        else:
            new_word = random_word_with_bits_0_1_set()     # Random word with bits[1:0]=0b11
        
        if new_word != original_word and is_valid_rv32im(new_word):
            return new_word
    return None  # Failed after max_attempts
```

**Key Properties:**
1. **Bits 0-1 are protected**: Always `0b11` (required for 32-bit RISC-V instructions)
2. **Validation loop**: Ensures output is always a valid RV32IM instruction
3. **Three strategies** with equal probability:
   - Single bit flip (1 bit in positions 2-31)
   - Multi bit flip (1-29 bits in positions 2-31)
   - Completely random valid word

#### Validation Function

```python
def _is_valid_rv32im_instruction(word):
    if (word & 0x03) != 0x03:  # Must be 32-bit instruction
        return False
    
    instr = RiscVInstruction.from_word(word)
    return instr.format != InstrFormat.UNKNOWN
```

This validates:
- Correct opcode (bits 0-6 form a recognized RV32IM opcode)
- Valid funct3 for the opcode (where applicable)
- Valid funct7 for R-type instructions

#### What It Covers

| Cycle Type | Major | Included | Reason |
|------------|-------|----------|--------|
| MISC0 | 0 | ✅ | ALU ops (ADD, SUB, XOR, etc.) |
| MISC1 | 1 | ✅ | Compare/branch (SLT, BEQ, etc.) |
| MISC2 | 2 | ✅ | LUI, AUIPC, JAL, JALR |
| MUL0 | 3 | ✅ | Multiplication |
| DIV0 | 4 | ✅ | Division |
| MEM0 | 5 | ✅ | Load instructions |
| MEM1 | 6 | ✅ | Store instructions |
| CONTROL0 | 7 | ❌ | No instruction fetch |
| ECALL0 | 8 | ❌ | System calls (different handling) |
| POSEIDON | 9-10 | ❌ | No transactions |
| SHA | 11 | ❌ | No transactions |

#### What It EXCLUDES

| Exclusion | Reason |
|-----------|--------|
| **Step 0** | Bootloader init (AUIPC at 0xC0000000); 16,574 cycles; not user code |
| **Invalid instructions** | Validation loop ensures only valid RV32IM |
| **Field-specific mutations** | Covered by INSTR_WORD_MOD_SUR |

#### Terminal Output Format

```
INSTR_WORD_MOD_FULL @ step 1234: 3 failures, 5432ms, outcome: REJECTED [+2 new]
  Original: ADD x10, x11, x12 (R-type)
  Mutated:  SUB x10, x11, x12 (R-type)
  Format change: R-type -> R-type
  Constraints hit (3 unique):
    - VerifyOpcodeF3F7@inst.zir:97
    - ...
```

#### Why Both `word` AND `prev_word` Are Set

The Rust handler sets both fields to the same mutated value:
```rust
txn.word = new_word;
txn.prev_word = new_word;
```

This is intentional because instruction fetch is a READ transaction, and for READs the circuit enforces `word == prev_word` (IsRead constraint). By setting both to the same mutated value:
1. The IsRead constraint still passes (memory consistency preserved)
2. But the circuit now "sees" a different instruction word
3. This causes **instruction decoding constraints** to fail

---

### 3.7.2 INSTR_WORD_MOD_SUR (Surgical)

| Property | Value |
|----------|-------|
| **Status** | ✅ Implemented |
| **File** | `instr_word_mod_sur.py` |
| **Target Field(s)** | Individual fields within `txns[].word` |
| **Scope** | Instruction fetch transactions at instruction cycles (major 0-6) |
| **Mutation Strategy** | Surgical: mutate ONE specific field per mutation |
| **Produces Invalid Instructions** | ✅ Yes (intentional - tests more constraints) |
| **Expected Constraint Failures** | Field-specific (see table below) |
| **Rust Support** | ✅ Yes (reuses INSTR_WORD_MOD handler in mod.rs) |

#### Purpose & Philosophy

INSTR_WORD_MOD_SUR tests what happens when **specific fields** within an instruction are corrupted while others remain intact. This provides:
1. **Fine-grained constraint coverage**: Know exactly which field triggered which constraint
2. **Field-constraint correlation**: Build a map of which fields affect which constraints
3. **Invalid instruction testing**: Intentionally create invalid opcode/funct combinations to test constraint completeness

**Key difference from FULL**: SUR does NOT validate instruction validity because invalid combinations (e.g., LOAD with invalid funct3) can reveal constraint gaps that valid-only mutations would miss.

#### Mutable Fields

| Field | Bits | Applies To | Description |
|-------|------|------------|-------------|
| `opcode` | [6:0] | All formats | Instruction type identifier |
| `rd` | [11:7] | R, I, U, J | Destination register |
| `rs1` | [19:15] | R, I, S, B | Source register 1 |
| `rs2` | [24:20] | R, S, B | Source register 2 |
| `funct3` | [14:12] | R, I, S, B | Operation variant |
| `funct7` | [31:25] | R only | Extended operation |
| `imm` | Various | I, S, B, U, J | Immediate value |

#### Value Generation Strategies Per Field

| Field | Strategy | Can Produce Invalid? |
|-------|----------|---------------------|
| `opcode` | 70% valid opcodes, 30% random [0,127] | ✅ Yes (30% chance) |
| `rd` | Random [0,31] | ❌ No (all registers valid) |
| `rs1` | Random [0,31] | ❌ No (all registers valid) |
| `rs2` | Random [0,31] | ❌ No (all registers valid) |
| `funct3` | Random [0,7] | ✅ Yes (invalid combos) |
| `funct7` | 60% common (0x00,0x20,0x01), 40% random | ✅ Yes (invalid combos) |
| `imm` | Random within format-specific range | ❌ No (any value valid) |

#### Why Invalid Instructions Are Allowed

From actual test results:
```
Surgical: funct3 = 0 -> 3
Original: ADDI x23, x10, 0
Mutated:  SLTIU x23, x10, 0
Constraints hit: VerifyOpcodeF3@inst.zir:97
```

The constraint `VerifyOpcodeF3` verifies that the instruction's funct3 **matches what was recorded in the preflight trace**, not that the instruction is valid. This distinction is crucial:

- **FULL** tests: "What if a different valid instruction is executed?"
- **SUR** tests: "What if a specific field doesn't match the recorded trace?"

Invalid instruction combinations can hit **different constraints** than valid ones, providing better coverage of the constraint system.

#### Expected Constraints Per Field

| Field Mutated | Primary Constraints Triggered |
|---------------|------------------------------|
| `opcode` | VerifyOpcodeF3, VerifyOpcodeF3F7, format detection |
| `rd` | Register addressing, result storage |
| `rs1` | Register read, operand fetch |
| `rs2` | Register read, operand fetch |
| `funct3` | VerifyOpcodeF3, operation selection |
| `funct7` | VerifyOpcodeF3F7, operation selection (R-type) |
| `imm` | Immediate decode, address calculation, branch targets |

#### RISC-V Instruction Format Reference

```
R-type: [funct7:7][rs2:5][rs1:5][funct3:3][rd:5][opcode:7]
I-type: [imm[11:0]:12][rs1:5][funct3:3][rd:5][opcode:7]
S-type: [imm[11:5]:7][rs2:5][rs1:5][funct3:3][imm[4:0]:5][opcode:7]
B-type: [imm[12|10:5]:7][rs2:5][rs1:5][funct3:3][imm[4:1|11]:5][opcode:7]
U-type: [imm[31:12]:20][rd:5][opcode:7]
J-type: [imm[20|10:1|11|19:12]:20][rd:5][opcode:7]
```

#### Terminal Output Format

```
INSTR_WORD_MOD_SUR @ step 3308: 1 failures, 18194ms, outcome: REJECTED [+1 new]
  Surgical: funct3 = 0 -> 3
  Original: ADDI x23, x10, 0
  Mutated:  SLTIU x23, x10, 0
  Constraints hit (1 unique):
    - VerifyOpcodeF3@inst.zir:97
```

#### Disassembly Support

The `RiscVInstruction` class provides full disassembly with proper mnemonics:

| Format | Mnemonic Resolution |
|--------|---------------------|
| R-type | funct7 + funct3 → ADD/SUB/SLL/SLT/SLTU/XOR/SRL/SRA/OR/AND/MUL/etc. |
| I-type ALU | funct3 → ADDI/SLTI/SLTIU/XORI/ORI/ANDI/SLLI/SRLI/SRAI |
| I-type LOAD | funct3 → LB/LH/LW/LBU/LHU |
| I-type JALR | JALR |
| S-type | funct3 → SB/SH/SW |
| B-type | funct3 → BEQ/BNE/BLT/BGE/BLTU/BGEU |
| U-type | opcode → LUI/AUIPC |
| J-type | JAL |

---

### 3.7.3 Comparison: FULL vs SUR

| Aspect | INSTR_WORD_MOD_FULL | INSTR_WORD_MOD_SUR |
|--------|--------------------|--------------------|
| **Granularity** | Whole 32-bit word | Individual field |
| **Validation** | ✅ Always valid RV32IM | ❌ May be invalid |
| **Strategy** | Arguzz-aligned (bit flips + random) | Field-specific value gen |
| **Constraint Focus** | Execution constraints | Field-specific constraints |
| **Trackability** | Original/mutated word | Which field, old/new value |
| **Use Case** | "Wrong instruction executed" | "Field mismatch detection" |
| **Coverage Style** | Broad (any valid instruction) | Deep (specific field combos) |

#### When to Use Each

| Scenario | Use |
|----------|-----|
| Testing overall instruction validation | FULL |
| Building field-constraint correlation map | SUR |
| Fuzzing with valid-only mutations | FULL |
| Testing constraint completeness | SUR |
| Replicating Arguzz behavior | FULL |
| Fine-grained coverage analysis | SUR |

---

### 3.7.4 Common Properties (Both Variants)

**What Both Cover:**
- Instruction cycles (major 0-6): MISC0, MISC1, MISC2, MUL0, DIV0, MEM0, MEM1
- Instruction fetch transaction (first memory READ of cycle)

**What Both EXCLUDE:**

| Exclusion | Reason |
|-----------|--------|
| **Step 0** | Bootloader init; not user code |
| **CONTROL cycles (major=7)** | No instruction fetch |
| **ECALL cycles (major=8)** | Different handling (fixed ECALL opcode) |
| **POSEIDON/SHA cycles** | No transactions |
| **Other memory transactions** | Covered by MEM_VAL_MOD |
| **Register transactions** | Covered by PRE_EXEC_REG_MOD |

**Branch/Jump Handling:**

For branches (BEQ, BNE, BLT, BGE, etc.) and jumps (JAL, JALR):
- `cycle.pc` stores the NEXT PC (branch target or sequential)
- We use `cycle.txn_idx` directly to find the instruction fetch
- This correctly handles all instruction types regardless of control flow

**Relationship to Other Mutations:**
- **Fills gap left by MEM_VAL_MOD**: MEM_VAL_MOD explicitly excludes instruction fetch
- **Complementary to INSTR_TYPE_MOD**: INSTR_TYPE_MOD changes `cycles[].major/minor`; these change `txns[].word`

---

### 3.8 TXN_PREV_WORD_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🔴 To Implement (High Priority) |
| **File** | `txn_prev_word_mod.py` (TO CREATE) |
| **Target Field(s)** | `txns[].prev_word` |
| **Scope** | Any transaction |
| **Expected Constraint Failures** | IsRead (for READs where `word == prev_word`), MemoryWrite |
| **Risk Level** | Low |

**What It Will Cover:**
- The `prev_word` field which stores the previous value at this address
- For READ transactions, the constraint `word == prev_word` should be checked
- For WRITE transactions, `prev_word` is used for write consistency

**What It Will EXCLUDE:**
- Nothing - targets all transactions (can be subsetted by address type if needed)

**Relationship to Other Mutations:**
- **First mutation targeting `txns[].prev_word`** - No overlap with existing mutations
- Complementary to all `txns[].word` mutations

---

### 3.9 TXN_PREV_CYCLE_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🔴 To Implement (High Priority) |
| **File** | `txn_prev_cycle_mod.py` (TO CREATE) |
| **Target Field(s)** | `txns[].prev_cycle` |
| **Scope** | Any transaction |
| **Expected Constraint Failures** | Memory ordering/consistency constraints |
| **Risk Level** | Low |

**What It Will Cover:**
- The `prev_cycle` field which tracks when this address was last accessed
- Breaking this creates temporal inconsistency in memory access ordering

**Relationship to Other Mutations:**
- **First mutation targeting `txns[].prev_cycle`** - No overlap with existing mutations

---

### 3.10 TXN_ADDR_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟡 To Implement (Medium Priority) |
| **File** | `txn_addr_mod.py` (TO CREATE) |
| **Target Field(s)** | `txns[].addr` |
| **Scope** | Any transaction |
| **Expected Constraint Failures** | Memory addressing constraints |
| **Risk Level** | High - may crash witness generation |

**What It Will Cover:**
- The word address of any transaction
- Breaking address consistency likely causes severe constraint failures

**Relationship to Other Mutations:**
- **First mutation targeting `txns[].addr`** - No overlap with existing mutations

---

### 3.11 TXN_CYCLE_PHASE_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟡 To Implement (Medium Priority) |
| **File** | `txn_cycle_phase_mod.py` (TO CREATE) |
| **Target Field(s)** | `txns[].cycle` |
| **Scope** | Any transaction |
| **Expected Constraint Failures** | Read/write classification constraints |
| **Risk Level** | Medium |

**What It Will Cover:**
- The `cycle` field which determines READ (even) vs WRITE (odd)
- Flipping even↔odd changes how the circuit interprets the transaction

**Relationship to Other Mutations:**
- **First mutation targeting `txns[].cycle`** - No overlap with existing mutations

---

### 3.12 CYCLE_PC_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟡 To Implement (Medium Priority) |
| **File** | `cycle_pc_mod.py` (TO CREATE) |
| **Target Field(s)** | `cycles[].pc` |
| **Scope** | Instruction cycles (major 0-6) |
| **Expected Constraint Failures** | PC consistency, instruction fetch address constraints |
| **Risk Level** | Medium |

**What It Will Cover:**
- The `pc` field which stores the NEXT PC after instruction execution
- The instruction fetch address is calculated as `(pc-4)/4`, so changing PC creates mismatch

**Relationship to Other Mutations:**
- **First mutation targeting `cycles[].pc`** - No overlap
- **Related to INSTR_WORD_MOD**: Both affect instruction fetch consistency from different angles

---

### 3.13 CYCLE_STATE_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟡 To Implement (Medium Priority) |
| **File** | `cycle_state_mod.py` (TO CREATE) |
| **Target Field(s)** | `cycles[].state` |
| **Scope** | Any cycle |
| **Expected Constraint Failures** | Cycle state machine constraints |
| **Risk Level** | Medium |

**What It Will Cover:**
- The `state` field which defines the cycle type (Decode, Poseidon, SHA, etc.)
- See Appendix A for state values

**Relationship to Other Mutations:**
- **First mutation targeting `cycles[].state`** - No overlap

---

### 3.14 CYCLE_MODE_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟡 To Implement (Medium Priority) |
| **File** | `cycle_mode_mod.py` (TO CREATE) |
| **Target Field(s)** | `cycles[].machine_mode` |
| **Scope** | Any cycle |
| **Expected Constraint Failures** | Privilege/mode checking constraints |
| **Risk Level** | Low |

**What It Will Cover:**
- The `machine_mode` field (0 = user mode, 1 = machine mode)
- Flipping mode tests privilege separation constraints

**Relationship to Other Mutations:**
- **First mutation targeting `cycles[].machine_mode`** - No overlap

---

### 3.15 CYCLE_INDEX_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟢 To Implement (Low Priority) |
| **File** | `cycle_index_mod.py` (TO CREATE) |
| **Target Field(s)** | `cycles[].txn_idx`, `cycles[].paging_idx`, `cycles[].bigint_idx` |
| **Scope** | Any cycle |
| **Expected Constraint Failures** | Index consistency, structural constraints |
| **Risk Level** | High - likely to crash witness generation |

**What It Will Cover:**
- Index fields that point into other arrays
- Breaking indices likely causes array out-of-bounds or structural inconsistency

**Relationship to Other Mutations:**
- **First mutation targeting index fields** - No overlap

---

### 3.16 CYCLE_DIFF_COUNT_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟢 To Implement (Low Priority) |
| **File** | `cycle_diff_count_mod.py` (TO CREATE) |
| **Target Field(s)** | `cycles[].diff_count` |
| **Scope** | Any cycle |
| **Expected Constraint Failures** | Memory diff tracking constraints |
| **Risk Level** | Medium |

**What It Will Cover:**
- The `diff_count` array used for memory diff tracking

**Relationship to Other Mutations:**
- **First mutation targeting `cycles[].diff_count`** - No overlap

---

### 3.17 REG_TXN_NON_INSN_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟢 To Implement (Low Priority) |
| **File** | `reg_txn_non_insn_mod.py` (TO CREATE) |
| **Target Field(s)** | `txns[].word` |
| **Scope** | Register transactions at non-instruction cycles (major 7+) |
| **Expected Constraint Failures** | Unknown (exploration) |
| **Risk Level** | Low |

**What It Will Cover:**
- Register transactions during control, ECALL, Poseidon, SHA, BigInt cycles
- **GAP**: PRE_EXEC_REG_MOD only targets major 0-6

**What It Will EXCLUDE:**
- Register transactions at instruction cycles (covered by PRE_EXEC_REG_MOD)

**Relationship to Other Mutations:**
- **Fills gap left by PRE_EXEC_REG_MOD**: Extends register transaction coverage to non-instruction cycles
- **Requires verification**: First check if register transactions actually occur at major 7+ cycles

---

### 3.18 BIGINT_DATA_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟢 To Implement (Low Priority) |
| **File** | `bigint_data_mod.py` (TO CREATE) |
| **Target Field(s)** | `bigint_bytes[]` |
| **Scope** | Steps with BigInt operations |
| **Expected Constraint Failures** | BigInt computation constraints |
| **Risk Level** | High |

**What It Will Cover:**
- Raw BigInt computation data

**Relationship to Other Mutations:**
- **First mutation targeting `bigint_bytes[]`** - No overlap

---

### 3.19 CRYPTO_STATE_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟢 To Implement (Low Priority) |
| **File** | `crypto_state_mod.py` (TO CREATE) |
| **Target Field(s)** | `backs[]` (Poseidon2State, Sha2State) |
| **Scope** | Cycles with crypto operations |
| **Expected Constraint Failures** | Hash computation constraints |
| **Risk Level** | High |

**What It Will Cover:**
- Internal state of Poseidon2 and SHA2 hash operations

**Relationship to Other Mutations:**
- **First mutation targeting crypto state** - No overlap

---

### 3.20 ECALL_BACK_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟢 To Implement (Low Priority) |
| **File** | `ecall_back_mod.py` (TO CREATE) |
| **Target Field(s)** | `backs[]` (Ecall variant) |
| **Scope** | Cycles with Ecall operations |
| **Expected Constraint Failures** | Syscall handling constraints |
| **Risk Level** | Medium |

**What It Will Cover:**
- Ecall parameters stored in `Back::Ecall(u32, u32, u32)`

**Relationship to Other Mutations:**
- **First mutation targeting Ecall state** - No overlap

---

### 3.21 STRUCTURAL_MOD (TO IMPLEMENT)

| Property | Value |
|----------|-------|
| **Status** | 🟢 To Implement (Low Priority) |
| **File** | `structural_mod.py` (TO CREATE) |
| **Target Field(s)** | `table_split_cycle`, `rand_z` |
| **Scope** | Trace-level values |
| **Expected Constraint Failures** | Table generation, checksum constraints |
| **Risk Level** | High |

**What It Will Cover:**
- Trace-level structural values that affect table generation

**Relationship to Other Mutations:**
- **First mutation targeting trace-level fields** - No overlap

---

## 4. Complete Variable Coverage Matrix

### 4.1 Transaction Variables (`txns[]`)

| Field | Type | Covered By | Gaps |
|-------|------|------------|------|
| `addr` | u32 | ❌ NONE | TXN_ADDR_MOD |
| `cycle` | u32 | ❌ NONE | TXN_CYCLE_PHASE_MOD |
| `word` | u32 | ✅ Multiple (see §5) | INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR, REG_TXN_NON_INSN_MOD |
| `prev_cycle` | u32 | ❌ NONE | TXN_PREV_CYCLE_MOD |
| `prev_word` | u32 | ❌ NONE | TXN_PREV_WORD_MOD |

### 4.2 Cycle Variables (`cycles[]`)

| Field | Type | Covered By | Gaps |
|-------|------|------------|------|
| `state` | u32 | ❌ NONE | CYCLE_STATE_MOD |
| `pc` | u32 | ❌ NONE | CYCLE_PC_MOD |
| `major` | u8 | ✅ INSTR_TYPE_MOD | Non-instruction cycles (major 7+) |
| `minor` | u8 | ✅ INSTR_TYPE_MOD | Non-instruction cycles (major 7+) |
| `machine_mode` | u8 | ❌ NONE | CYCLE_MODE_MOD |
| `user_cycle` | u32 | ❌ NONE | (limited utility - step counter) |
| `txn_idx` | u32 | ❌ NONE | CYCLE_INDEX_MOD |
| `paging_idx` | u32 | ❌ NONE | CYCLE_INDEX_MOD |
| `bigint_idx` | u32 | ❌ NONE | CYCLE_INDEX_MOD |
| `diff_count` | [u32; 2] | ❌ NONE | CYCLE_DIFF_COUNT_MOD |

### 4.3 Special Data

| Data | Type | Covered By | Gaps |
|------|------|------------|------|
| `bigint_bytes[]` | Vec<u8> | ❌ NONE | BIGINT_DATA_MOD |
| `backs[]` (Poseidon2State) | struct | ❌ NONE | CRYPTO_STATE_MOD |
| `backs[]` (Sha2State) | struct | ❌ NONE | CRYPTO_STATE_MOD |
| `backs[]` (BigIntState) | struct | ❌ NONE | BIGINT_DATA_MOD |
| `backs[]` (Ecall) | tuple | ❌ NONE | ECALL_BACK_MOD |
| `table_split_cycle` | u32 | ❌ NONE | STRUCTURAL_MOD |
| `rand_z` | ExtVal | ❌ NONE | STRUCTURAL_MOD |

---

## 5. `txns[].word` Context Coverage

This section provides complete coverage analysis of the `txns[].word` field across all contexts.

### 5.1 Register Transactions (`txns[].word` at register addresses)

| Context | Covered By | Status |
|---------|------------|--------|
| Register WRITE at compute (major 0-4), last write | COMP_OUT_MOD | ✅ Implemented |
| Register WRITE at compute (major 0-4), any write | PRE_EXEC_REG_MOD (prev_write) | ✅ Implemented |
| Register WRITE at load (major 5), last write | LOAD_VAL_MOD | ✅ Implemented |
| Register WRITE at load (major 5), any write | PRE_EXEC_REG_MOD (prev_write) | ✅ Implemented |
| Register WRITE at store (major 6) | N/A | N/A (stores don't write regs) |
| Register READ at any instruction (major 0-6) | PRE_EXEC_REG_MOD (next_read) | ✅ Implemented |
| Register READ/WRITE at non-instruction (major 7+) | — | ⚠️ **GAP: REG_TXN_NON_INSN_MOD** |

### 5.2 Memory Transactions (`txns[].word` at memory addresses)

| Context | Covered By | Status |
|---------|------------|--------|
| **Instruction Fetch** (first READ at instruction cycle) | INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR | ✅ Implemented |
| Memory READ at load (major 5) | MEM_VAL_MOD (load_mem_read) | ✅ Implemented |
| Memory READ at store (major 6) - RMW read | MEM_VAL_MOD (store_rmw_read) | ✅ Implemented |
| Memory WRITE at store (major 6) - RMW write | STORE_OUT_MOD | ✅ Implemented |
| Memory READ at other cycles (major 7+) | MEM_VAL_MOD (other_mem_read) | ✅ Implemented |
| Memory WRITE at non-store cycles | MEM_VAL_MOD (other_mem_write) | ✅ Implemented |

### 5.3 Exclusion Logic Summary

| Mutation | What It Explicitly Excludes | Why |
|----------|----------------------------|-----|
| MEM_VAL_MOD | Instruction fetch (`_is_instruction_fetch()`) | Covered by INSTR_WORD_MOD_FULL/SUR |
| MEM_VAL_MOD | Store memory writes (`major == 6 && is_write`) | Covered by STORE_OUT_MOD |
| MEM_VAL_MOD | Register transactions (address check) | Covered by PRE_EXEC_REG_MOD |
| PRE_EXEC_REG_MOD | Non-instruction cycles (major 7+) | Different execution context |
| COMP_OUT_MOD | Non-compute instructions (major != 0-4) | Instruction-specific |
| LOAD_VAL_MOD | Non-load instructions (major != 5) | Instruction-specific |
| STORE_OUT_MOD | Non-store instructions (major != 6) | Instruction-specific |

---

## 6. Gap Analysis

### 6.1 `txns[].word` Gaps

| Gap ID | Description | Mutation to Implement | Notes |
|--------|-------------|----------------------|-------|
| GAP-TW-1 | ~~Instruction fetch READ~~ | ~~INSTR_WORD_MOD~~ | ✅ **Implemented as INSTR_WORD_MOD_FULL and INSTR_WORD_MOD_SUR** |
| GAP-TW-2 | Register txns at non-instruction cycles | REG_TXN_NON_INSN_MOD | Verify if any exist first |

### 6.2 Full Field Gaps

| Gap ID | Field | Mutation to Implement |
|--------|-------|----------------------|
| GAP-F-1 | `txns[].addr` | TXN_ADDR_MOD |
| GAP-F-2 | `txns[].cycle` | TXN_CYCLE_PHASE_MOD |
| GAP-F-3 | `txns[].prev_word` | TXN_PREV_WORD_MOD |
| GAP-F-4 | `txns[].prev_cycle` | TXN_PREV_CYCLE_MOD |
| GAP-F-5 | `cycles[].pc` | CYCLE_PC_MOD |
| GAP-F-6 | `cycles[].state` | CYCLE_STATE_MOD |
| GAP-F-7 | `cycles[].machine_mode` | CYCLE_MODE_MOD |
| GAP-F-8 | `cycles[].txn_idx` | CYCLE_INDEX_MOD |
| GAP-F-9 | `cycles[].paging_idx` | CYCLE_INDEX_MOD |
| GAP-F-10 | `cycles[].bigint_idx` | CYCLE_INDEX_MOD |
| GAP-F-11 | `cycles[].diff_count` | CYCLE_DIFF_COUNT_MOD |
| GAP-F-12 | `bigint_bytes[]` | BIGINT_DATA_MOD |
| GAP-F-13 | `backs[]` (Poseidon2State) | CRYPTO_STATE_MOD |
| GAP-F-14 | `backs[]` (Sha2State) | CRYPTO_STATE_MOD |
| GAP-F-15 | `backs[]` (BigIntState) | BIGINT_DATA_MOD |
| GAP-F-16 | `backs[]` (Ecall) | ECALL_BACK_MOD |
| GAP-F-17 | `table_split_cycle` | STRUCTURAL_MOD |
| GAP-F-18 | `rand_z` | STRUCTURAL_MOD |

---

## 7. Implementation Roadmap

### 7.1 Implemented (Ready to Use)

| Mutation | File | Verified | Notes |
|----------|------|----------|-------|
| INSTR_TYPE_MOD | `instr_type_mod.py` | ✅ Yes | |
| COMP_OUT_MOD | `comp_out_mod.py` | ✅ Yes | |
| LOAD_VAL_MOD | `load_val_mod.py` | ✅ Yes | |
| STORE_OUT_MOD | `store_out_mod.py` | ✅ Yes | |
| PRE_EXEC_REG_MOD | `pre_exec_reg_mod.py` | ✅ Yes | |
| MEM_VAL_MOD | `mem_val_mod.py` | ❌ Standalone-only | |
| **INSTR_WORD_MOD_FULL** | `instr_word_mod.py` | ✅ Yes | Full 32-bit word, Arguzz-aligned, valid instructions only |
| **INSTR_WORD_MOD_SUR** | `instr_word_mod_sur.py` | ✅ Yes | Surgical field-level, may produce invalid instructions |

### 7.2 To Implement

| Priority | Mutation | File | Risk | Notes |
|----------|----------|------|------|-------|
| 🔴 High | TXN_PREV_WORD_MOD | `txn_prev_word_mod.py` | Low | Tests IsRead constraint |
| 🔴 High | TXN_PREV_CYCLE_MOD | `txn_prev_cycle_mod.py` | Low | Tests memory ordering |
| 🟡 Medium | TXN_ADDR_MOD | `txn_addr_mod.py` | High | May crash witgen |
| 🟡 Medium | TXN_CYCLE_PHASE_MOD | `txn_cycle_phase_mod.py` | Medium | Flips R/W |
| 🟡 Medium | CYCLE_PC_MOD | `cycle_pc_mod.py` | Medium | Breaks fetch address |
| 🟡 Medium | CYCLE_STATE_MOD | `cycle_state_mod.py` | Medium | Changes cycle type |
| 🟡 Medium | CYCLE_MODE_MOD | `cycle_mode_mod.py` | Low | Flips privilege |
| 🟢 Low | CYCLE_INDEX_MOD | `cycle_index_mod.py` | High | May crash |
| 🟢 Low | CYCLE_DIFF_COUNT_MOD | `cycle_diff_count_mod.py` | Medium | Diff tracking |
| 🟢 Low | REG_TXN_NON_INSN_MOD | `reg_txn_non_insn_mod.py` | Low | Verify existence first |
| 🟢 Low | BIGINT_DATA_MOD | `bigint_data_mod.py` | High | Requires BigInt understanding |
| 🟢 Low | CRYPTO_STATE_MOD | `crypto_state_mod.py` | High | Requires crypto understanding |
| 🟢 Low | ECALL_BACK_MOD | `ecall_back_mod.py` | Medium | Ecall params |
| 🟢 Low | STRUCTURAL_MOD | `structural_mod.py` | High | Trace-level |

**Priority Legend:**
- 🔴 **Highest/High**: Low risk, high value, easy to implement
- 🟡 **Medium**: Moderate risk/value
- 🟢 **Low**: High risk or requires deep investigation

---

## Appendix A: Cycle State Values

From `platform.rs`:

```rust
pub enum CycleState {
    LoadRootAndNonce = 0,
    Resume = 1,
    Suspend = 4,
    StoreRoot = 5,
    ControlTable = 6,
    ControlDone = 7,
    MachineEcall = 8,
    Terminate = 9,
    HostReadSetup = 10,
    HostWrite = 11,
    HostReadBytes = 12,
    HostReadWords = 13,
    PoseidonEntry = 16,
    PoseidonLoadState = 17,
    // ... more Poseidon states ...
    ShaEcall = 32,
    // ... more SHA states ...
    BigIntEcall = 40,
    BigIntStep = 41,
    Decode = 48,  // Normal instruction execution
}
```

---

## Appendix B: Major/Minor Values

From `platform.rs`:

| Major | Name | Instructions |
|-------|------|--------------|
| 0 | MISC0 | Add, Sub, Xor, Or, And, Slt, SltU, AddI |
| 1 | MISC1 | XorI, OrI, AndI, SltI, SltIU, Beq, Bne, Blt |
| 2 | MISC2 | Bge, BltU, BgeU, Jal, JalR, Lui, Auipc |
| 3 | MUL0 | Sll, SllI, Mul, MulH, MulHSU, MulHU |
| 4 | DIV0 | Srl, Sra, SrlI, SraI, Div, DivU, Rem, RemU |
| 5 | MEM0 | Lb, Lh, Lw, LbU, LhU |
| 6 | MEM1 | Sb, Sh, Sw |
| 7 | CONTROL0 | Control/padding |
| 8 | ECALL0 | Ecall operations |
| 9 | POSEIDON0 | Poseidon hash |
| 10 | POSEIDON1 | Poseidon hash |
| 11 | SHA0 | SHA operations |
| 12 | BIGINT0 | BigInt operations |

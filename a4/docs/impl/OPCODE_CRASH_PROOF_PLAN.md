# Opcode Mismatch Crash: 100% Proof Investigation Plan

## Objective

Obtain definitive proof that when `INSTR_WORD_MOD` changes an instruction word's opcode to a different instruction type, the prover crashes (SIGSEGV) during witness generation before any constraint checking occurs.

This proof is essential for:
1. Documenting expected behavior in mutation taxonomy
2. Guiding value generation strategies (opcode-preserving vs opcode-changing)
3. Understanding which mutations produce constraint failures vs crashes
4. Organizing fuzzing function logic around this architectural behavior

---

## Background Summary (from COMEBACK_INVESTIGATION.md)

### The Hypothesis

When INSTR_WORD_MOD mutates an instruction word:

1. **Preflight generation** already recorded `major/minor` based on the ORIGINAL instruction
2. **Witness generation** selects instruction handler based on `major/minor`
3. **Handler reads mutated word** and tries to decode it as the ORIGINAL instruction format
4. **Format mismatch** causes garbage values for register indices, immediates, etc.
5. **Invalid memory access** or out-of-bounds array indexing → SIGSEGV

### Evidence So Far

| Mutated Value | Opcode | Original | Result |
|---------------|--------|----------|--------|
| 0xDEADBEEF | 0x6F (JAL) | 0x23 (STORE) | SIGSEGV (return -11) |
| 0x00000000 | 0x00 (illegal) | 0x23 (STORE) | SIGSEGV (return -11) |
| 0x00000013 | 0x13 (ADDI) | 0x23 (STORE) | SIGSEGV (return -11) |
| 0x00B6A123 | 0x23 (STORE) | 0x23 (STORE) | Constraint failure ✓ |

### Instruction Format Differences (Why Format Mismatch Crashes)

```
R-type: [funct7:7][rs2:5][rs1:5][funct3:3][rd:5][opcode:7]     (ADD, SUB)
I-type: [imm:12][rs1:5][funct3:3][rd:5][opcode:7]              (ADDI, LW)
S-type: [imm:7][rs2:5][rs1:5][funct3:3][imm:5][opcode:7]       (SW, SB)
B-type: [imm:1][imm:6][rs2:5][rs1:5][funct3:3][imm:4][imm:1][opcode:7]  (BEQ, BNE)
U-type: [imm:20][rd:5][opcode:7]                               (LUI, AUIPC)
J-type: [imm:1][imm:10][imm:1][imm:8][rd:5][opcode:7]          (JAL)
```

When a STORE handler (expects S-type) reads a JAL instruction (J-type):
- What handler thinks is `rs2` (bits 20-24) is actually part of JAL's immediate
- Computed memory address = garbage
- Register index may be > 31 → array out of bounds → CRASH

---

## Phase 1: Create Controlled Test Cases

### 1.1 Identify Test Step

Find a step with a well-understood instruction (e.g., STORE at step 100):
- Get the original instruction word
- Identify its format (S-type for stores)
- Record major/minor values

### 1.2 Create Test Mutations

| Test | Original Opcode | Mutated Opcode | Expected Result |
|------|-----------------|----------------|-----------------|
| A | 0x23 (STORE) | 0x23 (STORE) | Constraint failure |
| B | 0x23 (STORE) | 0x6F (JAL) | Crash (SIGSEGV) |
| C | 0x23 (STORE) | 0x13 (ADDI) | Crash (SIGSEGV) |
| D | 0x23 (STORE) | 0x33 (R-type) | Crash (SIGSEGV) |
| E | 0x23 (STORE) | 0x63 (BRANCH) | Crash (SIGSEGV) |

### 1.3 Create Mutation Config Files

```bash
# Test A: Same opcode (should produce constraint failure)
echo '{"mutation_type":"INSTR_WORD_MOD","step":100,"word":VALUE_A}' > /tmp/test_same_opcode.json

# Test B: JAL opcode (should crash)
echo '{"mutation_type":"INSTR_WORD_MOD","step":100,"word":VALUE_B}' > /tmp/test_jal_opcode.json

# etc.
```

---

## Phase 2: GDB Crash Analysis

### 2.1 Setup

```bash
cd /root/arguzz/workspace/output/target/release

# Ensure debug symbols are available (may need debug build)
# If release build, we may still get function names
```

### 2.2 Run Crash Test Under GDB

```bash
# Method 1: Direct GDB
gdb --args ./risc0-host --in1 5 --in4 10
(gdb) set environment A4_MUTATION_CONFIG=/tmp/test_jal_opcode.json
(gdb) set environment CONSTRAINT_CONTINUE=1
(gdb) run
# Wait for SIGSEGV
(gdb) bt full
(gdb) info registers
(gdb) x/10i $pc
```

```bash
# Method 2: GDB batch mode
gdb -batch \
    -ex "set environment A4_MUTATION_CONFIG=/tmp/test_jal_opcode.json" \
    -ex "set environment CONSTRAINT_CONTINUE=1" \
    -ex "run --in1 5 --in4 10" \
    -ex "bt" \
    -ex "info registers" \
    ./risc0-host 2>&1 | tee /tmp/gdb_crash_output.txt
```

### 2.3 Expected GDB Output

We expect to see something like:
```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7abc123 in risc0_circuit_rv32im::zirgen::exec_OpSW ()
    at steps.rs.inc:XXXX

#0  exec_OpSW () at steps.rs.inc:XXXX
#1  exec_top () at ...
#2  witgen_execute () at ...
...
```

### 2.4 Alternative: Analyze Core Dump

```bash
# Enable core dumps
ulimit -c unlimited

# Run crash test
A4_MUTATION_CONFIG=/tmp/test_jal_opcode.json CONSTRAINT_CONTINUE=1 ./risc0-host --in1 5 --in4 10

# Analyze core dump
gdb ./risc0-host core -ex "bt" -ex "quit"
```

---

## Phase 3: Source Code Throughline

### 3.1 Map Crash Location to Source

From GDB backtrace, identify:
1. **Which function crashed** (e.g., `exec_OpSW`, `exec_decoder`)
2. **Which file** (`steps.rs.inc`, `ffi.cpp`)
3. **Line number** (if debug symbols available)

### 3.2 Trace the Path

Document the complete execution path:

```
1. mod.rs: A4 mutation applied
   └─ trace.txns[fetch_idx].word = 0xDEADBEEF (JAL bits)
   └─ trace.txns[fetch_idx].prev_word = 0xDEADBEEF

2. ffi.cpp:getMemoryTxn()
   └─ Returns mutated word to circuit
   └─ word = 0xDEADBEEF

3. steps.rs.inc:exec_decode_inst()
   └─ Calls exec_memory_read() to fetch instruction
   └─ Calls exec_decoder() with mutated word

4. steps.rs.inc:exec_decoder()
   └─ Extracts opcode: 0x6F (JAL)
   └─ Extracts rs1, rs2, rd using ORIGINAL format assumptions
   └─ For S-type handler: rs2 = bits[24:20] = garbage

5. steps.rs.inc:exec_OpSW() [selected based on major=6]
   └─ Reads rs2 value from register file
   └─ rs2 index = garbage (e.g., 47 from JAL immediate bits)
   └─ Array access: regs[47] → OUT OF BOUNDS → SIGSEGV
```

### 3.3 Find Specific Crash Point

Look for array accesses in the handler code:
- Register file accesses (index must be 0-31)
- Memory accesses (address must be valid)
- Any computed index used in array lookup

---

## Phase 4: Verification Tests

### 4.1 Reproducibility

Run each test case 3 times to confirm consistent behavior:

| Test | Run 1 | Run 2 | Run 3 | Consistent? |
|------|-------|-------|-------|-------------|
| A (same opcode) | ? | ? | ? | ? |
| B (JAL) | ? | ? | ? | ? |
| C (ADDI) | ? | ? | ? | ? |
| D (R-type) | ? | ? | ? | ? |
| E (BRANCH) | ? | ? | ? | ? |

### 4.2 Different Instruction Types

Test opcode changes for different original instructions:

| Original Major | Original Type | Mutate To | Result |
|----------------|---------------|-----------|--------|
| 0 (MISC0) | R-type | J-type | ? |
| 1 (MISC1) | B-type | S-type | ? |
| 2 (MISC2) | J-type | R-type | ? |
| 5 (MEM0) | I-type | S-type | ? |
| 6 (MEM1) | S-type | J-type | ? |

### 4.3 Edge Cases

Test mutations that change opcode within same format family:
- STORE (0x23) → LOAD (0x03) - both use register indices similarly
- ADD (0x33) → SUB (0x33) - same opcode, different func7

---

## Phase 5: Documentation

### 5.1 Create Proof Document

Final document structure:

```markdown
# INSTR_WORD_MOD Opcode Mismatch Behavior: Definitive Proof

## Summary
When INSTR_WORD_MOD changes instruction opcode, prover crashes at [LOCATION]
because [REASON].

## Test Results
[Table of all test cases with results]

## GDB Evidence
[Full backtrace from crash]

## Source Code Throughline
[Complete path from mutation to crash]

## Implications for Fuzzing
1. Same-opcode mutations → Constraint failures (useful for testing)
2. Different-opcode mutations → Crashes (valid finding but no constraint info)
3. Value generation should [RECOMMENDATION]
```

### 5.2 Update MUTATION_TAXONOMY.md

Add section on crash behavior:
- Which mutations cause crashes vs constraint failures
- Architectural explanation
- Value generation recommendations

### 5.3 Update INSTR_WORD_MOD Implementation

If needed, add opcode-preserving mutation option.

---

## Execution Checklist

- [ ] Phase 1.1: Identify test step and original instruction
- [ ] Phase 1.2: Calculate mutated values for each test case
- [ ] Phase 1.3: Create mutation config files
- [ ] Phase 2.1: Setup GDB environment
- [ ] Phase 2.2: Run crash test under GDB
- [ ] Phase 2.3: Capture backtrace
- [ ] Phase 3.1: Map crash to source location
- [ ] Phase 3.2: Trace full execution path
- [ ] Phase 3.3: Identify specific crash point
- [ ] Phase 4.1: Verify reproducibility
- [ ] Phase 4.2: Test different instruction types
- [ ] Phase 4.3: Test edge cases
- [ ] Phase 5.1: Create proof document
- [ ] Phase 5.2: Update taxonomy
- [ ] Phase 5.3: Update implementation if needed

---

## Files Referenced

- `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` - A4 mutation hooks
- `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/zirgen/steps.rs.inc` - Circuit handlers
- `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` - FFI layer
- `/root/arguzz/a4/docs/standalone/impl/COMEBACK_INVESTIGATION.md` - Prior investigation

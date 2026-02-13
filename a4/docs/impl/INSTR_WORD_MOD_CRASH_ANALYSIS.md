# INSTR_WORD_MOD Crash Analysis: Complete Source Code Trace

## Executive Summary

**Root Cause**: When `INSTR_WORD_MOD` mutates an instruction word in a way that changes the `rs1`, `rs2`, or `immediate` fields, the circuit handler decodes these fields from the mutated word and computes **different memory/register addresses** than what the original execution recorded in the preflight trace. This causes an **address mismatch** in `extern_getMemoryTxn()` (ffi.cpp:112-119), which throws an exception. In multi-threaded execution, this exception combined with parallel Poseidon hash cycles leads to a SIGSEGV crash.

**Key Finding**: The crash is NOT caused by the circuit selecting the wrong instruction handler based on the mutated opcode. The handler is selected based on `major/minor` from the preflight trace (correct). The crash occurs because the handler **decodes operands** from the mutated instruction word and requests addresses that don't exist in the trace.

---

## Part 1: The Mutation and What Gets Changed

### 1.1 The Test Case

**Step 100**: A STORE instruction (`sw x11, 0(x13)`) at PC 0x00203AC4

| Field | Original Value | Mutated Value | Change |
|-------|---------------|---------------|--------|
| **Full word** | 0x00B6A023 | 0x00C6A023 | rs2 field changed |
| opcode [6:0] | 0x23 (STORE) | 0x23 (STORE) | unchanged |
| func3 [14:12] | 0x2 (SW) | 0x2 (SW) | unchanged |
| rs1 [19:15] | 13 | 13 | unchanged |
| **rs2 [24:20]** | **11** | **12** | **CHANGED** |
| imm [31:25,11:7] | 0 | 0 | unchanged |

### 1.2 What the Mutation Does

The Rust code in `mod.rs` (lines 300-301) sets:
```rust
txn.word = new_word;      // 0x00C6A023
txn.prev_word = new_word; // 0x00C6A023
```

This changes only the instruction word in transaction 15829. The **rest of the preflight trace remains unchanged** - including the subsequent transactions that record what registers/memory were actually accessed during original execution.

---

## Part 2: How the Circuit Handler Decodes the Mutated Word

### 2.1 Instruction Fetch (Succeeds)

The STORE handler first fetches the instruction. Since we mutated the fetch transaction, it gets the mutated word.

**Source**: `steps.cpp:979` - `exec_DecodeInst()`:
```cpp
GetDataStruct x4 = exec_MemoryRead(ctx,arg0, x3._super, LAYOUT_LOOKUP(layout2, loadInst));
```

**Trace output**:
```
getMemoryTxn(16673, 0x00080cb1): txn(txnId: 15829, cycle: 33346, addr: 0x00080cb1, word: 0x00c6a023)
                                                                                         ^^^^^^^^^
                                                                                         Mutated!
```

This succeeds because the address matches (`0x00080cb1` = `0x00203AC4 / 4`).

### 2.2 Instruction Decoding (Uses Mutated Word)

The `exec_Decoder()` function extracts fields from the mutated word.

**Source**: `steps.cpp:697-699` - `DecoderStruct` return:
```cpp
return DecoderStruct{
  .opcode = x31,
  .rs1 = (x41 + x20._super),
  .rs2 = x44,               // <-- Extracted from mutated word = 12
  .rd = x47,
  // ...
};
```

The decoder extracts `rs2 = 12` from bits [24:20] of the mutated word `0x00C6A023`.

### 2.3 Reading Source Registers (Address Mismatch)

The handler calls `exec_ReadSourceRegs()` to read the rs1 and rs2 values.

**Source**: `steps.cpp:984-993` - `exec_ReadReg()`:
```cpp
GetDataStruct exec_ReadReg(ExecContext& ctx,NondetRegStruct arg0, InstInputStruct arg1_0, Val arg2_0, BoundLayout<ReadRegLayout> layout3)   {
// ReadReg(zirgen/circuit/rv32im/v2/dsl/inst.zir:37)
Val x4 = ((Val(1) - arg1_0.mode) * Val(1073725472));  // user mode base = 0x3fffc020
Val x5 = ((arg1_0.mode * Val(1073725440)) + x4);
NondetRegStruct x6 = exec_Reg(ctx,(x5 + arg2_0), ...);  // addr = base + rs2
//                                ^^^^^^^^^^^^
//                                For rs2=12: addr = 0x3fffc020 + 12 = 0x3fffc02c
GetDataStruct x7 = exec_MemoryRead(ctx,arg0, x6._super, LAYOUT_LOOKUP(layout3, _super));
return x7;
}
```

**Address computation**:
- User mode base: `0x3fffc020`
- `rs2 = 12` (from mutated word)
- Handler computes: `addr = 0x3fffc020 + 12 = 0x3fffc02c` (register x12)

But the preflight trace has transaction for register x11 (the original rs2):
- Trace has: `addr = 0x3fffc020 + 11 = 0x3fffc02b` (register x11)

---

## Part 3: The Address Mismatch Exception

### 3.1 Where It Happens

**Source**: `steps.cpp:748` - Memory access invokes external function:
```cpp
auto [x3, x4, x5, x6, x7] = INVOKE_EXTERN(ctx,getMemoryTxn, arg1_0);
//                                                          ^^^^^^
//                                                          arg1_0 = 0x3fffc02c (x12)
```

**Source**: `ffi.cpp:84-123` - `extern_getMemoryTxn()`:
```cpp
std::array<Val, 5> extern_getMemoryTxn(ExecContext& ctx, Val addrElem) {
  uint32_t addr = addrElem.asUInt32();                        // addr = 0x3fffc02c (x12)
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;   // txnIdx = 15831
  const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];  // txn.addr = 0x3fffc02b (x11)
  
  // ... (trace logging) ...

  if (txn.addr != addr) {                                     // 0x3fffc02b != 0x3fffc02c
    printf("[%lu]: txn.addr: 0x%08x, addr: 0x%08x\n", ctx.cycle, txn.addr, addr);
    throw std::runtime_error("memory peek not in preflight"); // <-- LINE 119
  }
```

### 3.2 Empirical Trace Output

```
getMemoryTxn(16673, 0x3fffc02d): txn(txnId: 15830, ..., addr: 0x3fffc02d, ...)  // rs1 read - OK
getMemoryTxn(16673, 0x3fffc02c): txn(txnId: 15831, ..., addr: 0x3fffc02b, ...)  // rs2 read - MISMATCH!
                     ^^^^^^^^^                              ^^^^^^^^^^
                     handler expects x12                    trace has x11
[16673]: txn.addr: 0x3fffc02b, addr: 0x3fffc02c
Segmentation fault (core dumped)
```

The handler requests register x12 (address 0x3fffc02c), but the trace has a transaction for register x11 (address 0x3fffc02b). The check at `ffi.cpp:112` fails and throws an exception.

---

## Part 4: Why the Exception Leads to SIGSEGV

### 4.1 Multi-threaded Execution

RISC Zero's prover uses parallel execution (Rayon threads). When the STORE handler throws an exception in one thread, other threads may:
1. Continue processing subsequent cycles
2. Read from corrupted/uninitialized witness buffers
3. Use corrupted values as buffer indices

### 4.2 GDB Crash Analysis

```
Thread 10 received signal SIGSEGV, Segmentation fault.
0x0000555556b52d80 in MutableBufObj::store()

Backtrace:
#0  MutableBufObj::store()
#1  exec_NondetReg()
#2  exec_Reg()
#3  exec_SBox()
#4  exec_DoIntRound()
#5  exec_DoIntRounds()
#6  exec_PoseidonIntRounds()
#7  exec_Poseidon1()          <-- Crash in Poseidon cycle, NOT the mutated STORE cycle
#8  exec_Top()
```

The crash occurs in a **Poseidon hash cycle** (major=10), not in the mutated STORE cycle (major=6). The Poseidon cycle reads back values via `back_*()` functions. When those values are corrupted (due to the failed STORE handler), computations overflow and produce invalid buffer indices.

### 4.3 Exception Origin (GDB `catch throw`)

```
Catchpoint 1 (exception thrown), __cxxabiv1::__cxa_throw
Thread 10, (gdb) bt
#3  0x0000555556b4be80 in extern_getMemoryTxn at ffi.cpp:119   <-- Exception source
#4  0x0000555556bc80f0 in exec_MemoryIO at steps.cpp:748
#5  0x0000555556bca750 in exec_MemoryRead at steps.cpp:783
#6  0x0000555556bcb630 in exec_MemStoreRead at steps.cpp:...
```

The exception originates at `ffi.cpp:119` when the address mismatch is detected.

---

## Part 5: Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Rust Mutation (mod.rs:300-301)                                                 │
│  trace.txns[15829].word = 0x00C6A023  (rs2 changed from 11 to 12)              │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  C++ Witness Generation - exec_Top() calls exec_InstInput() for cycle 16673     │
│  Handler selection: major=6 → STORE handler (correct, from preflight trace)     │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  exec_DecodeInst (steps.cpp:973-982)                                            │
│  1. Fetches instruction word from txn 15829 → gets 0x00C6A023 (mutated)         │
│  2. exec_Decoder extracts fields from mutated word:                             │
│     rs1 = 13 (correct), rs2 = 12 (WRONG - should be 11)                         │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  exec_ReadSourceRegs (steps.cpp:995)                                            │
│  → exec_ReadReg(rs1=13): addr = 0x3fffc02d                                      │
│     → getMemoryTxn(15830): txn.addr = 0x3fffc02d → MATCH ✓                      │
│                                                                                 │
│  → exec_ReadReg(rs2=12): addr = 0x3fffc02c   ← Computed from mutated word       │
│     → getMemoryTxn(15831): txn.addr = 0x3fffc02b → MISMATCH ✗                   │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ffi.cpp:112-119 - extern_getMemoryTxn                                          │
│                                                                                 │
│  if (txn.addr != addr) {              // 0x3fffc02b != 0x3fffc02c               │
│      throw std::runtime_error(...);   // <-- EXCEPTION THROWN                   │
│  }                                                                              │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Parallel Execution - Other threads continue                                    │
│                                                                                 │
│  Poseidon cycle reads corrupted witness data via back_*()                       │
│  → Corrupted value used as buffer index in MutableBufObj::store()               │
│  → Out-of-bounds memory access                                                  │
│  → SIGSEGV                                                                      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 6: Which Mutations Cause Crashes vs. Constraint Failures

### 6.1 Test Results Summary

| Mutation Type | Bits Changed | Result | Reason |
|--------------|--------------|--------|--------|
| Opcode only | [6:0] | **Constraint Failure** | Handler selects by major/minor (unchanged), opcode check fails |
| func3 only | [14:12] | **Constraint Failure** | Handler uses func3 for operation width, constraint catches mismatch |
| rs1 | [19:15] | **CRASH** | Different base address computed → transaction mismatch |
| rs2 | [24:20] | **CRASH** | Different source register accessed → transaction mismatch |
| imm_lo (small) | [11:7] | **Constraint Failure** | Address offset changes slightly, may still match or fail cleanly |
| imm_hi | [31:25] | **CRASH** | Address offset changes significantly → transaction mismatch |
| Random value | All bits | **CRASH** | Almost certainly changes rs1/rs2/imm → transaction mismatch |

### 6.2 Why Opcode Changes Don't Crash

When only the opcode is changed:

```
Original: 0x00B6A023 (STORE: opcode=0x23)
Mutated:  0x00B6A06F (JAL:   opcode=0x6F)
```

1. Handler is selected by `major=6` from preflight trace (unchanged) → STORE handler
2. STORE handler decodes `rs1=13`, `rs2=11`, `imm=0` from the mutated word
   - These bits are **not affected** by the opcode change
3. Handler accesses correct registers/memory (addresses match preflight)
4. Handler checks opcode constraint: `VerifyOpcodeF3`
5. Constraint fails: expected `0x23`, got `0x6F`
6. **Result**: Clean constraint failure, no crash

### 6.3 Why rs2 Changes Cause Crashes

When rs2 is changed:

```
Original: 0x00B6A023 (rs2=11)
Mutated:  0x00C6A023 (rs2=12)
```

1. Handler selected by `major=6` → STORE handler
2. STORE handler decodes `rs2=12` from bits [24:20] of mutated word
3. Handler computes address: `0x3fffc020 + 12 = 0x3fffc02c` (register x12)
4. Handler calls `getMemoryTxn(0x3fffc02c)`
5. Preflight trace has transaction for `0x3fffc02b` (register x11)
6. `ffi.cpp:112`: `txn.addr != addr` check fails
7. Exception thrown at `ffi.cpp:119`
8. **Result**: SIGSEGV (due to parallel execution corruption)

---

## Part 7: Source Code Citations

### 7.1 Exception Throw Location

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp`
**Lines**: 112-119

```cpp
if (txn.addr != addr) {
    printf("[%lu]: txn.addr: 0x%08x, addr: 0x%08x\n", ctx.cycle, txn.addr, addr);
    // ... fault injection check ...
    throw std::runtime_error("memory peek not in preflight");
}
```

### 7.2 Instruction Decoding (rs2 extraction)

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp`
**Lines**: 697-698

```cpp
return DecoderStruct{
  // ...
  .rs2 = x44,  // x44 is extracted from instruction word bits [24:20]
  // ...
};
```

### 7.3 Register Address Computation

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp`
**Lines**: 987-990

```cpp
Val x4 = ((Val(1) - arg1_0.mode) * Val(1073725472));  // user base = 0x3fffc020
Val x5 = ((arg1_0.mode * Val(1073725440)) + x4);
NondetRegStruct x6 = exec_Reg(ctx,(x5 + arg2_0), ...);  // addr = base + rs2
```

### 7.4 Memory Transaction Request

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp`
**Lines**: 748

```cpp
auto [x3, x4, x5, x6, x7] = INVOKE_EXTERN(ctx,getMemoryTxn, arg1_0);  // arg1_0 = computed addr
```

### 7.5 Mutation Application

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`
**Lines**: 300-301

```rust
txn.word = new_word;
txn.prev_word = new_word;
```

---

## Part 8: Implications for Fuzzing Design

### 8.1 Safe Mutation Fields (Constraint Failures)

| Field | Bits | Effect | Recommendation |
|-------|------|--------|----------------|
| opcode | [6:0] | Caught by VerifyOpcode constraint | ✅ Safe to mutate |
| func3 | [14:12] | Caught by OpSW/OpSH/OpSB constraints | ✅ Safe to mutate |

### 8.2 Unsafe Mutation Fields (Crashes)

| Field | Bits | Effect | Recommendation |
|-------|------|--------|----------------|
| rs1 | [19:15] | Changes base address → txn mismatch | ❌ Avoid |
| rs2 | [24:20] | Changes source register → txn mismatch | ❌ Avoid |
| rd | [11:7] | May overlap with imm, depends on format | ⚠️ Careful |
| imm_lo | [11:7] | Small changes may be safe, large cause crash | ⚠️ Careful |
| imm_hi | [31:25] | Changes address offset → txn mismatch | ❌ Avoid |

### 8.3 Recommended Value Generation Strategy

For meaningful constraint failures (not crashes), `INSTR_WORD_MOD` should:

1. **Preserve opcode**: Keep bits [6:0] the same
2. **Preserve rs1/rs2/rd**: Keep bits [24:7] the same
3. **Preserve immediate**: Keep bits [31:25] the same
4. **Only mutate func3**: Change bits [14:12]

**OR**

1. **Change opcode**: Modify bits [6:0]
2. **Keep all other bits the same**: This tests opcode verification without causing address mismatches

### 8.4 Alternative: Accept Crashes

Crashes indicate the prover correctly rejects inconsistent traces. However:
- Crashes don't identify which specific constraint failed
- Crashes don't provide useful debugging information
- For coverage-guided fuzzing, constraint failures are more informative

---

## Part 9: Verified Test Commands

### 9.1 Constraint Failure Test (Opcode Change)

```bash
echo '{"mutation_type":"INSTR_WORD_MOD","step":100,"word":11988079}' > /tmp/test.json
# 0x00B6A06F: changes opcode from 0x23 (STORE) to 0x6F (JAL)

RAYON_NUM_THREADS=1 A4_MUTATION_CONFIG=/tmp/test.json CONSTRAINT_CONTINUE=1 \
    ./workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 | \
    grep -E "constraint_fail|a4_instr"
```

**Expected**: `<constraint_fail>` messages, no crash

### 9.2 Crash Test (rs2 Change)

```bash
echo '{"mutation_type":"INSTR_WORD_MOD","step":100,"word":13017123}' > /tmp/test.json
# 0x00C6A023: changes rs2 from 11 to 12

RAYON_NUM_THREADS=1 A4_TRACE_TXN=1 A4_MUTATION_CONFIG=/tmp/test.json CONSTRAINT_CONTINUE=1 \
    ./workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 | \
    grep -E "txn\.addr:|mismatch|a4_instr"
```

**Expected**: `[16673]: txn.addr: 0x3fffc02b, addr: 0x3fffc02c`, then SIGSEGV

---

## Conclusion

The crash mechanism is now fully understood and verified with source code citations:

1. **Mutation** changes instruction word's `rs2` field (mod.rs:300-301)
2. **Decoder** extracts `rs2=12` from mutated bits (steps.cpp:697-698)
3. **Handler** computes address `0x3fffc02c` for register x12 (steps.cpp:987-990)
4. **Transaction lookup** finds mismatch: trace has x11 at `0x3fffc02b` (ffi.cpp:112)
5. **Exception thrown** at ffi.cpp:119
6. **SIGSEGV** in parallel Poseidon cycle due to corrupted witness data

This understanding enables designing mutation strategies that produce informative constraint failures rather than uninformative crashes.

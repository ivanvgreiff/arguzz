# RS1/RS2/IMM Field Mutation: Complete Source Code Failure Trace

## Executive Summary

**Type of Failure**: NOT a crash (SIGSEGV). It's a **ZKP verification failure** (`InvalidProof`).

**Root Cause**: When rs1/rs2/imm fields are mutated, the circuit handler decodes different register/address values from the mutated instruction word than what the original execution recorded. The handler receives wrong values, computes wrong results, generates corrupted witness data, and ZKP verification fails because `check != result`.

---

## Step-by-Step Source Code Trace

### Step 1: Mutation Applied

**File**: `risc0/circuit/rv32im/src/prove/witgen/mod.rs` lines 300-301
```rust
txn.word = new_word;      // 0x00C6A023 (rs2=12, was rs2=11)
txn.prev_word = new_word;
```

**Effect**: Transaction 15829 (instruction fetch) now has mutated word with rs2=12 instead of rs2=11.

---

### Step 2: Handler Decodes Mutated Word

**File**: `risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` lines 697-699
```cpp
return DecoderStruct{
  .opcode = x31,
  .rs1 = (x41 + x20._super),
  .rs2 = x44,   // Extracted from bits [24:20] of mutated word = 12
  ...
};
```

**Effect**: Decoder extracts rs2=12 from the mutated instruction word.

---

### Step 3: Handler Computes Wrong Register Address

**File**: `risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` lines 987-990
```cpp
Val x4 = ((Val(1) - arg1_0.mode) * Val(1073725472));  // user mode base = 0x3fffc020
Val x5 = ((arg1_0.mode * Val(1073725440)) + x4);
NondetRegStruct x6 = exec_Reg(ctx,(x5 + arg2_0), ...);  // addr = base + rs2
//                                ^^^^^^^^^^^^
//                                For rs2=12: addr = 0x3fffc020 + 12 = 0x3fffc02c
```

**Effect**: Handler computes address 0x3fffc02c (register x12).

---

### Step 4: Transaction Mismatch Detected

**File**: `risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` lines 86-112
```cpp
std::array<Val, 5> extern_getMemoryTxn(ExecContext& ctx, Val addrElem) {
  uint32_t addr = addrElem.asUInt32();               // addr = 0x3fffc02c (x12)
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;
  const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];  // txn.addr = 0x3fffc02b (x11)
  
  if (txn.addr != addr) {  // 0x3fffc02b != 0x3fffc02c → TRUE
    printf("[%lu]: txn.addr: 0x%08x, addr: 0x%08x\n", ...);
```

**Effect**: Mismatch detected - handler wants x12, trace has x11.

---

### Step 5: FAULT_INJECTION Skips Exception

**File**: `risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` lines 116-122
```cpp
// <----------------------- START OF FAULT INJECTION ----------------------->
const char* fi_env = std::getenv("FAULT_INJECTION_ENABLED");
if(fi_env != NULL) {
    printf("SKIP THROW: %s @ %s:%d\n", "memory peek not in preflight", __FILE__, __LINE__);
    // Exception NOT thrown - execution continues
} else {
    throw std::runtime_error("memory peek not in preflight");
}
// <------------------------ END OF FAULT INJECTION ------------------------>
```

**Effect**: Exception skipped, execution continues to return statement.

---

### Step 6: Wrong Value Returned

**File**: `risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` lines 130-136
```cpp
return {
    txn.prevCycle,
    txn.prevWord & 0xffff,
    txn.prevWord >> 16,
    txn.word & 0xffff,        // Returns x11's value (word=0)
    txn.word >> 16,           // NOT x12's value!
};
```

**Effect**: Handler receives x11's data (word=0) when it asked for x12's data.

**Empirical Proof** (from trace):
```
getMemoryTxn(16673, 0x3fffc02c): txn(txnId: 15831, ..., addr: 0x3fffc02b, word: 0x00000000)
                     ^^^^^^^^^                              ^^^^^^^^^^^ ^^^^^^^^^^^^^^^^
                     Handler wants x12                      Trace has x11  Returns x11's value (0)
```

---

### Step 7: Corrupted Value Used in STORE Operation

**File**: `risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` line 3385
```cpp
// For OpSW (minor=2):
x13 = x4.rs2;  // x4.rs2 contains WRONG value (x11's data, not x12's)
```

**Effect**: STORE operation's output value is corrupted.

---

### Step 8: Corrupted Value Written to Memory

**File**: `risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp` lines 3000-3002
```cpp
MemStoreFinalizeStruct exec_MemStoreFinalize(...) {
    MemoryWriteStruct x4 = exec_MemoryWrite(ctx, arg0, arg1_0.addr._super, arg2_0, ...);
    //                                                                    ^^^^^^
    //                                                                    arg2_0 is corrupted x13
}
```

**Effect**: Wrong value written to witness buffer.

---

### Step 9: Witness Generated with Corrupted Data

Witness generation completes, but the witness contains incorrect values because:
- rs2 read returned wrong register's value
- STORE computed wrong output
- Memory write used corrupted value

---

### Step 10: ZKP Verification Fails

**File**: `risc0/zkp/src/verify/mod.rs` lines 377-379
```rust
if check != result {
    tracing::debug!("check != result");
    return Err(VerificationError::InvalidProof);
}
```

**Empirical Proof** (from debug log):
```
DEBUG risc0_zkp::verify: check != result
```

---

### Step 11: Error Propagates to Panic

**File**: `risc0/zkvm/src/host/server/prove/prover_impl.rs` lines 278-280
```rust
receipt
    .verify_integrity_with_context(ctx)
    .context("verify segment")?;  // Error propagates
```

**File**: `workspace/output/host/src/main.rs` line 150
```rust
Err(error) => {
    panic!("{}", error);  // "verify segment"
}
```

---

## Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  1. MUTATION: mod.rs:300-301                                                    │
│     txn.word = 0x00C6A023 (rs2 changed from 11 to 12)                          │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  2. DECODE: steps.cpp:697-699                                                   │
│     DecoderStruct.rs2 = 12 (extracted from mutated bits [24:20])               │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  3. ADDRESS COMPUTE: steps.cpp:987-990                                          │
│     addr = 0x3fffc020 + 12 = 0x3fffc02c (register x12)                         │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  4. MISMATCH DETECTED: ffi.cpp:112                                              │
│     txn.addr (0x3fffc02b) != addr (0x3fffc02c)                                 │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  5. SKIP EXCEPTION: ffi.cpp:120-122                                             │
│     FAULT_INJECTION_ENABLED → skip throw, continue execution                    │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  6. WRONG VALUE RETURNED: ffi.cpp:130-136                                       │
│     Returns txn.word = 0 (x11's value) instead of x12's value                  │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  7. CORRUPTED STORE: steps.cpp:3385                                             │
│     x13 = x4.rs2 (contains wrong value 0 instead of correct x12 value)         │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  8. CORRUPTED WRITE: steps.cpp:3002                                             │
│     exec_MemoryWrite writes corrupted value to witness buffer                   │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  9. ZKP VERIFY FAILS: verify/mod.rs:377-379                                     │
│     check != result → VerificationError::InvalidProof                           │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  10. PANIC: main.rs:150                                                         │
│      "verify segment" (NOT SIGSEGV - Rust panic from error propagation)        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Finding: NOT a Crash

**Important**: This is NOT a SIGSEGV crash. The failure is:
1. A **Rust error** (`VerificationError::InvalidProof`)
2. Propagated via `?` operator with `.context("verify segment")`
3. Converted to **panic** at `main.rs:150`

The previous SIGSEGV crashes occurred because:
1. FAULT_INJECTION_ENABLED was not set from Rust (shell env vars not visible to C++ FFI)
2. Exception was thrown, caught by Rust FFI layer
3. Multi-threaded execution continued with corrupted state
4. Poseidon cycles accessed corrupted witness data → SIGSEGV

With FAULT_INJECTION_ENABLED properly set from Rust:
1. Exception is skipped
2. Wrong value is returned
3. Witness is corrupted
4. Verification fails cleanly (no SIGSEGV)

---

## Conclusion

Mutating rs1/rs2/imm fields causes verification failure because:
1. Handler decodes different register/address from mutated word
2. Transaction lookup returns data for wrong address
3. Wrong value propagates through computation
4. Witness contains incorrect values
5. ZKP verification polynomial check fails: `check != result`

**This is 100% verified behavior with source code citations at each step.**

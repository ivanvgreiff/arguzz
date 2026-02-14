# Modifications to RISC Zero Source Code

This document tracks all modifications made to the RISC Zero zkVM source code for A4 fuzzing support. Environment variables that are read **only by Python tests** (e.g. Phase 0.1 determinism test: `A4_TEST_HOST`, `A4_TEST_HOST_ARGS`, `A4_TEST_CONFIG`) are **not** listed here; see [README.md](./README.md) section "Test / development environment variables".

## 1. ffi.cpp - Transaction Tracing and Fault Injection

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp`

### 1.1 A4_TRACE_TXN Debug Output (Lines 88-97)

**Added by**: A4 investigation
**Purpose**: Trace transaction access during witness generation

```cpp
if (std::getenv("A4_TRACE_TXN") != NULL) {
    printf("getMemoryTxn(%lu, 0x%08x): txn(txnId: %zu, cycle: %u, addr: 0x%08x, word: 0x%08x)\n",
           ctx.cycle, addr, txnIdx, txn.cycle, txn.addr, txn.word);
    fflush(stdout);
}
```

**Usage**: `A4_TRACE_TXN=1 ./risc0-host ...`

### 1.2 Debug Output for FAULT_INJECTION_ENABLED (Lines 117-120)

**Added by**: A4 investigation (2026-02-10)
**Purpose**: Debug why FAULT_INJECTION_ENABLED wasn't working from shell

```cpp
const char* fi_env = std::getenv("FAULT_INJECTION_ENABLED");
printf("[DEBUG] FAULT_INJECTION_ENABLED = %s\n", fi_env ? fi_env : "NULL");
fflush(stdout);
```

**Note**: This debug code can be removed once investigation is complete.

**Finding**: Discovered that shell env vars are NOT visible to C++ FFI code. Must be set from Rust using `std::env::set_var()`.

### 1.3 FAULT_INJECTION_ENABLED Logic (Lines 103-121, 115-125)

**Added by**: Arguzz (original)
**Purpose**: Skip exception throws on address/cycle mismatches

```cpp
// <----------------------- START OF FAULT INJECTION ----------------------->
if(std::getenv("FAULT_INJECTION_ENABLED") != NULL) {
    printf("SKIP THROW: %s @ %s:%d\n", "memory peek not in preflight", __FILE__, __LINE__);
} else {
    throw std::runtime_error("memory peek not in preflight");
}
// <------------------------ END OF FAULT INJECTION ------------------------>
```

**Important**: Shell environment variables are NOT visible to the C++ FFI code. The variable must be set from Rust using `std::env::set_var()`.

---

## 2. mod.rs - A4 Preflight Mutation and Inspection

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`

### 2.1 A4 Inspection Output (Lines ~67-186)

**Added by**: A4
**Purpose**: Dump cycle and transaction data for analysis

Controlled by environment variables:
- `A4_INSPECT=1` - Enable inspection output
- `A4_DUMP_STEP=N` - Dump transactions at specific step
- `A4_DUMP_TXN=N` - Dump specific transaction
- `A4_DUMP_REG_TXNS=1` - Dump all register transactions
- `A4_DUMP_ALL_TXNS=1` - Dump all transactions with step info

### 2.2 A4 Mutation Config Processing (Lines ~189-450+)

**Added by**: A4
**Purpose**: Apply mutations to preflight trace based on JSON config

Controlled by: `A4_MUTATION_CONFIG=/path/to/config.json`

Supported mutation types:
- `INSTR_TYPE_MOD` - Mutate cycles[].major/minor
- `INSTR_WORD_MOD` - Mutate instruction fetch word
- `COMP_OUT_MOD` - Mutate computation output
- `LOAD_VAL_MOD` - Mutate load value
- `STORE_OUT_MOD` - Mutate store output
- `PRE_EXEC_REG_MOD` - Mutate register read/write
- `MEM_VAL_MOD` - Mutate memory read/write

### 2.3 Automatic FAULT_INJECTION_ENABLED (Lines ~219-225)

**Added by**: A4 investigation (this session)
**Purpose**: Automatically enable fault injection when A4 mutation config is present

```rust
if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
    // Enable fault injection to skip throws on address mismatches
    if std::env::var("A4_NO_FAULT_INJECTION").is_err() {
        unsafe { std::env::set_var("FAULT_INJECTION_ENABLED", "1"); }
        println!("<a4_fault_injection_enabled/>");
    }
    // ...
}
```

**Important**: This is required because shell environment variables are not visible to C++ FFI code. Setting from Rust makes them visible.

---

## 3. witgen.h - Constraint Continue Mode

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h`

### 3.1 CONSTRAINT_CONTINUE Mode (Lines ~188-192)

**Added by**: Arguzz (original), modified for A4
**Purpose**: Continue execution after constraint failures instead of throwing

```cpp
// <---- PHASE 2: CONSTRAINT CONTINUE MODE ---->
if (std::getenv("CONSTRAINT_CONTINUE") != NULL) {
    return;  // Continue to next constraint
}
// <---- END PHASE 2 ---->
```

**Usage**: `CONSTRAINT_CONTINUE=1 ./risc0-host ...`

**Note**: This only affects `eqz()` constraint failures. Address mismatch exceptions in ffi.cpp are handled separately by `FAULT_INJECTION_ENABLED`.

---

## 4. Environment Variable Summary

| Variable | Scope | Purpose | Where Set |
|----------|-------|---------|-----------|
| `A4_TRACE_TXN` | C++ ffi.cpp | Trace transaction access | Shell |
| `A4_INSPECT` | Rust mod.rs | Enable inspection output | Shell |
| `A4_DUMP_*` | Rust mod.rs | Various dump controls | Shell |
| `A4_MUTATION_CONFIG` | Rust mod.rs | Path to mutation JSON | Shell |
| `A4_NO_FAULT_INJECTION` | Rust mod.rs | Disable auto fault injection | Shell |
| `FAULT_INJECTION_ENABLED` | C++ various | Skip throws on mismatches | **Must be set from Rust** |
| `CONSTRAINT_CONTINUE` | C++ witgen.h | Continue after eqz failures | Shell |
| `RISC0_WITGEN_DEBUG` | Rust hal/mod.rs | Force sequential execution | Shell (requires feature) |

---

## 5. Critical Finding: Environment Variable Visibility

**Problem Discovered**: Shell environment variables are visible to Rust code but NOT to C++ FFI code when set only from shell.

**Solution**: Set variables from Rust using `std::env::set_var()` before FFI calls.

**Example from fuzzer_utils/src/lib.rs**:
```rust
pub fn set_injection(value: bool) {
    // ...
    if value {
        unsafe { std::env::set_var("FAULT_INJECTION_ENABLED", "1"); }
    }
}
```

**Why A4_TRACE_TXN works from shell**: It's checked early in the transaction access path before any errors occur. FAULT_INJECTION_ENABLED is checked later when an error is detected, and by then something may have changed.

---

## 6. Crash vs. Continue Behavior

With the modifications:

1. **Without FAULT_INJECTION_ENABLED**: Transaction address mismatch → `std::runtime_error` thrown → Rust catches → Panic "witness generation failure"

2. **With FAULT_INJECTION_ENABLED (from Rust)**: Transaction address mismatch → Exception skipped → Witness generation continues with corrupted data → Verification fails → Panic "verify segment"

3. **With CONSTRAINT_CONTINUE**: `eqz()` constraint failures are logged but execution continues → More failures may be detected

---

## 7. Sequential Execution Mode for A4

**File**: `risc0/circuit/rv32im/src/prove/hal/mod.rs`

**Problem**: Parallel witness generation causes SIGSEGV when A4 mutations corrupt transaction data, because other threads continue processing corrupted values.

**Solution**: Force sequential mode (`StepMode::SeqForward`) when `A4_MUTATION_CONFIG` is detected.

**Code Change** (lines ~146-156):
```rust
// A4: Force sequential mode when A4_MUTATION_CONFIG is set to avoid SIGSEGV
let mode = if std::env::var_os("A4_MUTATION_CONFIG").is_some() {
    StepMode::SeqForward
} else {
    cfg_if::cfg_if! {
        if #[cfg(feature = "witgen_debug")] {
            if std::env::var_os("RISC0_WITGEN_DEBUG").is_some() {
                StepMode::SeqForward
            } else {
                StepMode::Parallel
            }
        } else {
            StepMode::Parallel
        }
    }
};
```

**Note**: This change requires manual editing (not via patch), because it's in a different file.

---

## 8. Files Modified (Summary)

| File | Lines Changed | Purpose |
|------|--------------|---------|
| `ffi.cpp` | ~88-97, ~115-125 | A4 tracing + debug |
| `mod.rs` | ~67-450+ | A4 inspection + mutation |
| `hal/mod.rs` | ~146-156 | Force sequential mode for A4 |
| `witgen.h` | ~188-192 | Constraint continue mode (Arguzz) |

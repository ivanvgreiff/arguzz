# INSTR_WORD_MOD Crash Fix Report

## Problem

INSTR_WORD_MOD mutations caused SIGSEGV crashes when mutating instruction words. No constraint failures were captured, making the fuzzer useless for this mutation type.

## Root Cause

Shell environment variables (like `FAULT_INJECTION_ENABLED=1`) are **NOT visible to C++ FFI code** when the Rust process calls into native libraries.

When the C++ code in `ffi.cpp` checked `std::getenv("FAULT_INJECTION_ENABLED")`, it returned `NULL` even though the shell had set the variable.

## The Fix

**File**: `risc0/circuit/rv32im/src/prove/witgen/mod.rs`
**Lines**: ~219-225

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

This sets `FAULT_INJECTION_ENABLED` from **Rust code** using `std::env::set_var()`, which makes it visible to the C++ FFI layer.

## Results After Fix

### Before Fix:
```
[1/10] SIGSEGV (exit code -11)
[2/10] SIGSEGV (exit code -11)
...
Total mutations: 0
Constraint failures: 0
```

### After Fix:
```
[1] ⚡ INSTR_WORD_MOD @ step 393: 4 failures, outcome: WITNESS_FAIL
    Constraints hit: IsRead@mem.zir:80, MemoryWrite@mem.zir:99,100, VerifyOpcode@inst.zir:91
[2] ⚡ INSTR_WORD_MOD @ step 296: 3 failures, outcome: WITNESS_FAIL
    Constraints hit: MemoryWrite@mem.zir:99, VerifyOpcodeF3@inst.zir:96,97
...
Total mutations: 19
Constraint failures: 74
Unique constraints: 14
```

## Why This Works

1. **FAULT_INJECTION_ENABLED** is now visible to `ffi.cpp:116`
2. When transaction address mismatch is detected (e.g., handler wants x12 but trace has x11)
3. Instead of throwing `std::runtime_error` (which caused chaos in multi-threaded execution)
4. Execution continues, returning the "wrong" value
5. Witness generation completes with corrupted data
6. ZKP verification fails with `InvalidProof`
7. **But we capture all constraint failures that occurred during witness generation!**

## Constraint Types Now Captured

| Constraint | Source File | Description |
|------------|-------------|-------------|
| VerifyOpcodeF3 | inst.zir:96,97 | Opcode and func3 verification |
| VerifyOpcode | inst.zir:91 | Basic opcode verification |
| MemoryWrite | mem.zir:99,100 | Memory write consistency |
| IsRead | mem.zir:79,80 | Memory read consistency |
| OpSW | inst_mem.zir:160,161 | Store word operation constraints |
| OpLW | inst_mem.zir:108 | Load word operation constraints |
| DecodeInst | inst.zir:29 | Instruction decoding constraints |

## Conclusion

The fix enables meaningful fuzzing with `INSTR_WORD_MOD`:
- No more crashes
- Constraint failures are captured
- Coverage can be tracked
- Random mutations across all instruction bits work

**No need for "safe" rs1/rs2/imm mutations** - the random mutations already provide good constraint coverage now that crashes are fixed.

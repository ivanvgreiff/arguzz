# A4 Standalone Fuzzing - Complete Guide

This document contains everything needed to clone this repository on another machine and run A4 standalone fuzzing campaigns without crashes.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites & Setup](#prerequisites--setup)
3. [Running Fuzzing Campaigns](#running-fuzzing-campaigns)
4. [Supported Mutation Types](#supported-mutation-types)
5. [Environment Variables Reference](#environment-variables-reference)
6. [RISC Zero Modifications](#risc-zero-modifications)
7. [Critical Technical Details](#critical-technical-details)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# From repo root
cd /root/arguzz

# 1. Apply A4 patches to RISC Zero (REQUIRED)
python3 -m a4.injection.inject --risc0-path ./workspace/risc0-modified

# 2. Build RISC Zero with patches
cd workspace/output && cargo build --release
cd ../..

# 3. Run a fuzzing campaign
python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --num 10 \
    --kind INSTR_WORD_MOD \
    -- --in1 5 --in4 10
```

---

## Prerequisites & Setup

### Initial Clone

```bash
git clone <repo-url> arguzz
cd arguzz
```

### Python Environment

```bash
# Recommended: Use conda or venv
conda create -n arguzz python=3.10
conda activate arguzz

# No external Python dependencies required - uses stdlib only
```

### RISC Zero Build

```bash
# Navigate to the RISC Zero workspace
cd workspace/output

# Build in release mode (required for fuzzing)
cargo build --release

# The host binary will be at:
# ./target/release/risc0-host
```

### Apply A4 Patches (CRITICAL)

The A4 patches inject mutation and inspection hooks into the RISC Zero source code. **This must be done before building.**

```bash
cd /root/arguzz

# Check if patches are applied
python3 -m a4.injection.inject --risc0-path ./workspace/risc0-modified --check

# Apply patches (if not already applied)
python3 -m a4.injection.inject --risc0-path ./workspace/risc0-modified

# Rebuild RISC Zero after patching
cd workspace/output && cargo build --release
```

#### What Gets Patched

| File | Purpose |
|------|---------|
| `risc0/circuit/rv32im/src/prove/witgen/mod.rs` | A4 inspection output + mutation handlers + **FAULT_INJECTION_ENABLED auto-enable** |

---

## Running Fuzzing Campaigns

### Basic Fuzzing Command

```bash
python -m a4.standalone.cli fuzz \
    --host <path-to-risc0-host> \
    --num <number-of-mutations> \
    --kind <mutation-type> \
    -- <host-args>
```

### Examples

```bash
# Run 20 INSTR_WORD_MOD mutations
python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --num 20 \
    --kind INSTR_WORD_MOD \
    -- --in1 5 --in4 10

# Run all mutation types
python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --num 50 \
    --kind all \
    -- --in1 5 --in4 10

# With specific seed (for reproducibility)
python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --num 20 \
    --kind COMP_OUT_MOD \
    --seed 12345 \
    -- --in1 5 --in4 10
```

### CLI Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--host` | Path to risc0-host binary | Required |
| `--num` | Number of mutations to run | 10 |
| `--kind` | Mutation type (see below) | "all" |
| `--seed` | Random seed for reproducibility | random |
| `--db` | Path to coverage database | `a4_coverage.db` |
| `--selector` | Step selection strategy | "random" |
| `--values` | Value generation strategy | "mixed" |
| `--` | Separator for host arguments | Required if host has args |

### Inspection Only

```bash
# Just run inspection without mutations
python -m a4.standalone.cli inspect \
    --host ./workspace/output/target/release/risc0-host \
    -- --in1 5 --in4 10
```

---

## Supported Mutation Types

| Kind | Target | Description |
|------|--------|-------------|
| `COMP_OUT_MOD` | `txns[].word` | Mutate register write after compute instructions (ADD, SUB, etc.) |
| `LOAD_VAL_MOD` | `txns[].word` | Mutate register write after load instructions (LW, LH, etc.) |
| `STORE_OUT_MOD` | `txns[].word` | Mutate memory write after store instructions (SW, SH, etc.) |
| `PRE_EXEC_REG_MOD` | `txns[].word` | Mutate register read before instruction execution |
| `INSTR_TYPE_MOD` | `cycles[].major/minor` | Mutate instruction type classification |
| `MEM_VAL_MOD` | `txns[].word` | Mutate memory transactions (non-register, non-instruction) |
| `INSTR_WORD_MOD` | `txns[].word + prev_word` | **Mutate instruction fetch word** |

### Use `--kind all` to run all mutation types randomly.

---

## Environment Variables Reference

### Inspection Variables (set by A4 automatically)

| Variable | Purpose | Set By |
|----------|---------|--------|
| `A4_INSPECT=1` | Enable preflight trace inspection output | A4 Python |
| `A4_DUMP_STEP=N` | Dump transactions for specific step | Manual |
| `A4_DUMP_TXN=N` | Dump specific transaction by index | Manual |
| `A4_DUMP_REG_TXNS=1` | Dump all register transactions | Manual |
| `A4_DUMP_ALL_TXNS=1` | Dump all transactions with step info | A4 Python |

### Mutation Variables

| Variable | Purpose | Set By |
|----------|---------|--------|
| `A4_MUTATION_CONFIG=/path` | Path to JSON mutation config | A4 Python |
| `A4_NO_FAULT_INJECTION=1` | Disable auto fault injection | Manual |

### Critical Execution Variables

| Variable | Purpose | Set By |
|----------|---------|--------|
| `FAULT_INJECTION_ENABLED=1` | **Skip throws on address mismatches** | **Auto (Rust)** |
| `CONSTRAINT_CONTINUE=1` | Continue after constraint failures | Python executor |
| `A4_TRACE_TXN=1` | Trace transaction access (debug) | Shell |

### ⚠️ CRITICAL: Sequential Execution Mode

**A4 automatically forces sequential witness generation when `A4_MUTATION_CONFIG` is set.**

Without sequential mode, parallel thread corruption causes intermittent SIGSEGV crashes. The fix is in `hal/mod.rs`:

```rust
// Lines ~146-156 in hal/mod.rs
let mode = if std::env::var_os("A4_MUTATION_CONFIG").is_some() {
    StepMode::SeqForward  // Force sequential for A4
} else {
    // Original parallel mode for non-A4 runs
    StepMode::Parallel
};
```

### ⚠️ CRITICAL: FAULT_INJECTION_ENABLED

**This is automatically set by the A4 Rust code when `A4_MUTATION_CONFIG` is detected.**

Setting it from shell does NOT work because shell environment variables are not visible to C++ FFI code. The fix is in `mod.rs`:

```rust
// Lines ~219-225 in mod.rs
if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
    if std::env::var("A4_NO_FAULT_INJECTION").is_err() {
        unsafe { std::env::set_var("FAULT_INJECTION_ENABLED", "1"); }
    }
    // ...
}
```

**Without FAULT_INJECTION, address mismatch exceptions would crash the witness generator.**

---

## RISC Zero Modifications

### Files Modified

| File | Purpose |
|------|---------|
| `risc0/circuit/rv32im/src/prove/witgen/mod.rs` | A4 hooks (via patch) |
| `risc0/circuit/rv32im/src/prove/hal/mod.rs` | Sequential mode for A4 (manual) |
| `risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | Fault injection (Arguzz) + A4 debug |
| `risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` | Constraint continue mode (Arguzz) |

### mod.rs Changes (Applied via a4/injection/patches/)

1. **Inspection hooks** (`A4_INSPECT`, `A4_DUMP_*`)
2. **Mutation handlers** (INSTR_TYPE_MOD, INSTR_WORD_MOD, COMP_OUT_MOD, etc.)
3. **Auto FAULT_INJECTION_ENABLED** (critical for crash prevention)

### ffi.cpp Changes (Already in repo)

```cpp
// Lines 88-97: A4 transaction tracing
if (std::getenv("A4_TRACE_TXN") != NULL) {
    printf("getMemoryTxn(%lu, 0x%08x): ...\n", ...);
}

// Lines 103-108, 116-126: FAULT_INJECTION_ENABLED (Arguzz original)
if(std::getenv("FAULT_INJECTION_ENABLED") != NULL) {
    printf("SKIP THROW: %s @ %s:%d\n", ...);
    // Don't throw - continue execution
} else {
    throw std::runtime_error("...");
}
```

### witgen.h Changes (Already in repo)

```cpp
// Lines ~178-197: Constraint failure tracing and CONSTRAINT_CONTINUE
void eqz(ExecContext& ctx, Val a, const char* loc) {
    if (a.asUInt32()) {
        // Print constraint failure details
        printf("<constraint_fail>{...}</constraint_fail>\n");
        
        // CONSTRAINT_CONTINUE mode
        if (std::getenv("CONSTRAINT_CONTINUE") != NULL) {
            return;  // Don't throw, continue
        }
        throw std::runtime_error("eqz failure");
    }
}
```

---

## Critical Technical Details

### Why Crashes Happened (and How We Fixed Them)

**Problem**: `INSTR_WORD_MOD` mutations caused SIGSEGV crashes instead of useful constraint failures.

**Root Cause**: When instruction words are mutated, the circuit handler tries to access registers/memory addresses that don't match the recorded trace. The `ffi.cpp` code throws `std::runtime_error` on mismatch, which in parallel execution caused chaos and SIGSEGV.

**Solution**: `FAULT_INJECTION_ENABLED` skips the throw, allowing execution to continue with corrupted data. The proof verification then fails with `InvalidProof` (expected behavior), and we capture constraint failures along the way.

**Critical Discovery**: Shell environment variables (like `FAULT_INJECTION_ENABLED=1` set in bash) are NOT visible to C++ FFI code. The variable must be set from Rust using `std::env::set_var()`.

### Before vs After Fix

| Before Fix | After Fix |
|------------|-----------|
| SIGSEGV crashes | No crashes |
| 0 constraint failures captured | 70+ constraint failures captured |
| Process dies unexpectedly | Process completes with `InvalidProof` |

### Outcome Types

| Outcome | Meaning |
|---------|---------|
| `WITNESS_FAIL` | Witness generation completed but proof verification failed (`InvalidProof`) |
| `CONSTRAINT_FAIL` | Constraint failures detected during witness generation |
| `NO_EFFECT` | Mutation had no detectable effect |
| `ACCEPTED` | **BUG!** Verifier accepted mutated proof |

---

## Troubleshooting

### "No valid steps for INSTR_WORD_MOD"

**Cause**: Inspection data not collected properly.

**Fix**: Ensure A4 patches are applied and RISC Zero is rebuilt:
```bash
python3 -m a4.injection.inject --risc0-path ./workspace/risc0-modified --check
cd workspace/output && cargo build --release
```

### SIGSEGV Crashes

**Cause**: `FAULT_INJECTION_ENABLED` not being set properly.

**Fix**: Ensure you're using the patched `mod.rs` that automatically sets `FAULT_INJECTION_ENABLED`:
```bash
python3 -m a4.injection.inject --risc0-path ./workspace/risc0-modified
cd workspace/output && cargo build --release
```

### "memory peek not in preflight" Error

**Cause**: `FAULT_INJECTION_ENABLED` not reaching C++ FFI.

**Fix**: This should be auto-fixed by the patched `mod.rs`. If you see this error, re-apply patches and rebuild.

### Constraint Failures Show But Campaign Reports 0

**Cause**: Output parsing issue.

**Fix**: Check that the host binary outputs `<constraint_fail>` tags properly. The `witgen.h` patch should ensure this.

---

## Implementation Status

| Feature | Status |
|---------|--------|
| INSTR_WORD_MOD | ✅ Working (with FAULT_INJECTION fix) |
| COMP_OUT_MOD | ✅ Working |
| LOAD_VAL_MOD | ✅ Working |
| STORE_OUT_MOD | ✅ Working |
| PRE_EXEC_REG_MOD | ✅ Working |
| INSTR_TYPE_MOD | ✅ Working |
| MEM_VAL_MOD | ✅ Working |
| Coverage tracking | ✅ SQLite database |
| Bug detection | ✅ Verifier acceptance check |

---

## File Structure

```
a4/
├── standalone/
│   ├── cli.py                 # Main CLI entry point
│   ├── fuzzer.py              # Fuzzing orchestrator
│   ├── coverage_db.py         # SQLite coverage tracking
│   ├── step_selector.py       # Step selection strategies
│   ├── value_generator.py     # Mutation value generation
│   └── mutations/             # Per-mutation-type handlers
│       ├── instr_word_mod.py  # INSTR_WORD_MOD
│       ├── comp_out_mod.py    # COMP_OUT_MOD
│       └── ...
├── injection/
│   ├── inject.py              # Patch injection system
│   └── patches/
│       └── mod_rs_patch.py    # mod.rs patch definition
├── core/
│   ├── inspection_data.py     # Inspection data container
│   ├── executor.py            # Mutation execution
│   └── trace_parser.py        # Output parsing
└── docs/
    └── standalone/
        ├── README.md          # This file
        ├── MUTATION_TAXONOMY.md
        └── impl/              # Implementation details
```

---

## Key Commits/Changes to Preserve

1. **mod.rs patch** (`a4/injection/patches/mod_rs_patch.py`)
   - A4 inspection hooks
   - A4 mutation handlers
   - **Auto FAULT_INJECTION_ENABLED** (lines ~219-225)

2. **ffi.cpp modifications** (already in repo)
   - FAULT_INJECTION_ENABLED skip logic (Arguzz)
   - A4_TRACE_TXN debug output

3. **witgen.h modifications** (already in repo)
   - Enhanced constraint failure output
   - CONSTRAINT_CONTINUE mode

**To clone on another machine:**
1. Clone the repo
2. Apply A4 patches: `python3 -m a4.injection.inject --risc0-path ./workspace/risc0-modified`
3. Build: `cd workspace/output && cargo build --release`
4. Run: `python -m a4.standalone.cli fuzz ...`

---

## References

- [MUTATION_TAXONOMY.md](./MUTATION_TAXONOMY.md) - Detailed mutation documentation
- [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) - Implementation roadmap
- [impl/CRASH_FIX_REPORT.md](./impl/CRASH_FIX_REPORT.md) - Crash investigation findings
- [impl/modifications_to_risc0_code.md](./impl/modifications_to_risc0_code.md) - All RISC Zero modifications

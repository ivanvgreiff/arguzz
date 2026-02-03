# A4: Post-Preflight Trace Mutation for RISC Zero

A4 is a mutation testing strategy that modifies the **PreflightTrace** (execution witness data) BEFORE witness generation, enabling precise constraint failure analysis without cascading execution effects.

## Table of Contents

1. [What is Preflight?](#what-is-preflight)
2. [Overview](#overview)
3. [Quick Start](#quick-start)
4. [Project Structure](#project-structure)
5. [Supported Mutations](#supported-mutations)
6. [Injection System](#injection-system)
7. [Environment Variables](#environment-variables)

---

## What is Preflight?

### The RISC Zero Proving Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        RISC Zero: Execution → Proof                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────────────────┐    │
│  │  EXECUTOR   │         │  PREFLIGHT  │         │   WITNESS GENERATOR     │    │
│  │             │         │             │         │                         │    │
│  │ Runs RISC-V │ ──────► │ Re-executes │ ──────► │ Fills constraint matrix │    │
│  │ program     │ Segment │ & records   │ Trace   │ using trace data        │    │
│  │             │         │ everything  │         │                         │    │
│  └─────────────┘         └─────────────┘         └───────────┬─────────────┘    │
│        │                                                     │                   │
│        │ Arguzz injects                          A4 mutates  │                   │
│        │ faults HERE                             trace HERE  │                   │
│        ▼                                                     ▼                   │
│  Cascading effects                               ┌─────────────────────────┐    │
│  propagate through                               │        PROVER           │    │
│  execution                                       └─────────────────────────┘    │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Why Preflight exists:** The ZK circuit needs a complete trace of *every* memory and register access with exact timing. Preflight "replays" execution while recording everything for the witness.

**What's in PreflightTrace:**
- `cycles[]`: Per-instruction metadata (PC, major/minor instruction type, transaction index)
- `txns[]`: Memory/register transactions (address, value, timing)

---

## Overview

### A4 vs Arguzz: Key Difference

| Aspect | Arguzz | A4 |
|--------|--------|-----|
| **When** | During execution | After preflight, before witness gen |
| **What changes** | Actual execution (values, PC, etc.) | Recorded trace metadata only |
| **Failures** | Cascading (mutation propagates) | Localized (surgical mutation) |
| **Use case** | Find all constraints that catch errors | Find the CORE constraint |

### Example: INSTR_WORD_MOD at Step 200

```
Arguzz: 6 constraint failures (1 core + 5 cascading)
A4:     1 constraint failure (CORE only: VerifyOpcodeF3)

Common: VerifyOpcodeF3 - verifies instruction type matches decoded word
```

---

## Quick Start

### Prerequisites

```bash
cd /root/arguzz

# Ensure A4 patches are applied (check first)
python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified --check

# If not applied, inject them
python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified

# Rebuild risc0 (run this manually)
cd workspace/output && cargo build --release
```

### Run Full Comparison

```bash
cd /root/arguzz

# INSTR_WORD_MOD (instruction type mutation)
python3 -m a4.cli compare \
  --step 200 \
  --kind INSTR_WORD_MOD \
  --seed 12345 \
  --host-binary ./workspace/output/target/release/risc0-host \
  --host-args '--in1 5 --in4 10'

# COMP_OUT_MOD (compute output mutation)
python3 -m a4.cli compare \
  --step 200 \
  --kind COMP_OUT_MOD \
  --seed 12345 \
  --host-binary ./workspace/output/target/release/risc0-host \
  --host-args '--in1 5 --in4 10'

# LOAD_VAL_MOD (load value mutation - use step 207 for lw instruction)
python3 -m a4.cli compare \
  --step 207 \
  --kind LOAD_VAL_MOD \
  --seed 12345 \
  --host-binary ./workspace/output/target/release/risc0-host \
  --host-args '--in1 5 --in4 10'

# STORE_OUT_MOD (store value mutation - use step 214 for sw instruction)
python3 -m a4.cli compare \
  --step 214 \
  --kind STORE_OUT_MOD \
  --seed 12345 \
  --host-binary ./workspace/output/target/release/risc0-host \
  --host-args '--in1 5 --in4 10'
```

### Find Mutation Target Only

```bash
python3 -m a4.cli find-target \
  --fault '<fault>{"step":200, "pc":2144416, "kind":"INSTR_WORD_MOD", "info":"word:3147283 => word:8897555"}</fault>' \
  --host-binary ./workspace/output/target/release/risc0-host \
  --output-config ./a4/output/config.json
```

---

## Project Structure

```
a4/
├── __init__.py              # Package init
├── cli.py                   # Main CLI entry point
├── README.md                # This file
│
├── common/                  # Shared utilities
│   ├── __init__.py
│   ├── insn_decode.py      # RISC-V instruction decoding
│   └── trace_parser.py     # Arguzz/A4 output parsing
│
├── mutations/               # Mutation-specific logic
│   ├── __init__.py
│   ├── base.py             # Shared utilities (run_arguzz_mutation, compare_failures, etc.)
│   ├── instr_type_mod.py   # INSTR_TYPE_MOD (for Arguzz INSTR_WORD_MOD)
│   ├── comp_out_mod.py     # COMP_OUT_MOD (for Arguzz COMP_OUT_MOD)
│   ├── load_val_mod.py     # LOAD_VAL_MOD (for Arguzz LOAD_VAL_MOD)
│   └── store_out_mod.py    # STORE_OUT_MOD (for Arguzz STORE_OUT_MOD)
│
├── injection/               # Patch injection system
│   ├── __init__.py
│   ├── inject.py           # Main injection script
│   └── patches/
│       ├── __init__.py
│       └── mod_rs_patch.py # Patch for mod.rs
│
└── output/                  # Generated outputs (gitignored)
    └── .gitignore
```

---

## Supported Mutations

### INSTR_TYPE_MOD (for Arguzz INSTR_WORD_MOD)

**What it does:** Mutates `cycles[].major` and `cycles[].minor` in the PreflightTrace to change the recorded instruction type.

**Config format:**
```json
{
  "mutation_type": "INSTR_TYPE_MOD",
  "step": 198,
  "major": 1,
  "minor": 0
}
```

**Core constraint caught:** `VerifyOpcodeF3` - verifies the decoded instruction word matches the recorded instruction type.

### COMP_OUT_MOD (for Arguzz COMP_OUT_MOD)

**What it does:** Mutates `txns[].word` for a WRITE transaction to a destination **register** after compute instructions (ADD, SUB, AND, OR, XOR, etc.).

**Config format:**
```json
{
  "mutation_type": "COMP_OUT_MOD",
  "step": 198,
  "txn_idx": 16261,
  "word": 73117827
}
```

**Core constraint caught:** `MemoryWrite` (mem.zir) - verifies the value written matches what was computed.

### LOAD_VAL_MOD (for Arguzz LOAD_VAL_MOD)

**What it does:** Mutates `txns[].word` for a WRITE transaction to a destination **register** after load instructions (Lw, Lh, Lb, Lhu, Lbu).

**Config format:**
```json
{
  "mutation_type": "LOAD_VAL_MOD",
  "step": 205,
  "txn_idx": 16289,
  "word": 73117824
}
```

**Core constraint caught:** `MemoryWrite` (mem.zir) - verifies the value written matches what was loaded.

### STORE_OUT_MOD (for Arguzz STORE_OUT_MOD)

**What it does:** Mutates `txns[].word` for a WRITE transaction to **memory** after store instructions (Sw, Sh, Sb).

**Key difference from LOAD_VAL_MOD/COMP_OUT_MOD:** Writes to **memory** addresses (not registers).

**Config format:**
```json
{
  "mutation_type": "STORE_OUT_MOD",
  "step": 212,
  "txn_idx": 16318,
  "word": 73117825
}
```

**Core constraint caught:** `MemoryWrite` (mem.zir) - verifies the value written matches what was stored.

---

## Injection System

A4 patches must be applied to RISC Zero source files before building. The injection system handles this.

### Check Status

```bash
python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified --check
```

### Apply Patches

```bash
python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified
```

### Revert Patches

```bash
python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified --revert
```

### What Gets Patched

| File | Patch |
|------|-------|
| `risc0/circuit/rv32im/src/prove/witgen/mod.rs` | A4 inspection and mutation hooks |

---

## Environment Variables

### A4 Inspection

| Variable | Purpose |
|----------|---------|
| `A4_INSPECT=1` | Enable preflight trace inspection output |
| `A4_DUMP_STEP=N` | Dump transactions for step N |
| `A4_DUMP_TXN=N` | Dump specific transaction by index |

### A4 Mutation

| Variable | Purpose |
|----------|---------|
| `A4_MUTATION_CONFIG=/path` | Path to JSON mutation config |

### Constraint Tracing

| Variable | Purpose |
|----------|---------|
| `CONSTRAINT_CONTINUE=1` | Don't abort on first constraint failure (allows multiple failures to be reported) |

---

## How It Works

### PC Matching Algorithm

Since Arguzz `step` ≠ A4 `user_cycle` (they differ by ecall count), we match by PC:

1. Arguzz records PC **before** execution
2. A4 records PC **after** execution (next PC)
3. For sequential instructions: `A4_pc = Arguzz_pc + 4`
4. We also verify the instruction type (major/minor) matches

### Loop Handling

For instructions inside loops (same PC appears multiple times), we select the iteration where `user_cycle <= arguzz_step` with the maximum `user_cycle`.

---

## Technical Details

### InsnKind to Major/Minor

```
major = InsnKind / 8
minor = InsnKind % 8

Examples:
  AddI = 7  → major=0, minor=7
  XorI = 8  → major=1, minor=0
  Lw   = 42 → major=5, minor=2
  Sw   = 50 → major=6, minor=2
```

### Constraint Failure Format

```json
{
  "cycle": 16777,
  "step": 198,
  "pc": 2144420,
  "major": 1,
  "minor": 0,
  "loc": "VerifyOpcodeF3(...)",
  "value": 2013265917
}
```

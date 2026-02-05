# A4 Verification Framework

This folder contains the verification framework for systematically testing A4's fuzzing strategies across all valid instruction types.

## Overview

The verification framework ensures that A4 correctly identifies the same core constraints as Arguzz across:
- **All valid instruction types** for each mutation strategy
- **Multiple execution points** (steps) for each instruction
- **Different input variations** (Phase 2)
- **Different guest programs** (Phase 3)

---

## Phase 1: Comprehensive Single-Program Testing

### Goal
Test ALL valid instruction types for each A4 mutation strategy on the current guest program.

### Step 1.1: Generate Execution Trace ✅

```bash
cd /root/arguzz/workspace/output
./target/release/risc0-host --trace --in1 5 --in4 10 2>&1 | grep "<trace>" > ../../a4/tmp/trace.log
```

### Step 1.2: Select Valid Test Steps ✅

Run the step selection script to identify valid steps for each mutation type:

```bash
cd /root/arguzz

# COMPREHENSIVE mode: Select 2+ steps for EVERY instruction type found
python3 -m a4.verification.scripts.select_steps \
    --trace-file ./a4/tmp/trace.log \
    --steps-per-instruction 2

# Or QUICK mode for fast testing (5 diverse steps per mutation type)
python3 -m a4.verification.scripts.select_steps \
    --trace-file ./a4/tmp/trace.log \
    --quick
```

**Current Selection (Comprehensive Mode):**

| Mutation Type | Unique Instructions | Total Valid Steps | Selected Tests |
|--------------|---------------------|-------------------|----------------|
| INSTR_WORD_MOD | 16 | 3,752 | 32 |
| COMP_OUT_MOD | 18 | 4,268 | 36 |
| LOAD_VAL_MOD | 3 | 1,360 | 6 |
| STORE_OUT_MOD | 2 | 1,192 | 4 |
| **TOTAL** | - | - | **78** |

**Instruction Coverage:**

```
INSTR_WORD_MOD / COMP_OUT_MOD:
  AddI (2310), Lui (274), Auipc (214), SllI (192), Add (178), 
  AndI (176), Sub (114), Or (102), And (50), SltIU (48), 
  SrlI (46), XorI (14), SltU (12), Mul (8), OrI (8), Xor (6)
  + Jal (76), JalR (440) for COMP_OUT_MOD only

LOAD_VAL_MOD:
  Lw (1018), LbU (338), Lb (4)

STORE_OUT_MOD:
  Sw (1082), Sb (110)
```

### Step 1.3: Run INSTR_WORD_MOD Tests 🔄

Test all 16 instruction types (32 tests):

```bash
cd /root/arguzz

# Run all INSTR_WORD_MOD tests
python3 -m a4.verification.scripts.run_tests --mutation-type INSTR_WORD_MOD

# Or run incrementally (one instruction at a time for debugging)
python3 -m a4.cli compare --step 927 --kind INSTR_WORD_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args '--in1 5 --in4 10' \
    --output-json ./a4/verification/results/instr_word_mod_step927_addi.json
```

**Expected Core Constraint:** `VerifyOpcodeF3` should appear in common failures for ALL tests.

### Step 1.4: Run COMP_OUT_MOD Tests ⏳

Test all 18 instruction types (36 tests):

```bash
python3 -m a4.verification.scripts.run_tests --mutation-type COMP_OUT_MOD
```

**Expected Core Constraint:** `MemoryWrite` should appear in common failures for ALL tests.

### Step 1.5: Run LOAD_VAL_MOD Tests ⏳

Test all 3 load instruction types (6 tests):

```bash
python3 -m a4.verification.scripts.run_tests --mutation-type LOAD_VAL_MOD
```

**Expected Core Constraint:** `MemoryWrite` should appear in common failures for ALL tests.

### Step 1.6: Run STORE_OUT_MOD Tests ⏳

Test all 2 store instruction types (4 tests):

```bash
python3 -m a4.verification.scripts.run_tests --mutation-type STORE_OUT_MOD
```

**Expected Core Constraint:** `MemoryWrite` should appear in common failures for ALL tests.

### Step 1.7: Run ALL Tests & Generate Report ⏳

```bash
# Run all 78 tests
python3 -m a4.verification.scripts.run_tests --all \
    --output-summary ./a4/verification/phase1_summary.json
```

---

## Success Criteria

### Per-Test Success
- ✅ Arguzz produces at least 1 constraint failure
- ✅ A4 produces at least 1 constraint failure  
- ✅ At least 1 constraint appears in BOTH (common > 0)

### Per-Mutation-Type Success
- ✅ ALL tests for that mutation type pass per-test criteria
- ✅ Expected core constraint appears in common failures:
  - INSTR_WORD_MOD → `VerifyOpcodeF3`
  - COMP_OUT_MOD → `MemoryWrite`
  - LOAD_VAL_MOD → `MemoryWrite`
  - STORE_OUT_MOD → `MemoryWrite`

### Phase 1 Success
- ✅ ALL mutation types pass per-mutation-type criteria

---

## File Structure

```
a4/verification/
├── README.md                     # This file
├── __init__.py                   # Python package
├── selected_steps.json           # Generated test configuration
├── scripts/
│   ├── __init__.py
│   ├── select_steps.py           # Step selection logic
│   └── run_tests.py              # Test runner
├── results/                      # Test result JSON files (per-test)
│   ├── instr_word_mod_step927_addi.json
│   ├── comp_out_mod_step927_addi.json
│   └── ...
├── logs/                         # Test execution logs
│   ├── instr_word_mod_step927_addi.log
│   └── ...
└── phase1_summary.json           # Aggregated results (after all tests)
```

---

## Quick Reference

### Step Selection Commands

```bash
# Comprehensive (all instruction types, 2 steps each)
python3 -m a4.verification.scripts.select_steps --steps-per-instruction 2

# Quick (5 diverse steps per mutation type)
python3 -m a4.verification.scripts.select_steps --quick

# More thorough (3 steps per instruction type)
python3 -m a4.verification.scripts.select_steps --steps-per-instruction 3
```

### Test Runner Commands

```bash
# Run one mutation type
python3 -m a4.verification.scripts.run_tests --mutation-type INSTR_WORD_MOD

# Run all mutation types
python3 -m a4.verification.scripts.run_tests --all

# Run specific steps only
python3 -m a4.verification.scripts.run_tests --mutation-type COMP_OUT_MOD --steps 927 2890
```

### Manual Single Test

```bash
python3 -m a4.cli compare \
    --step STEP \
    --kind MUTATION_TYPE \
    --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args '--in1 5 --in4 10' \
    --output-json ./a4/verification/results/OUTPUT.json
```

# A4 Multi-Phase Verification Plan

## Executive Summary

This document outlines a systematic verification plan to ensure A4's fuzzing strategies correctly identify the same core constraints as Arguzz across different execution steps and guest programs. The plan is organized into three phases:

1. **Phase 1**: Same guest program, multiple steps (same inputs)
2. **Phase 2**: Same guest program, different input variations
3. **Phase 3**: Different guest programs

---

## Current State Assessment

### What Has Been Verified

A4's four functioning mutation types have been tested on **one specific step each** with inputs `--in1 5 --in4 10`:

| Mutation Type | Tested Step | Instruction Type | Core Constraint Verified |
|--------------|-------------|------------------|-------------------------|
| INSTR_WORD_MOD | 200 | AddI | VerifyOpcodeF3 |
| COMP_OUT_MOD | 200 | AddI | MemoryWrite@mem.zir:99/100 |
| LOAD_VAL_MOD | 207 | Lw | MemoryWrite@mem.zir:99/100 |
| STORE_OUT_MOD | 214 | Sw | MemoryWrite@mem.zir:99/100 |

### What Needs Verification

1. **Different steps within the same execution** - Do different instances of the same instruction type trigger the same constraints?
2. **Different instruction variants** - Do Add, Sub, Xor, etc. all trigger the same core compute constraint?
3. **Different inputs** - Do different execution traces still show constraint alignment?
4. **Different programs** - Do the strategies generalize to other guest programs?

---

## Phase 1: Multiple Steps on Same Guest Program

### Objective

Verify that A4 correctly identifies core constraints when the same mutation type is applied at different execution steps.

### Prerequisites

```bash
cd /root/arguzz
# Ensure patches are applied
python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified --check

# Build if needed
cd workspace/output && cargo build --release
```

### Task 1.1: Identify Target Steps

First, run a trace to identify instruction locations:

```bash
# Generate execution trace with default inputs
cd /root/arguzz/workspace/output
./target/release/risc0-host --trace --in1 5 --in4 10 2>&1 | grep "<trace>" > /tmp/trace.log
```

Then categorize steps by instruction type:

| Category | Instruction Types | Major Values | Arguzz Mutation |
|----------|------------------|--------------|-----------------|
| Compute (R-type) | Add, Sub, Sll, Slt, SltU, Xor, Or, And | 0 | COMP_OUT_MOD |
| Compute (I-type) | AddI, XorI, OrI, AndI, SltI, SltIU | 0-1 | COMP_OUT_MOD |
| Load | Lw, Lh, Lb, LbU, LhU | 5 | LOAD_VAL_MOD |
| Store | Sw, Sh, Sb | 6 | STORE_OUT_MOD |
| Branch | Beq, Bne, Blt, Bge, etc. | 1-2 | N/A (A4) |
| Jump | Jal, JalR | 2 | COMP_OUT_MOD |

**Deliverable**: A categorized list of step numbers with their instruction types.

### Task 1.2: INSTR_WORD_MOD at Multiple Steps

Test INSTR_WORD_MOD on 5-10 different compute instructions:

```bash
cd /root/arguzz

# Test at step 200 (AddI - baseline)
python3 -m a4.cli compare --step 200 --kind INSTR_WORD_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args '--in1 5 --in4 10' \
    --output-json ./a4/output/instr_mod_step200.json

# Test at additional steps (identify from trace)
# Replace STEP_N with actual step numbers from trace
for STEP in 201 202 203 204 205; do
    python3 -m a4.cli compare --step $STEP --kind INSTR_WORD_MOD --seed 12345 \
        --host-binary ./workspace/output/target/release/risc0-host \
        --host-args '--in1 5 --in4 10' \
        --output-json ./a4/output/instr_mod_step${STEP}.json 2>&1 | tee ./a4/output/instr_mod_step${STEP}.log
done
```

**Success Criteria**: 
- All tests produce constraint failures
- Core constraint `VerifyOpcodeF3` appears in common failures for all tests

### Task 1.3: COMP_OUT_MOD at Multiple Steps

Test COMP_OUT_MOD on different compute instruction types:

```bash
cd /root/arguzz

# Different compute instructions
# Need to identify steps with different instruction types from trace
for STEP in 200 201 202 203; do
    python3 -m a4.cli compare --step $STEP --kind COMP_OUT_MOD --seed 12345 \
        --host-binary ./workspace/output/target/release/risc0-host \
        --host-args '--in1 5 --in4 10' \
        --output-json ./a4/output/comp_out_step${STEP}.json 2>&1 | tee ./a4/output/comp_out_step${STEP}.log
done
```

**Success Criteria**:
- All compute instructions trigger constraint failures
- `MemoryWrite` constraints appear in common failures

### Task 1.4: LOAD_VAL_MOD at Multiple Steps

Test on different load instructions (Lw, Lh, Lb, etc.):

```bash
cd /root/arguzz

# Find load instructions in trace
grep -E "\"(Lw|Lh|Lb|LhU|LbU)\"" /tmp/trace.log | head -20

# Test at multiple load steps
for STEP in 207 208; do
    python3 -m a4.cli compare --step $STEP --kind LOAD_VAL_MOD --seed 12345 \
        --host-binary ./workspace/output/target/release/risc0-host \
        --host-args '--in1 5 --in4 10' \
        --output-json ./a4/output/load_val_step${STEP}.json 2>&1 | tee ./a4/output/load_val_step${STEP}.log
done
```

**Success Criteria**:
- All load instructions trigger constraint failures
- `MemoryWrite` constraints appear in common failures

### Task 1.5: STORE_OUT_MOD at Multiple Steps

Test on different store instructions:

```bash
cd /root/arguzz

# Find store instructions in trace
grep -E "\"(Sw|Sh|Sb)\"" /tmp/trace.log | head -20

# Test at multiple store steps
for STEP in 214 215; do
    python3 -m a4.cli compare --step $STEP --kind STORE_OUT_MOD --seed 12345 \
        --host-binary ./workspace/output/target/release/risc0-host \
        --host-args '--in1 5 --in4 10' \
        --output-json ./a4/output/store_out_step${STEP}.json 2>&1 | tee ./a4/output/store_out_step${STEP}.log
done
```

**Success Criteria**:
- All store instructions trigger constraint failures  
- `MemoryWrite` constraints appear in common failures

### Task 1.6: Create Results Summary Script

Create a script to aggregate Phase 1 results:

```python
#!/usr/bin/env python3
"""Aggregate Phase 1 verification results"""

import json
from pathlib import Path

def analyze_results():
    output_dir = Path("./a4/output")
    results = []
    
    for json_file in output_dir.glob("*.json"):
        with open(json_file) as f:
            data = json.load(f)
            results.append({
                "file": json_file.name,
                "arguzz_step": data["arguzz"]["step"],
                "kind": data["arguzz"]["kind"],
                "arguzz_failures": data["arguzz"]["failures"],
                "a4_failures": data["a4"]["failures"],
                "common": len(data["comparison"]["common"]),
                "arguzz_only": len(data["comparison"]["arguzz_only"]),
                "a4_only": len(data["comparison"]["a4_only"]),
            })
    
    # Print summary table
    print("=" * 80)
    print("Phase 1 Results Summary")
    print("=" * 80)
    print(f"{'File':<30} {'Kind':<15} {'Common':<8} {'Arguzz Only':<12} {'A4 Only':<10}")
    print("-" * 80)
    
    for r in sorted(results, key=lambda x: (x["kind"], x["arguzz_step"])):
        print(f"{r['file']:<30} {r['kind']:<15} {r['common']:<8} {r['arguzz_only']:<12} {r['a4_only']:<10}")
    
    # Success check
    all_common = all(r["common"] > 0 for r in results)
    print("\n" + "=" * 80)
    print(f"SUCCESS: {'Yes' if all_common else 'No'} (all tests have common constraints)")

if __name__ == "__main__":
    analyze_results()
```

---

## Phase 2: Different Input Variations

### Objective

Verify that A4 produces consistent results across different input combinations, which generate different execution traces.

### Input Variation Strategy

The current guest program accepts 5 inputs: `in0` (bool), `in1` (u32), `in2` (bool), `in3` (bool), `in4` (u32).

| Input Set | in0 | in1 | in2 | in3 | in4 | Expected Effect |
|-----------|-----|-----|-----|-----|-----|-----------------|
| Default | false | 5 | false | false | 10 | Baseline |
| Set A | true | 5 | false | false | 10 | Different branch path |
| Set B | false | 100 | false | false | 10 | Different compute values |
| Set C | false | 5 | true | false | 10 | Different boolean logic |
| Set D | false | 5 | false | true | 10 | Different boolean logic |
| Set E | false | 0 | false | false | 0 | Edge case (zeros) |
| Set F | false | 0xFFFFFFFF | false | false | 0xFFFFFFFF | Edge case (max values) |

### Task 2.1: Identify Common Steps Across Inputs

For each input set, generate a trace and find common step positions:

```bash
cd /root/arguzz/workspace/output

# Generate traces for each input set
./target/release/risc0-host --trace --in1 5 --in4 10 2>&1 | grep "<trace>" > /tmp/trace_default.log
./target/release/risc0-host --trace --in0 --in1 5 --in4 10 2>&1 | grep "<trace>" > /tmp/trace_a.log
./target/release/risc0-host --trace --in1 100 --in4 10 2>&1 | grep "<trace>" > /tmp/trace_b.log
./target/release/risc0-host --trace --in1 5 --in2 --in4 10 2>&1 | grep "<trace>" > /tmp/trace_c.log
```

**Analysis Script**:
```python
#!/usr/bin/env python3
"""Find common instruction types across different inputs"""

import json
import re

def parse_trace(filename):
    """Parse trace file and return list of (step, pc, insn_kind)"""
    entries = []
    with open(filename) as f:
        for line in f:
            match = re.search(r'<trace>({.*?})</trace>', line)
            if match:
                data = json.loads(match.group(1))
                entries.append((data['step'], data['pc'], data['instruction']))
    return entries

def main():
    traces = {
        "default": parse_trace("/tmp/trace_default.log"),
        "set_a": parse_trace("/tmp/trace_a.log"),
        "set_b": parse_trace("/tmp/trace_b.log"),
        "set_c": parse_trace("/tmp/trace_c.log"),
    }
    
    # Find steps with compute instructions in all traces
    for name, trace in traces.items():
        compute_steps = [(s, i) for s, p, i in trace 
                        if i in ["Add", "Sub", "AddI", "XorI", "OrI", "AndI", "Mul"]]
        print(f"{name}: {len(compute_steps)} compute instructions")
        print(f"  First 5: {compute_steps[:5]}")

if __name__ == "__main__":
    main()
```

### Task 2.2: Cross-Input Verification

For each mutation type, test with different input sets at equivalent steps:

```bash
cd /root/arguzz

# COMP_OUT_MOD with different inputs
python3 -m a4.cli compare --step 200 --kind COMP_OUT_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args '--in1 5 --in4 10' \
    --output-json ./a4/output/phase2_comp_default.json

python3 -m a4.cli compare --step 200 --kind COMP_OUT_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args '--in1 100 --in4 10' \
    --output-json ./a4/output/phase2_comp_setb.json

python3 -m a4.cli compare --step 200 --kind COMP_OUT_MOD --seed 12345 \
    --host-binary ./workspace/output/target/release/risc0-host \
    --host-args '--in1 5 --in2 --in4 10' \
    --output-json ./a4/output/phase2_comp_setc.json
```

### Task 2.3: Seed Variation Testing

Test multiple random seeds to ensure the constraint matching is deterministic:

```bash
cd /root/arguzz

for SEED in 12345 23456 34567 45678 56789; do
    python3 -m a4.cli compare --step 200 --kind COMP_OUT_MOD --seed $SEED \
        --host-binary ./workspace/output/target/release/risc0-host \
        --host-args '--in1 5 --in4 10' \
        --output-json ./a4/output/phase2_seed${SEED}.json 2>&1 | tee ./a4/output/phase2_seed${SEED}.log
done
```

**Success Criteria**:
- Core constraints remain consistent across different seeds
- Common failure counts are > 0 for all seeds

---

## Phase 3: Different Guest Programs

### Objective

Verify that A4 works correctly with different guest programs beyond the current synthetic circuit program.

### Task 3.1: Survey Existing Guest Programs

Check available guest programs in the RISC Zero ecosystem:

```bash
# Check risc0-fuzzer tests
ls -la /root/arguzz/projects/risc0-fuzzer/tests/

# Check for other example programs
find /root/arguzz -name "*.rs" -path "*/guest/*" -type f 2>/dev/null

# Check RISC Zero examples
ls -la /root/arguzz/workspace/risc0-modified/examples/ 2>/dev/null || echo "No examples directory"
```

### Task 3.2: Create Minimal Test Programs

If needed, create additional minimal guest programs:

**Guest Program 1: Pure Arithmetic**
```rust
// Simple arithmetic operations
fn main() {
    let a: u32 = env::read();
    let b: u32 = env::read();
    
    let sum = a + b;
    let diff = a - b;
    let prod = a * b;
    let quot = if b != 0 { a / b } else { 0 };
    
    env::commit(&(sum ^ diff ^ prod ^ quot));
}
```

**Guest Program 2: Memory-Heavy**
```rust
// Memory load/store intensive
fn main() {
    let mut arr: [u32; 16] = [0; 16];
    let n: u32 = env::read();
    
    for i in 0..16 {
        arr[i] = n.wrapping_mul(i as u32);
    }
    
    let result: u32 = arr.iter().sum();
    env::commit(&result);
}
```

**Guest Program 3: Branch-Heavy**
```rust
// Control flow intensive
fn main() {
    let n: u32 = env::read();
    let mut count = 0u32;
    
    for i in 0..n {
        if i % 2 == 0 {
            count += 1;
        } else if i % 3 == 0 {
            count += 2;
        } else {
            count += 3;
        }
    }
    
    env::commit(&count);
}
```

### Task 3.3: Adapt A4 Testing Infrastructure

The current infrastructure assumes specific host arguments (`--in0` through `--in4`). For different guest programs:

1. **Create a new host program** that accepts the appropriate arguments
2. **Or modify cli.py** to accept arbitrary host arguments

```bash
# Example: Testing with a different guest program
cd /root/arguzz

# Build new guest program (if created)
cd workspace/new_guest && cargo build --release

# Run A4 comparison
python3 -m a4.cli compare --step 50 --kind COMP_OUT_MOD --seed 12345 \
    --host-binary ./workspace/new_guest/target/release/new-host \
    --host-args '100 200' \
    --output-json ./a4/output/phase3_new_guest.json
```

### Task 3.4: Cross-Program Constraint Analysis

Create a script to analyze constraint patterns across programs:

```python
#!/usr/bin/env python3
"""Analyze constraint patterns across different guest programs"""

import json
from collections import defaultdict
from pathlib import Path

def analyze_cross_program():
    output_dir = Path("./a4/output")
    
    # Group by program
    programs = defaultdict(list)
    for json_file in output_dir.glob("phase3_*.json"):
        program = json_file.stem.split("_")[1]
        with open(json_file) as f:
            programs[program].append(json.load(f))
    
    # Analyze constraint patterns
    for program, results in programs.items():
        print(f"\n=== Program: {program} ===")
        all_constraints = set()
        for r in results:
            for c in r["comparison"]["common"]:
                # Extract constraint name
                parts = c.split(":")
                if len(parts) >= 5:
                    constraint = parts[4]
                    all_constraints.add(constraint)
        
        print(f"Common constraints across all tests: {sorted(all_constraints)}")

if __name__ == "__main__":
    analyze_cross_program()
```

---

## Verification Checklist

### Phase 1 Checklist

| Task | Status | Notes |
|------|--------|-------|
| 1.1 Identify target steps | ☐ | |
| 1.2 INSTR_WORD_MOD multi-step | ☐ | |
| 1.3 COMP_OUT_MOD multi-step | ☐ | |
| 1.4 LOAD_VAL_MOD multi-step | ☐ | |
| 1.5 STORE_OUT_MOD multi-step | ☐ | |
| 1.6 Results summary | ☐ | |

### Phase 2 Checklist

| Task | Status | Notes |
|------|--------|-------|
| 2.1 Identify common steps | ☐ | |
| 2.2 Cross-input verification | ☐ | |
| 2.3 Seed variation testing | ☐ | |

### Phase 3 Checklist

| Task | Status | Notes |
|------|--------|-------|
| 3.1 Survey existing programs | ☐ | |
| 3.2 Create test programs | ☐ | |
| 3.3 Adapt infrastructure | ☐ | |
| 3.4 Cross-program analysis | ☐ | |

---

## Success Criteria Summary

### Phase 1 Success
- [ ] Each mutation type triggers at least one common constraint at every tested step
- [ ] Core constraints are consistent:
  - INSTR_WORD_MOD → `VerifyOpcodeF3`
  - COMP_OUT_MOD → `MemoryWrite`
  - LOAD_VAL_MOD → `MemoryWrite`  
  - STORE_OUT_MOD → `MemoryWrite`

### Phase 2 Success
- [ ] Common constraints remain consistent across input variations
- [ ] Results are reproducible across different random seeds
- [ ] No A4-only failures that don't appear in Arguzz

### Phase 3 Success
- [ ] A4 successfully runs on at least 2 different guest programs
- [ ] Constraint patterns are similar across programs
- [ ] Documentation updated with findings

---

## Appendix A: Command Reference

### Trace Generation
```bash
./target/release/risc0-host --trace [args] 2>&1 | grep "<trace>"
```

### A4 Comparison
```bash
python3 -m a4.cli compare --step STEP --kind KIND --seed SEED \
    --host-binary BINARY --host-args 'ARGS' --output-json OUTPUT.json
```

### Inspection Only
```bash
A4_INSPECT=1 ./target/release/risc0-host [args] 2>&1 | grep "<a4_cycle_info>"
```

### Mutation Config
```json
{
    "mutation_type": "COMP_OUT_MOD",
    "step": 198,
    "txn_idx": 16261,
    "word": 73117827
}
```

---

## Appendix B: Expected Constraint Mappings

| Mutation | What's Changed | Core Constraint | Why |
|----------|----------------|-----------------|-----|
| INSTR_WORD_MOD | cycles[].major/minor | VerifyOpcodeF3 | Instruction word doesn't match recorded type |
| COMP_OUT_MOD | txns[].word (reg write) | MemoryWrite | Written value doesn't match expected computation |
| LOAD_VAL_MOD | txns[].word (reg write) | MemoryWrite | Loaded value doesn't match memory |
| STORE_OUT_MOD | txns[].word (mem write) | MemoryWrite | Stored value creates inconsistency |

---

## Appendix C: Troubleshooting

### No Fault Recorded
If Arguzz doesn't record a fault, the step may not contain the expected instruction type:
```bash
# Check instruction at step
./target/release/risc0-host --trace [args] 2>&1 | grep "<trace>" | sed -n 'STEPp'
```

### Constraint Mismatch
If Arguzz and A4 show different constraints:
1. Verify the step mapping (Arguzz step vs A4 user_cycle)
2. Check if there are ecalls between step 0 and target step
3. Verify PC matching (`A4_PC = Arguzz_PC + 4`)

### Build Issues
```bash
# Clean rebuild
cd /root/arguzz/workspace/output
cargo clean
cargo build --release

# Re-inject patches if needed
cd /root/arguzz
python3 -m a4.cli inject --risc0-path ./workspace/risc0-modified
```

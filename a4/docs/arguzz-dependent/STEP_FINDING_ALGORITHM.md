# Preflight Trace Step Finding Algorithm

## Overview

When Arguzz injects a fault at a specific step, A4 needs to find the corresponding step in the preflight trace to apply the equivalent mutation. This document explains how the step-finding algorithm works and handles various edge cases.

## Key Insight: PC Semantics Differ!

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PC RECORDING DIFFERENCE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ARGUZZ fault.pc  = PC of the CURRENT instruction being executed            │
│   PREFLIGHT cycle.pc = PC AFTER the instruction (NEXT PC)                   │
│                                                                              │
│   For sequential instructions:  preflight.pc = arguzz.pc + 4                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why This Happens

In `rv32im.rs`, the step function:
```rust
fn step(&mut self) -> bool {
    let pc = self.ctx.pc();              // Current instruction PC
    self.fault_inj_ctx.set_pc(pc);       // Arguzz records THIS
    // ... execute instruction ...
    // During execution: ctx.set_pc(pc + 4) updates PC
    self.ctx.on_insn_end(insn_ctx, pc);  // BUT on_insn_end uses...
}
```

In `preflight.rs`:
```rust
fn on_insn_end(&mut self, kind: InsnKind) -> Result<()> {
    self.add_cycle_insn(CycleState::Decode, self.pc.0, kind);  // self.pc (NEXT PC!)
    // ...
}
```

The `self.pc` has already been updated to the NEXT PC before `on_insn_end` is called.

## Visual Example: Sequential Instructions

```
                    ARGUZZ VIEW                    PREFLIGHT VIEW
                    ═══════════                    ══════════════
                    
    Step 1486       PC = 2196672                   
    (LbU)           ────────────►                  cycle.pc = 2196676
                    fault.pc = 2196672             step = 1462
                                                   (PC after LbU = PC + 4)
                    
    ┌──────────────────────────────────────────────────────────────────┐
    │  To find preflight step: look for cycle.pc = arguzz_pc + 4       │
    │                                                                   │
    │  arguzz_pc = 2196672  ──►  expected_pc = 2196672 + 4 = 2196676   │
    │                                                                   │
    │  Find cycle with pc = 2196676  ──►  step 1462 ✓                  │
    └──────────────────────────────────────────────────────────────────┘
```

## Step Counting Differences

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       STEP COUNTING DIFFERENCES                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ARGUZZ:   Counts only user instruction executions                         │
│   PREFLIGHT: Counts instructions + special cycles (Poseidon, SHA, Control)  │
│                                                                              │
│   Result: offset = arguzz_step - preflight_step > 0 and GROWS over time     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Visual Timeline

```
Time ──────────────────────────────────────────────────────────────────────►

Arguzz:     [1] [2] [3] [4] [5] [6] [7] [8] [9] [10] ...  [1486] ...
             │   │   │   │   │   │   │   │   │    │          │
Preflight:  [1] [2] [3] [4] [5] [P] [6] [7] [S] [8] ...  [1462] ...
                              ▲       ▲       ▲
                              │       │       │
                         Poseidon  Control   SHA
                         (not counted by Arguzz)

Offset at step 1486: 1486 - 1462 = 24
```

## The Algorithm

```python
def find_a4_step_for_arguzz_step(arguzz_step, arguzz_pc, a4_cycles, offset=None):
    """
    STEP 1: Calculate expected preflight PC
    ───────────────────────────────────────
    expected_pc = arguzz_pc + 4
    
    Why +4? Because preflight records NEXT PC, not current PC.
    
    
    STEP 2: Find all cycles at expected_pc
    ───────────────────────────────────────
    matches = [c for c in a4_cycles if c.pc == expected_pc and c.major <= 6]
    
    Filter: major <= 6 ensures we only match instruction cycles
            (major 7+ are Poseidon, SHA, Control, etc.)
    
    
    STEP 3: Handle loop iterations
    ──────────────────────────────
    If len(matches) == 1:
        return matches[0].step  # Only one occurrence, easy!
    
    If len(matches) > 1:
        # Multiple loop iterations at same PC
        # Use offset to find correct iteration
        
        if offset is not None:
            target_step = arguzz_step - offset
            return closest_match_to(target_step)
        else:
            # Fallback: return highest step <= arguzz_step
            return max([c.step for c in matches if c.step <= arguzz_step])
    """
```

## Handling Loops: The Offset Problem

When an instruction is inside a loop, there are multiple preflight cycles at the same PC:

```
Loop at PC = 2196672 (LbU instruction):

Preflight:   step 1342, pc=2196676  ← iteration 1
             step 1349, pc=2196676  ← iteration 2
             step 1356, pc=2196676  ← iteration 3
             ...
             step 1461, pc=2196676  ← iteration N
             step 1468, pc=2196676  ← iteration N+1
             step 1475, pc=2196676  ← iteration N+2
             step 1482, pc=2196676  ← iteration N+3

Loop period = 7 steps

If Arguzz injects at step 1486:
- With offset = 25, target = 1486 - 25 = 1461
- Find cycle at pc=2196676 closest to 1461
- Answer: step 1461 ✓
```

### The Tight Loop Problem

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PROBLEM: Offset > Loop Period                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   If offset (25) > loop_period (7), the naive "closest step" approach       │
│   might pick the WRONG iteration!                                            │
│                                                                              │
│   Solution: Compute offset accurately from Arguzz trace + preflight trace   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Offset Computation

```python
def compute_arguzz_preflight_offset(arguzz_traces, a4_cycles):
    """
    Find PCs that appear in both traces, compute offset at each,
    use median offset.
    
    Example:
        PC 0x204000: arguzz_step=100, preflight_step=95 → offset=5
        PC 0x204010: arguzz_step=200, preflight_step=185 → offset=15
        PC 0x204020: arguzz_step=300, preflight_step=275 → offset=25
        
        Median offset = 15
    """
```

## Special Case: JAL/JALR Instructions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JAL/JALR: PC+4 Doesn't Work!                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   For JAL at PC=X jumping to target=Y:                                       │
│   - Arguzz fault.pc = X (the JAL instruction)                                │
│   - ctx.set_pc(Y) is called (jump to target)                                │
│   - Preflight cycle.pc = Y (the jump target, NOT X+4!)                      │
│                                                                              │
│   Problem: We don't know Y from the fault info alone!                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### JAL Example

```
                    JAL at PC = 0xC0000058
                    Jumps to target = 0xC0000194
                    
    Arguzz:         fault.pc = 0xC0000058
    
    Expected PC+4:  0xC000005C  ← WRONG! This address is never reached!
    
    Actual preflight.pc: 0xC0000194  ← The jump target
    
    ┌────────────────────────────────────────────────────────┐
    │  Algorithm looks for pc = 0xC000005C                   │
    │  But no cycle exists at that PC!                       │
    │  Result: "No A4 instruction cycle found" error         │
    └────────────────────────────────────────────────────────┘
```

### Current Handling

For COMP_OUT_MOD with JAL/JALR:
1. Step finding fails (PC+4 not in trace)
2. Test is **skipped** (marked as N/A)
3. Uses `compare_failures_by_constraint_only()` as fallback

```
============================================================
Testing COMP_OUT_MOD at step 2798 (JAL)
============================================================

*** STEP FINDING FAILED ***
Reason: No A4 instruction cycle found at PC=0x2037EC (arguzz_pc+4)

Result: ⊘ N/A (step finding failed)
```

## Algorithm Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        STEP FINDING ALGORITHM                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INPUT:  arguzz_step, arguzz_pc, preflight_cycles, offset                   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Step 1: expected_pc = arguzz_pc + 4                                 │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Step 2: Find cycles where cycle.pc == expected_pc                   │    │
│  │         AND cycle.major <= 6 (instruction cycles only)              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│              ┌───────────────┼───────────────┐                              │
│              │               │               │                              │
│              ▼               ▼               ▼                              │
│      ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│      │ 0 matches   │  │ 1 match     │  │ N matches   │                     │
│      │ (JAL/JALR)  │  │ (simple)    │  │ (loop)      │                     │
│      └─────────────┘  └─────────────┘  └─────────────┘                     │
│              │               │               │                              │
│              ▼               ▼               ▼                              │
│      ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│      │ Raise       │  │ Return      │  │ Use offset  │                     │
│      │ ValueError  │  │ step        │  │ to pick     │                     │
│      │ (skip test) │  │             │  │ correct one │                     │
│      └─────────────┘  └─────────────┘  └─────────────┘                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Test Results by Instruction Type

| Instruction Type | PC+4 Works? | Offset Helps? | Status |
|-----------------|-------------|---------------|--------|
| ALU (Add, Sub, etc.) | ✅ Yes | ✅ Yes (loops) | ✓ PASS |
| Load (Lb, Lw, etc.) | ✅ Yes | ✅ Yes (loops) | ✓ PASS |
| Store (Sb, Sw, etc.) | ✅ Yes | ✅ Yes (loops) | ✓ PASS |
| Branch (Beq, Bne, etc.) | ⚠️ Depends | ✅ Yes | ⚠️ Varies |
| JAL | ❌ No | ❌ No | ⊘ SKIP |
| JALR | ❌ No | ❌ No | ⊘ SKIP |

## Future Improvements

For JAL/JALR support, potential approaches:

1. **Extract jump target from instruction word**: Decode the JAL/JALR instruction to compute target address
2. **Use major/minor matching**: Look for JAL/JALR cycles near the target step based on offset
3. **Use constraint-only comparison**: Current workaround - compare constraint types, ignore step/PC

## Code References

- **Step finding**: `a4/mutations/base.py` → `find_a4_step_for_arguzz_step()`
- **Offset computation**: `a4/mutations/base.py` → `compute_arguzz_preflight_offset()`
- **INSTR_TYPE_MOD step finding**: `a4/mutations/instr_type_mod.py` → `find_mutation_target()`

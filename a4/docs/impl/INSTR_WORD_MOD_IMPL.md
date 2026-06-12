# INSTR_WORD_MOD Implementation Plan

## Overview

**Mutation**: INSTR_WORD_MOD  
**Target**: `txns[].word` for instruction fetch transactions  
**Status**: Partial - Rust exists with bug, needs fix + Python wrapper

## Pre-Implementation Findings

### Critical Bug to Fix

**File**: `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`  
**Line**: 287

**Current (BUG)**:
```rust
let expected_addr = cycle.pc / 4;
```

**Fixed**:
```rust
let expected_addr = (cycle.pc - 4) / 4;
```

**Reason**: `cycle.pc` stores the NEXT PC (after instruction execution). The instruction was fetched from `NEXT_PC - 4`. This is confirmed by:
1. `set_cycle()` uses `NEXT_PC_LOW/HIGH` column names
2. MEM_VAL_MOD correctly uses `(cycle.pc - 4) // 4` in `_is_instruction_fetch()`

### Design: Why Both word AND prev_word Are Set

The Rust handler sets both:
```rust
txn.word = new_word;
txn.prev_word = new_word;
```

**Rationale**:
- Instruction fetch is a READ transaction
- For READs, constraint IsRead checks: `word == prev_word`
- By setting both to the same mutated value:
  - IsRead constraint still passes (memory consistency preserved)
  - Instruction decoding constraints should fail (different instruction bits)
- This targets instruction decoding bugs, not memory consistency bugs

### No Overlap Verification

| Mutation | Instruction Fetch | Reason |
|----------|------------------|--------|
| MEM_VAL_MOD | ❌ Excluded | `_is_instruction_fetch()` check |
| PRE_EXEC_REG_MOD | ❌ Not applicable | Only targets register addresses |
| COMP/LOAD/STORE_*_MOD | ❌ Not applicable | Different transaction types |
| INSTR_TYPE_MOD | ❌ Different field | Targets `cycles[].major/minor` |

---

## Implementation Steps

### Step 1: Fix Rust Bug

**File**: `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`

**Find** (around line 287):
```rust
let expected_addr = cycle.pc / 4;
```

**Replace with**:
```rust
// cycle.pc is NEXT PC; instruction was fetched from NEXT_PC - 4
let expected_addr = (cycle.pc - 4) / 4;
```

### Step 2: Create Python Module

**File**: `a4/standalone/mutations/instr_word_mod.py`

```python
"""
INSTR_WORD_MOD Mutation (Standalone)

Mutates the instruction word fetched from memory at the start of each instruction.
This changes what instruction the circuit "sees" without affecting memory consistency.

Target: txns[].word for instruction fetch transaction
Condition: First transaction at instruction step where addr = (pc-4)/4

================================================================================
BACKGROUND: Instruction Fetch in RISC-V
================================================================================

At each instruction step:
1. CPU fetches instruction from memory at current PC
2. This creates a READ transaction in the trace
3. The transaction is the FIRST transaction of the cycle (txn_idx = cycle.txn_idx)
4. The transaction address = (current_instruction_address) / 4

IMPORTANT: cycle.pc stores the NEXT PC (after instruction execution)
- For sequential: NEXT_PC = current_PC + 4
- Therefore: instruction_address = cycle.pc - 4
- Word address = (cycle.pc - 4) / 4

================================================================================
RELATIONSHIP TO OTHER MUTATIONS
================================================================================

This mutation fills the gap left by MEM_VAL_MOD:
- MEM_VAL_MOD explicitly EXCLUDES instruction fetch (see _is_instruction_fetch())
- Reason: INSTR_WORD_MOD provides more targeted testing of instruction decoding

This differs from INSTR_TYPE_MOD:
- INSTR_TYPE_MOD changes cycles[].major/minor directly
- INSTR_WORD_MOD changes the actual instruction bits in memory

================================================================================
EXPECTED CONSTRAINT FAILURES
================================================================================

Mutating the instruction word should trigger:
- Instruction decoding constraints (opcode validation)
- Potentially instruction-specific computation constraints

The Rust handler sets BOTH word and prev_word to maintain memory consistency:
- IsRead constraint (word == prev_word) still passes
- Instruction decoding is what should fail

================================================================================
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo


# Instruction cycles have major 0-6
MAX_INSTRUCTION_MAJOR = 6


@dataclass
class InstrWordModTarget:
    """
    Target for an INSTR_WORD_MOD mutation.
    
    Represents the instruction fetch transaction that can be mutated.
    """
    step: int               # A4 step (user_cycle)
    cycle_idx: int          # Index into trace.cycles[]
    pc: int                 # NEXT PC (after instruction execution)
    instr_addr: int         # Actual instruction byte address = pc - 4
    txn_idx: int            # Index of instruction fetch transaction
    fetch_addr: int         # Word address of instruction = (pc-4)/4
    original_word: int      # Original instruction word
    major: int              # Instruction major category
    minor: int              # Instruction minor variant


def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[InstrWordModTarget]:
    """
    Get the INSTR_WORD_MOD mutation target at a specific step.
    
    Instruction fetch is the first transaction at each instruction cycle.
    
    Args:
        step: The step number to find target for
        data: InspectionData containing pre-collected cycles and transactions
        
    Returns:
        InstrWordModTarget if valid instruction fetch found, None otherwise
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return None
    
    # Only instruction cycles (major 0-6) have instruction fetch
    if cycle.major > MAX_INSTRUCTION_MAJOR:
        return None
    
    # Get the first transaction of this cycle (instruction fetch)
    txn_idx = cycle.txn_idx
    txn = data.get_txn(txn_idx)
    if not txn:
        return None
    
    # Verify this is the instruction fetch transaction
    # Instruction fetch: READ from address (pc-4)/4
    expected_fetch_addr = (cycle.pc - 4) // 4
    
    if txn.addr != expected_fetch_addr:
        # Address mismatch - not instruction fetch
        return None
    
    if not txn.is_read():
        # Must be a READ transaction
        return None
    
    return InstrWordModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        instr_addr=cycle.pc - 4,
        txn_idx=txn_idx,
        fetch_addr=expected_fetch_addr,
        original_word=txn.word,
        major=cycle.major,
        minor=cycle.minor,
    )


def create_config(target: InstrWordModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for INSTR_WORD_MOD.
    
    The config tells the Rust witgen code which instruction to mutate.
    Note: The Rust handler identifies the transaction by step, not txn_idx.
    
    Args:
        target: The mutation target
        mutated_value: The new instruction word (different from original)
        output_path: Where to save the config JSON
        
    Returns:
        Path to the created config file
    """
    config = {
        "mutation_type": "INSTR_WORD_MOD",
        "step": target.step,
        "word": mutated_value,
        "_info": {
            "description": "INSTR_WORD_MOD: Mutate instruction fetch word",
            "instr_addr": f"0x{target.instr_addr:08x}",
            "fetch_word_addr": target.fetch_addr,
            "original_word": f"0x{target.original_word:08x}",
            "mutated_word": f"0x{mutated_value:08x}",
            "next_pc": f"0x{target.pc:08x}",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def get_valid_steps(data: 'InspectionData') -> List[int]:
    """
    Get all steps that have valid INSTR_WORD_MOD targets.
    
    All instruction cycles (major 0-6) should have instruction fetch.
    
    Args:
        data: InspectionData with pre-collected trace information
        
    Returns:
        List of step numbers that have INSTR_WORD_MOD targets
    """
    valid_steps = []
    
    for cycle in data.cycles:
        # Only instruction cycles
        if cycle.major <= MAX_INSTRUCTION_MAJOR:
            # Verify target exists (should always be true for instruction cycles)
            if get_targets_at_step(cycle.step, data):
                valid_steps.append(cycle.step)
    
    return valid_steps
```

### Step 3: Update `__init__.py`

**File**: `a4/standalone/mutations/__init__.py`

Add imports:
```python
from a4.standalone.mutations.instr_word_mod import (
    InstrWordModTarget,
    get_targets_at_step as get_instr_word_targets,
    create_config as create_instr_word_config,
    get_valid_steps as get_instr_word_valid_steps,
)
```

Add to `__all__`:
```python
    # INSTR_WORD_MOD
    'InstrWordModTarget',
    'get_instr_word_targets',
    'create_instr_word_config',
    'get_instr_word_valid_steps',
```

### Step 4: Update `fuzzer.py`

**File**: `a4/standalone/fuzzer.py`

#### 4.1 Add import

```python
from a4.standalone.mutations import (
    # ... existing imports ...
    get_instr_word_targets, create_instr_word_config, InstrWordModTarget,
)
```

#### 4.2 Add to MUTATION_KINDS

```python
MUTATION_KINDS = [
    "COMP_OUT_MOD",
    "LOAD_VAL_MOD", 
    "STORE_OUT_MOD",
    "PRE_EXEC_REG_MOD",
    "INSTR_TYPE_MOD",
    "MEM_VAL_MOD",
    "INSTR_WORD_MOD",  # NEW
]
```

#### 4.3 Add handler in `_create_mutation()`

```python
elif kind == "INSTR_WORD_MOD":
    target = get_instr_word_targets(step, self.data)
    if not target:
        return None, 0, 0
    mutated_value = self.value_gen.generate_different(
        target.original_word,
        {'major': target.major, 'minor': target.minor, 'is_instruction': True}
    )
    config = {
        "mutation_type": "INSTR_WORD_MOD",
        "step": target.step,
        "word": mutated_value,
    }
    return config, mutated_value, target.original_word
```

---

## Testing Plan

### Test 1: Verify Rust Fix

After fixing the Rust bug, manually test with inspection:

```bash
# Set up inspection dump
export A4_DUMP_STEP=100

# Run inspection
./risc0-host prove /path/to/guest.elf

# Check output: verify instruction fetch addr matches (pc-4)/4
# Look for: <a4_txn> showing first txn at step 100
# Verify: addr == (pc from <a4_cycle_info> - 4) / 4
```

### Test 2: Mini-Campaign

```bash
python -m a4.standalone.cli \
    --binary /path/to/risc0-host \
    --args "prove" "/path/to/guest.elf" \
    --db /tmp/a4_test_instr_word.db \
    --kind INSTR_WORD_MOD \
    --mutations 20 \
    --verbose
```

**Success Criteria**:
- ✅ No Python exceptions
- ✅ Mutations execute (see `<a4_instr_word_mod>` in output)
- ✅ Constraint failures detected (not IsRead, but decoding-related)
- ✅ No "addr mismatch" errors in output

### Test 3: Verify Gap is Filled

Run MEM_VAL_MOD and INSTR_WORD_MOD on the same step, verify different txn_idx targeted:

```bash
# Run with verbose mode, check that:
# - MEM_VAL_MOD skips first transaction (instruction fetch)
# - INSTR_WORD_MOD targets first transaction only
```

---

## Expected Outcome

After implementation:
1. INSTR_WORD_MOD works correctly (address calculation fixed)
2. Python wrapper properly identifies instruction fetch transactions
3. Mutations trigger instruction decoding constraint failures
4. Gap in `txns[].word` coverage is filled

---

## Checklist

- [ ] Fix Rust bug in mod.rs (line 287)
- [ ] Create `instr_word_mod.py`
- [ ] Update `__init__.py`
- [ ] Update `fuzzer.py` (MUTATION_KINDS + handler)
- [ ] Test Rust fix manually
- [ ] Test mini-campaign (20 mutations)
- [ ] Verify no addr mismatch errors
- [ ] Verify constraint failures occur
